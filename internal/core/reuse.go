package core

import (
	"context"
	"fmt"
	"sort"
	"time"

	"github.com/xlfe/pivb/internal/config"
)

// This file holds the in-memory assertion reuse cache: the state that lets one
// already-authorised signature answer the requests that are byte-identical to
// the one the operator touched for. It never widens what a touch authorises —
// the cache key is the full requester tuple, the entry dies with the assertion
// it holds, and every path that drops an entry zeroizes its token first.
//
// Locking: the cache is read and written under mu only. mintMu serializes the
// local mint branch and is what makes an insert race-free against a concurrent
// lookup; purges deliberately take mu alone so a released workspace claim or a
// removed card takes effect during the twenty seconds an in-flight touch may
// still have to run.

// reuseKeyFor reduces a validated request to the tuple one touch authorises.
// The request has already been checked against configuration, so alias.Target
// and the request's own target agree by construction; both are keyed anyway so
// a future path that reaches here with a looser check cannot share a signature
// across targets.
func reuseKeyFor(req SubjectTokenRequest, alias config.Alias) reuseKey {
	fc := req.ForwardContext
	return reuseKey{
		alias:              req.Alias,
		target:             alias.Target,
		audience:           req.ExternalAccountAudience,
		sourceKind:         req.RequestSource.Kind,
		sourceLabel:        req.RequestSource.Label,
		sessionID:          req.RequestSource.SessionID,
		attachmentMode:     req.Attachment.Mode,
		attachmentProtocol: req.Attachment.Protocol,
		routeSocket:        req.Attachment.RouteSocket,
		cardSerial:         req.ExpectedCard.Serial,
		cardKID:            req.ExpectedCard.KeyID,
		cardSPKI:           string(req.ExpectedCard.SPKIDER),
		originNodeID:       fc.OriginNodeID,
		workspaceID:        fc.WorkspaceID,
		bundle:             fc.Bundle,
		claimGeneration:    fc.ClaimGeneration,
	}
}

// serveAuthorised answers one request from an assertion an earlier touch has
// already authorised, or reports that the card must be touched. The caller
// holds mintMu and no other lock.
//
// Two independent grounds admit an entry. The first is strict concurrency
// coalescing: this request arrived before that signature completed, so it was
// queued behind the very touch it now shares, and no wall-clock window is
// involved. The second is the operator's opt-in reuse window for the alias,
// bounded by the entry's own end so an assertion whose touch-free window was
// capped by a granted authorisation window stops serving when that grant does,
// however much of the alias window is still unspent.
// Either way the served token is the byte-identical one that touch produced.
//
// grantedSeconds and grantedDeadline are what this provider grants the request
// in hand, not what the entry was minted under. They are reported back, never
// consulted for admission: a re-granted window arrives as a new claim
// generation, which is a different entry.
func (c *Core) serveAuthorised(key reuseKey, req SubjectTokenRequest, arrival time.Time, aliasReuse time.Duration, grantedSeconds int64, grantedDeadline time.Time) (SubjectTokenResult, bool) {
	now := c.now().UTC()
	c.mu.Lock()
	entry := c.cache[key]
	admit := false
	if entry != nil && entry.expiresAt.Sub(now) >= reuseValidityFloor {
		coalesced := c.singleFlight && !entry.completedAt.Before(arrival)
		reusable := aliasReuse > 0 && now.Sub(entry.completedAt) <= aliasReuse && now.Before(entry.windowEndsAt)
		admit = coalesced || reusable
	}
	var snapshot []string
	if admit {
		snapshot = append([]string(nil), entry.readers...)
	}
	c.mu.Unlock()
	if !admit {
		return SubjectTokenResult{}, false
	}
	// The card the operator touched must still be the card in the reader. This
	// enumerates hardware, so it runs with mu released and mintMu held.
	if !c.cardUnchanged(snapshot) {
		c.dropEntry(key)
		return SubjectTokenResult{}, false
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	if c.cache[key] != entry {
		// A purge overtook the probe. Inserts happen only under mintMu, which
		// this call holds, so the entry can only have been removed.
		return SubjectTokenResult{}, false
	}
	result := SubjectTokenResult{
		IDToken:               string(entry.token),
		ExpiresAt:             entry.expiresAt,
		Serial:                entry.serial,
		KeyID:                 entry.keyID,
		SPKIDER:               append([]byte(nil), entry.spki...),
		ForwardContext:        req.ForwardContext,
		Reused:                true,
		GrantedWindowSeconds:  grantedSeconds,
		GrantedWindowDeadline: unixOrZero(grantedDeadline),
	}
	// A hit deliberately spends no PIN: it neither reaches the card nor needs
	// to, so it keeps working under pin_cache = "never" after the single mint
	// that PIN was allowed to buy. It also leaves lastSign alone, which means
	// the last signature and not the last credential.
	c.recordMintLocked(mintRecord{at: now, alias: req.Alias, sessionID: req.RequestSource.SessionID, reused: true})
	return result, true
}

// newCacheEntry prepares the entry a completed mint leaves behind, or nil when
// this daemon must keep nothing. It enumerates readers, so the caller holds
// mintMu and no other lock.
//
// grantedDeadline is the end of the authorisation window this mint was covered
// by, or the zero time when it was covered by none.
func (c *Core) newCacheEntry(key reuseKey, token string, expiresAt, completedAt time.Time, aliasReuse time.Duration, grantedDeadline time.Time, serial uint32, keyID string, spki []byte) *cacheEntry {
	c.mu.RLock()
	singleFlight := c.singleFlight
	c.mu.RUnlock()
	if !singleFlight && aliasReuse == 0 {
		// Neither coalescing nor a window is configured, so this daemon holds
		// no assertion at all: byte for byte the behaviour before the cache.
		return nil
	}
	readers, supported, err := c.readerSnapshot()
	if supported && err != nil {
		// An entry whose reader snapshot is unknown could never pass the
		// presence probe. Dropping it now costs one touch later, which is the
		// only conservative answer.
		return nil
	}
	return &cacheEntry{
		key:          key,
		token:        []byte(token),
		completedAt:  completedAt,
		expiresAt:    expiresAt,
		serial:       serial,
		keyID:        keyID,
		spki:         append([]byte(nil), spki...),
		readers:      readers,
		windowEndsAt: touchFreeUntil(completedAt, aliasReuse, grantedDeadline),
	}
}

// touchFreeUntil is how long this daemon may answer byte-identical requests
// from one signature: whichever ends sooner of the alias's own reuse window
// and the authorisation window this mint was granted.
//
// Taking the earlier of the two is what makes a grant one-directional. It can
// only shorten a window, never open one — at assertion_reuse_s = 0 the alias
// window ends at completedAt, so an entry stays coalesce-only however long the
// grant is, because a remote claim cannot buy touch-free minting the card's
// own operator did not configure. A grant that ran out while the operator was
// touching leaves the same coalesce-only entry rather than a window that has
// already closed.
func touchFreeUntil(completedAt time.Time, aliasReuse time.Duration, grantedDeadline time.Time) time.Time {
	endsAt := completedAt.Add(aliasReuse)
	if grantedDeadline.IsZero() || !grantedDeadline.Before(endsAt) {
		return endsAt
	}
	if grantedDeadline.Before(completedAt) {
		return completedAt
	}
	return grantedDeadline
}

// insertLocked keeps a completed mint's assertion unless an invalidation has
// already spoken for its workspace claim. The caller holds mu.
func (c *Core) insertLocked(entry *cacheEntry) bool {
	if entry == nil {
		return false
	}
	if watermark, ok := c.invalidated[entry.key.workspaceID]; ok && entry.key.workspaceID != "" && entry.key.claimGeneration <= watermark {
		zero(entry.token)
		return false
	}
	if c.cache == nil {
		c.cache = make(map[reuseKey]*cacheEntry)
	}
	if previous := c.cache[entry.key]; previous != nil {
		zero(previous.token)
	}
	c.cache[entry.key] = entry
	c.evictLocked()
	return true
}

// evictLocked bounds the cache by dropping the least recently authorised
// entries. The caller holds mu.
func (c *Core) evictLocked() {
	for len(c.cache) > reuseCacheCap {
		var oldestKey reuseKey
		var oldest *cacheEntry
		for key, entry := range c.cache {
			if oldest == nil || entry.completedAt.Before(oldest.completedAt) {
				oldestKey, oldest = key, entry
			}
		}
		zero(oldest.token)
		delete(c.cache, oldestKey)
	}
}

// beginPendingMint and endPendingMint bracket the one local mint that is
// inside the card. A release-everything invalidation reads them so it can
// speak for a claim generation that is not in the cache yet.
func (c *Core) beginPendingMint(key reuseKey) {
	c.mu.Lock()
	c.pendingWorkspace, c.pendingGeneration = key.workspaceID, key.claimGeneration
	c.mu.Unlock()
}

func (c *Core) endPendingMint() {
	c.mu.Lock()
	c.pendingWorkspace, c.pendingGeneration = "", 0
	c.mu.Unlock()
}

// dropEntry removes one entry by key, zeroizing its token.
func (c *Core) dropEntry(key reuseKey) {
	c.mu.Lock()
	defer c.mu.Unlock()
	entry := c.cache[key]
	if entry == nil {
		return
	}
	zero(entry.token)
	delete(c.cache, key)
	c.wakeNotifierLocked()
}

// purgeAllLocked drops every held assertion. The caller holds mu.
func (c *Core) purgeAllLocked() int {
	purged := 0
	for key, entry := range c.cache {
		zero(entry.token)
		delete(c.cache, key)
		purged++
	}
	if purged != 0 {
		c.wakeNotifierLocked()
	}
	return purged
}

// purgeOtherSerialsLocked drops every assertion that a card other than serial
// authorised. The caller holds mu. Only one card can be in the reader at a
// time, so this normally finds nothing; when it does, the fleet key was
// swapped and the touches the old key gave are no longer the operator's
// current consent.
func (c *Core) purgeOtherSerialsLocked(serial uint32) int {
	purged := 0
	for key, entry := range c.cache {
		if entry.serial == serial {
			continue
		}
		zero(entry.token)
		delete(c.cache, key)
		purged++
	}
	if purged != 0 {
		c.wakeNotifierLocked()
	}
	return purged
}

// InvalidateWorkspace drops every assertion held for one ZKA workspace claim
// and refuses to keep the one an in-flight mint is about to produce for it.
// maxGeneration == 0 means every generation of that workspace. It returns how
// many held assertions were dropped.
//
// It takes mu and never mintMu, so a released claim stops granting touch-free
// mints immediately instead of waiting out the twenty seconds an in-flight
// touch may still have to run. The protocol-bump work package exposes it as
// POST /v1/invalidate, which ZKA calls when a workspace claim is released or
// its generation advances.
func (c *Core) InvalidateWorkspace(workspaceID string, maxGeneration uint64) int {
	if workspaceID == "" {
		return 0
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	purged := 0
	highest := uint64(0)
	for key, entry := range c.cache {
		if key.workspaceID != workspaceID {
			continue
		}
		if maxGeneration != 0 && key.claimGeneration > maxGeneration {
			continue
		}
		if key.claimGeneration > highest {
			highest = key.claimGeneration
		}
		zero(entry.token)
		delete(c.cache, key)
		purged++
	}
	// The watermark exists for one race only: a mint that entered the card
	// before this call must not insert its result after it. A bounded
	// maxGeneration is recorded as given, so a re-claim at a higher generation
	// caches again. "Every generation" cannot be recorded as ^uint64(0),
	// because a re-claim is exactly what follows a release and would then
	// never cache again. It is recorded instead as the highest generation this
	// daemon has actually seen for the workspace — the highest one purged, or
	// the one currently inside the card, whichever is greater. A generation
	// above that has not been issued yet, so it cannot be the mint this call
	// is racing.
	watermark := maxGeneration
	if maxGeneration == 0 {
		watermark = highest
		if c.pendingWorkspace == workspaceID && c.pendingGeneration > watermark {
			watermark = c.pendingGeneration
		}
	}
	if watermark != 0 {
		c.recordWatermarkLocked(workspaceID, watermark)
	}
	if purged != 0 {
		c.wakeNotifierLocked()
	}
	return purged
}

// recordWatermarkLocked raises a workspace's invalidation watermark, bounding
// the map. The caller holds mu.
func (c *Core) recordWatermarkLocked(workspaceID string, generation uint64) {
	if c.invalidated == nil {
		c.invalidated = make(map[string]uint64)
	}
	if current, ok := c.invalidated[workspaceID]; ok && current >= generation {
		return
	}
	c.invalidated[workspaceID] = generation
	for len(c.invalidated) > invalidatedCap {
		// A watermark matters only until the mint it races with completes, so
		// the lowest generation is the one whose race is furthest behind.
		lowest, lowestGeneration := "", uint64(0)
		for workspace, seen := range c.invalidated {
			if lowest == "" || seen < lowestGeneration {
				lowest, lowestGeneration = workspace, seen
			}
		}
		delete(c.invalidated, lowest)
	}
}

// readerSnapshot enumerates and sorts the smart-card reader names. supported
// reports whether the configured signer can enumerate at all; a signer that
// cannot disables the presence probe rather than failing it.
func (c *Core) readerSnapshot() (names []string, supported bool, err error) {
	lister, ok := c.signer.(readerLister)
	if !ok {
		return nil, false, nil
	}
	live, err := lister.ListReaderNames()
	if err != nil {
		return nil, true, err
	}
	sorted := append([]string(nil), live...)
	sort.Strings(sorted)
	return sorted, true, nil
}

// cardUnchanged reports whether the readers still look exactly as they did
// when the assertion was signed. An enumeration failure counts as changed.
func (c *Core) cardUnchanged(snapshot []string) bool {
	names, supported, err := c.readerSnapshot()
	if !supported {
		return true
	}
	if err != nil {
		return false
	}
	return equalStrings(names, snapshot)
}

// reuseWindowsLocked reports the operator-visible touch-free windows, ordered
// by the one that ends soonest. Entries that exist only to coalesce concurrent
// requests carry no window and are not reported. The caller holds mu.
func (c *Core) reuseWindowsLocked() []ReuseWindow {
	windows := make([]ReuseWindow, 0, len(c.cache))
	for key, entry := range c.cache {
		if !entry.windowEndsAt.After(entry.completedAt) {
			continue
		}
		windows = append(windows, ReuseWindow{
			Alias:          key.alias,
			SessionID:      key.sessionID,
			Serial:         entry.serial,
			WindowEndsAt:   entry.windowEndsAt,
			TokenExpiresAt: entry.expiresAt,
		})
	}
	if len(windows) == 0 {
		return nil
	}
	sort.Slice(windows, func(i, j int) bool {
		if !windows[i].WindowEndsAt.Equal(windows[j].WindowEndsAt) {
			return windows[i].WindowEndsAt.Before(windows[j].WindowEndsAt)
		}
		return windows[i].Alias < windows[j].Alias
	})
	return windows
}

// RunNotifier owns the reuse cache's clock: it tells the operator before and
// when a touch-free window closes, retires entries the moment they stop being
// usable, and watches for the card leaving the reader. It is one goroutine,
// started once by serve, and it returns when ctx is done.
func (c *Core) RunNotifier(ctx context.Context) {
	timer := time.NewTimer(time.Hour)
	defer timer.Stop()
	for {
		messages, next := c.notifierSweep(c.now().UTC())
		// Delivery runs a command, so it happens with no lock held.
		for _, message := range messages {
			c.notify(message)
		}
		if c.cacheSize() != 0 {
			c.pollReaders()
		}

		delay := time.Hour
		if !next.IsZero() {
			if delay = next.Sub(c.now().UTC()); delay < 0 {
				delay = 0
			}
		}
		if !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}
		timer.Reset(delay)
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		case <-c.notifyWake:
		}
	}
}

// notifierSweep is the pure step of the notifier: it emits the notices due at
// now, retires the entries that are finished, and reports when it next needs
// to run. It takes mu itself and returns messages for the caller to deliver
// without it.
func (c *Core) notifierSweep(now time.Time) (messages []string, next time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	consider := func(deadline time.Time) {
		if deadline.IsZero() {
			return
		}
		if next.IsZero() || deadline.Before(next) {
			next = deadline
		}
	}
	for key, entry := range c.cache {
		windowed := entry.windowEndsAt.After(entry.completedAt)
		switch {
		case windowed && !now.Before(entry.windowEndsAt):
			if !entry.notifiedExpired {
				entry.notifiedExpired = true
				messages = append(messages, fmt.Sprintf("window for %s expired; next mint needs a touch", key.alias))
			}
			zero(entry.token)
			delete(c.cache, key)
			continue
		case !now.Before(entry.expiresAt):
			// The assertion itself is dead. An entry that exists only to
			// coalesce concurrent requests never announced itself and leaves
			// the same way.
			zero(entry.token)
			delete(c.cache, key)
			continue
		}
		if windowed && !entry.notifiedPre && entry.windowEndsAt.Sub(entry.completedAt) > reuseNotifyLead {
			// A window no longer than the lead would announce its own opening,
			// so it gets the closing notice only.
			preAt := entry.windowEndsAt.Add(-reuseNotifyLead)
			if now.Before(preAt) {
				consider(preAt)
			} else {
				entry.notifiedPre = true
				messages = append(messages, fmt.Sprintf("window for %s expires in %ds", key.alias, int(reuseNotifyLead/time.Second)))
			}
		}
		if windowed {
			consider(entry.windowEndsAt)
		}
		consider(entry.expiresAt)
	}
	if len(c.cache) != 0 {
		consider(now.Add(readerPollInterval))
	}
	// Map iteration is unordered and these lines reach a desktop, so they are
	// sorted rather than shuffled.
	sort.Strings(messages)
	return messages, next
}

// pollReaders drops every assertion whose card is no longer the one in the
// reader. It enumerates hardware, so it runs with no lock held; a failed
// enumeration is treated as a change and drops everything.
func (c *Core) pollReaders() {
	names, supported, err := c.readerSnapshot()
	if !supported {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	purged := 0
	for key, entry := range c.cache {
		if err == nil && equalStrings(entry.readers, names) {
			continue
		}
		zero(entry.token)
		delete(c.cache, key)
		purged++
	}
	if purged != 0 {
		c.wakeNotifierLocked()
	}
}

func (c *Core) cacheSize() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.cache)
}

func (c *Core) notify(message string) {
	c.mu.RLock()
	notify := c.notifyFn
	c.mu.RUnlock()
	if notify != nil {
		notify(message)
	}
}

// wakeNotifier nudges the notifier so it recomputes its deadlines. The channel
// is buffered by one and the send is non-blocking, so a nudge never waits and
// never depends on the notifier running at all.
func (c *Core) wakeNotifier() {
	if c.notifyWake == nil {
		return
	}
	select {
	case c.notifyWake <- struct{}{}:
	default:
	}
}

// wakeNotifierLocked is wakeNotifier from a path that already holds mu. The
// send cannot block, so holding mu across it is safe.
func (c *Core) wakeNotifierLocked() { c.wakeNotifier() }

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
