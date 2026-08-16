// Package core holds the daemon state machine. After the WIF redesign it is
// deliberately narrow: it caches at most the verified PIV PIN and the
// metadata of the last successful signature. It never holds, caches, logs, or
// returns a Google access token, Google-issued ID token, or STS response, and
// the only credential it can mint is a five-minute OIDC subject token for a
// configured alias/target pair.
package core

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/xlfe/pivb/internal/agentsource"
	"github.com/xlfe/pivb/internal/attachment"
	"github.com/xlfe/pivb/internal/config"
	"github.com/xlfe/pivb/internal/forwardapi"
	"github.com/xlfe/pivb/internal/pivsigner"
	"github.com/xlfe/pivb/internal/tokenapi"
	"github.com/xlfe/pivb/internal/wif"
)

var ErrLocked = errors.New("PIN is not cached; run `pivb unlock` first")

type UnknownAliasError struct{ Alias string }

func (e *UnknownAliasError) Error() string { return fmt.Sprintf("unknown alias %q", e.Alias) }

// RequestMismatchError reports a subject-token request whose caller-supplied
// audience or impersonation target does not match the daemon configuration.
// It usually means a tampered or stale credential file.
type RequestMismatchError struct {
	Field string
	Got   string
	Want  string
}

// RequestSourceError rejects malformed trusted-host-asserted audit context
// before it can reach a signing label, daemon log, or notification command.
type RequestSourceError struct{ Err error }

func (e *RequestSourceError) Error() string { return "invalid request source: " + e.Err.Error() }
func (e *RequestSourceError) Unwrap() error { return e.Err }

func (e *RequestMismatchError) Error() string {
	return fmt.Sprintf("request %s %q does not match the configured value %q; regenerate the credential file with `pivb wif credentials`", e.Field, e.Got, e.Want)
}

// SubjectTokenRequest is the only credential operation the daemon accepts.
// Every field is validated against configuration; none of them select
// anything that configuration does not already bind.
type SubjectTokenRequest struct {
	Alias                   string
	ExternalAccountAudience string
	ImpersonatedEmail       string
	RequestSource           agentsource.Source
	Attachment              attachment.Context
	// RouteSocket selects a trusted-host ZKA workspace route. It is injected
	// by agent-session and is never present in the sandbox request shape.
	RouteSocket    string
	ExpectedCard   forwardapi.CardIdentity
	ForwardContext forwardapi.ForwardContext
}

type SubjectTokenResult struct {
	IDToken        string
	ExpiresAt      time.Time
	Serial         uint32
	KeyID          string
	SPKIDER        []byte
	ForwardContext forwardapi.ForwardContext
	// Reused reports an assertion served from an already-authorised signature
	// rather than from a fresh touch. It is observability only: the token is
	// byte-identical to the one that touch produced.
	Reused bool
}

// SignEvent records the metadata of the last successful signature for
// card-free status reporting. It contains no token material.
type SignEvent struct {
	Alias          string
	Target         string
	Serial         uint32
	KeyID          string
	At             time.Time
	Route          string
	ForwardContext forwardapi.ForwardContext
}

// mintRecord is one completed mint, kept in memory only for rate reporting.
// It holds no token material: an alias and a session identifier that
// configuration and agentsource.Validate have already bound, and nothing else.
type mintRecord struct {
	at        time.Time
	alias     string
	sessionID string
	// reused marks a mint served without a fresh signature; forwarded marks
	// one satisfied over a ZKA route rather than by the local card.
	reused    bool
	forwarded bool
}

const (
	// mintRingWindow is how far back the rolling counters can see, and
	// mintRingCap bounds the ring so an unexpectedly busy hour cannot grow it
	// without limit. Both are memory-only: no mint is ever refused for them.
	mintRingWindow = time.Hour
	mintRingCap    = 4096
	// A session that crosses mintWarnThreshold mints within mintWarnWindow
	// earns one journal warning per window. This is visibility, not policy:
	// none of those mints was refused, and the ones served from the reuse
	// cache spent no touch at all.
	mintWarnThreshold = 30
	mintWarnWindow    = 5 * time.Minute
)

const (
	// defaultSingleFlight coalesces the requests that arrive while a
	// byte-identical request is already being signed. One touch authorises one
	// request tuple; handing that tuple's queued duplicates the same signature
	// spends no further touch and grants no authority the touch did not. It is
	// one flippable constant so the behaviour can be disabled fleet-wide.
	defaultSingleFlight = true
	// reuseValidityFloor is the remaining assertion validity below which a
	// cached assertion is never served, so every reused token still has a full
	// minute in which to complete an STS exchange. internal/config bounds
	// assertion_reuse_s against the same floor.
	reuseValidityFloor = 60 * time.Second
	// reuseCacheCap bounds the cache in entries; past it the entry with the
	// oldest completion is evicted.
	reuseCacheCap = 64
	// reuseNotifyLead is how far ahead of a window's end the operator is told
	// that touch-free reuse is about to stop.
	reuseNotifyLead = 60 * time.Second
	// readerPollInterval is how often the notifier re-enumerates smart-card
	// readers while the cache is non-empty, so removing the card drops the
	// reuse state without waiting for the next mint.
	readerPollInterval = 2 * time.Second
	// invalidatedCap bounds the per-workspace invalidation watermarks.
	invalidatedCap = 256
)

// reuseKey is the requester tuple a touch authorises. Two requests share a
// signature only if every field matches, so the operator's consent covers
// exactly what they were shown on the touch prompt. It is deliberately
// comparable: it is a map key, never a fingerprint to be logged.
//
// ForwardContext.OperationID and ProviderAttachID are excluded on purpose:
// they identify one request, not one requester, and every forwarded mint
// carries a fresh pair. Everything an operator could read off the prompt —
// alias, target, audience, session, attachment, claimed card, workspace claim
// and its generation — is inside the key.
type reuseKey struct {
	alias, target, audience            string
	sourceKind, sourceLabel, sessionID string
	attachmentMode                     string
	attachmentProtocol                 int
	routeSocket                        string
	cardSerial                         uint32
	cardKID                            string
	cardSPKI                           string
	originNodeID, workspaceID, bundle  string
	claimGeneration                    uint64
}

// cacheEntry is one already-authorised assertion. token is the only secret in
// it and is zeroized on every path that drops the entry.
type cacheEntry struct {
	key         reuseKey
	token       []byte
	completedAt time.Time
	expiresAt   time.Time
	serial      uint32
	keyID       string
	spki        []byte
	// readers is the sorted reader-name snapshot taken when the assertion was
	// signed. nil means the signer cannot enumerate readers at all, which
	// disables the presence probe rather than failing it.
	readers []string
	// windowEndsAt is completedAt plus the alias reuse duration. It equals
	// completedAt when the entry exists only to coalesce concurrent requests,
	// which is how the notifier tells a consent window from a queue.
	windowEndsAt    time.Time
	notifiedPre     bool
	notifiedExpired bool
}

// ReuseWindow is one operator-visible touch-free window. It carries no token
// material and no request identifiers.
type ReuseWindow struct {
	Alias          string    `json:"alias"`
	SessionID      string    `json:"session_id,omitempty"`
	Serial         uint32    `json:"serial"`
	WindowEndsAt   time.Time `json:"window_ends_at"`
	TokenExpiresAt time.Time `json:"token_expires_at"`
}

// readerLister is the optional card-presence seam. pivsigner.Hardware
// implements it; fakes that do not simply skip the probe.
type readerLister interface {
	ListReaderNames() ([]string, error)
}

// MintCounters is the rolling in-memory mint rate. Reporting it touches no
// card and reveals no token material.
type MintCounters struct {
	Total1m  int `json:"total_1m"`
	Total5m  int `json:"total_5m"`
	Total60m int `json:"total_60m"`
	// Signatures60m counts the mints that spent a touch rather than reusing an
	// assertion an earlier touch already authorised.
	Signatures60m int            `json:"signatures_60m"`
	PerAlias60m   map[string]int `json:"per_alias_60m,omitempty"`
	PerSession60m map[string]int `json:"per_session_60m,omitempty"`
}

type Status struct {
	PINCached         bool                       `json:"pin_cached"`
	PINVerifiedSerial uint32                     `json:"pin_verified_serial"`
	WIFProvider       string                     `json:"wif_provider"`
	LastSignAlias     string                     `json:"last_sign_alias,omitempty"`
	LastSignTarget    string                     `json:"last_sign_target,omitempty"`
	LastSignSerial    uint32                     `json:"last_sign_serial,omitempty"`
	LastSignKeyID     string                     `json:"last_sign_key_id,omitempty"`
	LastSignAt        time.Time                  `json:"last_sign_at,omitzero"`
	LastSignRoute     string                     `json:"last_sign_route,omitempty"`
	LastSignForward   *forwardapi.ForwardContext `json:"last_sign_forward_context,omitempty"`
	Mints             *MintCounters              `json:"mints,omitempty"`
	ReuseWindows      []ReuseWindow              `json:"reuse_windows,omitempty"`
	Version           string                     `json:"version"`
}

type Core struct {
	cfg     *config.Config
	signer  pivsigner.Signer
	version string
	now     func() time.Time
	random  io.Reader

	// mintMu serializes PIV operations; mu guards cached state.
	mintMu            sync.Mutex
	mu                sync.RWMutex
	pin               []byte
	pinVerifiedSerial uint32
	lastSign          *SignEvent
	logger            *slog.Logger
	// mintRing is the rolling mint window, pruned only when a mint appends;
	// warnedAt records when each session last triggered a rate warning.
	mintRing []mintRecord
	warnedAt map[string]time.Time

	// cache holds already-authorised assertions; singleFlight decides whether
	// an entry may serve requests that were queued behind its own signature.
	cache        map[reuseKey]*cacheEntry
	singleFlight bool
	// invalidated is workspaceID → the highest claim generation whose cached
	// assertions have been invalidated. It exists to close one race: a mint
	// that entered the card before a purge must not insert its result after
	// it, and mintMu is deliberately not held by the purge.
	invalidated map[string]uint64
	// pendingWorkspace and pendingGeneration describe the single local mint
	// currently inside signer.Sign. mintMu serializes the local branch, so
	// there is never more than one, and a release-everything invalidation uses
	// it to raise its watermark over a claim that is not in the cache yet.
	pendingWorkspace  string
	pendingGeneration uint64

	notifyFn   func(string)
	notifyWake chan struct{}
	// arrivalHook runs immediately after a local request records its arrival
	// instant. Production leaves it nil; concurrency tests use it to hold every
	// racing request at the same point in the mint path.
	arrivalHook func()
}

func New(cfg *config.Config, signer pivsigner.Signer, version string) *Core {
	return &Core{
		cfg: cfg, signer: signer, version: version,
		now:          time.Now,
		random:       rand.Reader,
		singleFlight: defaultSingleFlight,
		notifyWake:   make(chan struct{}, 1),
	}
}

func (c *Core) SetNowForTest(now func() time.Time) { c.now = now }
func (c *Core) SetRandomForTest(random io.Reader)  { c.random = random }

// SetSingleFlightForTest disables or restores concurrency coalescing. A daemon
// built by New always starts at defaultSingleFlight.
func (c *Core) SetSingleFlightForTest(enabled bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.singleFlight = enabled
}

func (c *Core) SetMintArrivalHookForTest(hook func()) { c.arrivalHook = hook }

// SetNotify routes reuse-window notices to the operator's desktop. Without it
// the notices are computed and the entries still expire; only the message is
// dropped.
func (c *Core) SetNotify(notify func(string)) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.notifyFn = notify
}

// SetLogger routes core's own observations — today, only the mint-rate
// warning — to l. Without it they go to slog.Default().
func (c *Core) SetLogger(l *slog.Logger) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.logger = l
}

func (c *Core) Unlock(ctx context.Context, pin string) (int, error) {
	if pin == "" {
		return -1, errors.New("PIN must not be empty")
	}
	c.mintMu.Lock()
	defer c.mintMu.Unlock()
	serial, retries, err := c.signer.VerifyPIN(ctx, pin)
	if err != nil {
		return retries, err
	}
	c.mu.Lock()
	c.clearPINLocked()
	c.pin = append([]byte(nil), pin...)
	c.pinVerifiedSerial = serial
	// The card that is now authenticated is the only one whose touches this
	// daemon may still be trading on.
	c.purgeOtherSerialsLocked(serial)
	c.mu.Unlock()
	return retries, nil
}

// Lock discards the cached PIN, the cached signing metadata, and every
// already-authorised assertion.
func (c *Core) Lock() {
	c.mintMu.Lock()
	defer c.mintMu.Unlock()
	c.mu.Lock()
	defer c.mu.Unlock()
	c.clearPINLocked()
	c.lastSign = nil
	c.purgeAllLocked()
}

// SubjectToken validates the request against configuration, opens one PIV
// signing session, and returns a five-minute RS256 OIDC subject token bound
// to the enrolled key observed in that session. The token is returned to the
// caller and never retained or logged by the daemon.
func (c *Core) SubjectToken(ctx context.Context, req SubjectTokenRequest) (SubjectTokenResult, error) {
	if err := req.Attachment.Validate(); err != nil {
		return SubjectTokenResult{}, err
	}
	if req.Attachment.RouteRequired() {
		if req.RouteSocket != "" && req.RouteSocket != req.Attachment.RouteSocket {
			return SubjectTokenResult{}, &attachment.PolicyError{Message: "trusted request route conflicts with its attachment policy"}
		}
		req.RouteSocket = req.Attachment.RouteSocket
		result, err := RouteSubjectToken(ctx, c.cfg, req, c.now)
		if err != nil {
			return SubjectTokenResult{}, err
		}
		at := c.now().UTC()
		c.mu.Lock()
		c.lastSign = &SignEvent{
			Alias: req.Alias, Target: req.ImpersonatedEmail, Serial: result.Serial, KeyID: result.KeyID,
			At: at, Route: "zka-workspace-forwarded", ForwardContext: result.ForwardContext,
		}
		c.recordMintLocked(mintRecord{at: at, alias: req.Alias, sessionID: req.RequestSource.SessionID, forwarded: true})
		c.mu.Unlock()
		return result, nil
	}
	if req.RouteSocket != "" {
		return SubjectTokenResult{}, &attachment.PolicyError{Message: "local-allowed request cannot select a workspace route"}
	}
	source, _, err := agentsource.Validate(req.RequestSource, req.Alias)
	if err != nil {
		return SubjectTokenResult{}, &RequestSourceError{Err: err}
	}
	req.RequestSource = source
	switch {
	case req.ForwardContext.OperationID != "":
		ctx = pivsigner.WithOperation(ctx, pivsigner.OriginForwarded, req.ForwardContext.OperationID)
	case source.Kind == agentsource.KindAgentSession:
		ctx = pivsigner.WithOperation(ctx, pivsigner.OriginAgentSession, source.SessionID)
	default:
		ctx = pivsigner.WithOperation(ctx, pivsigner.OriginLocalWIF, "")
	}
	alias, ok := c.cfg.Aliases[req.Alias]
	if !ok {
		return SubjectTokenResult{}, &UnknownAliasError{Alias: req.Alias}
	}
	provider := c.cfg.Provider()
	if want := provider.ExternalAccountAudience(); req.ExternalAccountAudience != want {
		return SubjectTokenResult{}, &RequestMismatchError{Field: "external_account_audience", Got: req.ExternalAccountAudience, Want: want}
	}
	if req.ImpersonatedEmail != alias.Target {
		return SubjectTokenResult{}, &RequestMismatchError{Field: "impersonated_email", Got: req.ImpersonatedEmail, Want: alias.Target}
	}
	keys := c.cfg.KeysBySerial()
	// The request is now fully bound to configuration, so it can be reduced to
	// the tuple one touch authorises. arrival is taken before the queue: it is
	// what distinguishes a request that waited behind a signature from one
	// that arrived after it.
	aliasReuse := time.Duration(alias.AssertionReuseS) * time.Second
	cacheKey := reuseKeyFor(req, alias)
	arrival := c.now().UTC()
	if c.arrivalHook != nil {
		c.arrivalHook()
	}
	c.mintMu.Lock()
	defer c.mintMu.Unlock()

	if result, ok := c.serveAuthorised(cacheKey, req, arrival, aliasReuse); ok {
		return result, nil
	}
	pin, err := c.takePIN()
	if err != nil {
		return SubjectTokenResult{}, err
	}
	defer zero(pin)

	now := c.now().UTC()
	jti, err := wif.NewJTI(c.random)
	if err != nil {
		return SubjectTokenResult{}, err
	}

	var input string
	var claims wif.Claims
	var signedKid string
	var signedSPKI []byte
	digestFor := func(serial uint32, cert *x509.Certificate) ([]byte, error) {
		key, enrolled := keys[serial]
		if !enrolled {
			return nil, fmt.Errorf("YubiKey %d is not enrolled; add [keys.%d] to the configuration", serial, serial)
		}
		kid, kidErr := wif.CertificateKeyID(cert)
		if kidErr != nil {
			return nil, kidErr
		}
		if kid != key.JWKKid {
			return nil, fmt.Errorf("live slot 9c key on YubiKey %d derives jwk_kid %q but configuration expects %q; a replaced key must be deliberately re-enrolled", serial, kid, key.JWKKid)
		}
		if req.ExpectedCard.Serial != 0 && (serial != req.ExpectedCard.Serial || kid != req.ExpectedCard.KeyID) {
			return nil, fmt.Errorf("live YubiKey identity %d/%s does not match claimed identity %d/%s; re-claim the PIVB credential bundle", serial, kid, req.ExpectedCard.Serial, req.ExpectedCard.KeyID)
		}
		if len(req.ExpectedCard.SPKIDER) != 0 && !equalBytes(cert.RawSubjectPublicKeyInfo, req.ExpectedCard.SPKIDER) {
			return nil, fmt.Errorf("live slot 9c public key on YubiKey %d does not match the claimed PIVB provider", serial)
		}
		var claimsErr error
		claims, claimsErr = wif.NewClaims(provider, req.Alias, alias.Target, serial, kid, jti, now)
		if claimsErr != nil {
			return nil, claimsErr
		}
		var inputErr error
		input, inputErr = wif.SigningInput(claims)
		if inputErr != nil {
			return nil, inputErr
		}
		signedKid = kid
		signedSPKI = append([]byte(nil), cert.RawSubjectPublicKeyInfo...)
		return wif.SigningDigest(input), nil
	}

	label := signingLabel(req, alias.Target, aliasReuse)
	signCtx := ctx
	if req.ForwardContext.OperationID != "" {
		signCtx = pivsigner.RequireLease(ctx)
	}
	c.beginPendingMint(cacheKey)
	defer c.endPendingMint()
	sig, serial, err := c.signer.Sign(signCtx, label, string(pin), digestFor)
	c.recordPINVerification(serial, err)
	if err != nil {
		return SubjectTokenResult{}, err
	}
	if input == "" {
		return SubjectTokenResult{}, errors.New("signer returned without requesting a serial-bound digest")
	}
	token, err := wif.Assemble(input, sig)
	if err != nil {
		return SubjectTokenResult{}, err
	}
	// The touch took seconds, so the instant the assertion became authorised is
	// this one, not the pre-sign now that dated its claims.
	completedAt := c.now().UTC()
	entry := c.newCacheEntry(cacheKey, token, claims.ExpiresAt(), completedAt, aliasReuse, serial, signedKid, signedSPKI)
	c.mu.Lock()
	route := "local"
	if req.ForwardContext.OperationID != "" {
		route = "zka-workspace-provider"
	}
	c.lastSign = &SignEvent{Alias: req.Alias, Target: alias.Target, Serial: serial, KeyID: signedKid, At: now, Route: route, ForwardContext: req.ForwardContext}
	c.recordMintLocked(mintRecord{at: now, alias: req.Alias, sessionID: req.RequestSource.SessionID})
	inserted := c.insertLocked(entry)
	c.mu.Unlock()
	if inserted {
		c.wakeNotifier()
	}
	return SubjectTokenResult{IDToken: token, ExpiresAt: claims.ExpiresAt(), Serial: serial, KeyID: signedKid, SPKIDER: signedSPKI}, nil
}

// DescribeForwardProvider returns the non-secret policy and exact public card
// identity used to prepare a ZKA credential claim. It never verifies a PIN or
// requests a touch.
func (c *Core) DescribeForwardProvider(ctx context.Context) (forwardapi.Description, error) {
	describer, ok := c.signer.(pivsigner.Describer)
	if !ok {
		return forwardapi.Description{}, errors.New("configured signer cannot describe its live card")
	}
	c.mintMu.Lock()
	defer c.mintMu.Unlock()
	describeCtx := pivsigner.WithOperation(pivsigner.RequireLease(ctx), pivsigner.OriginForwarded, "")
	serial, cert, err := describer.Describe(describeCtx)
	if err != nil {
		return forwardapi.Description{}, err
	}
	key, ok := c.cfg.KeysBySerial()[serial]
	if !ok {
		return forwardapi.Description{}, fmt.Errorf("YubiKey %d is not enrolled", serial)
	}
	kid, err := wif.CertificateKeyID(cert)
	if err != nil {
		return forwardapi.Description{}, err
	}
	if kid != key.JWKKid {
		return forwardapi.Description{}, fmt.Errorf("live slot 9c key on YubiKey %d derives jwk_kid %q but configuration expects %q", serial, kid, key.JWKKid)
	}
	aliases := make(map[string]forwardapi.AliasBinding, len(c.cfg.Aliases))
	for name, alias := range c.cfg.Aliases {
		aliases[name] = forwardapi.AliasBinding{Target: alias.Target}
	}
	provider := c.cfg.Provider()
	return forwardapi.Description{
		Version: forwardapi.ProtocolVersion, ProviderResource: provider.Resource(), IssuerURI: provider.IssuerURI,
		Aliases: aliases,
		Card:    forwardapi.CardIdentity{Serial: serial, KeyID: kid, SPKIDER: append([]byte(nil), cert.RawSubjectPublicKeyInfo...)},
	}, nil
}

// ForwardPolicy is the card-free half of provider discovery. An origin uses
// it to reject a mismatched remote claim before publishing a workspace route.
func (c *Core) ForwardPolicy() forwardapi.Policy {
	aliases := make(map[string]forwardapi.AliasBinding, len(c.cfg.Aliases))
	for name, alias := range c.cfg.Aliases {
		aliases[name] = forwardapi.AliasBinding{Target: alias.Target}
	}
	keys := make([]forwardapi.EnrolledKey, 0, len(c.cfg.Keys))
	for serial, key := range c.cfg.KeysBySerial() {
		keys = append(keys, forwardapi.EnrolledKey{Serial: serial, KeyID: key.JWKKid})
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i].Serial < keys[j].Serial })
	provider := c.cfg.Provider()
	return forwardapi.Policy{
		Version: forwardapi.ProtocolVersion, ProviderResource: provider.Resource(), IssuerURI: provider.IssuerURI,
		Aliases: aliases, EnrolledKeys: keys,
	}
}

// RouteSubjectToken mints and verifies one token through a ZKA route without
// constructing or touching a local hardware signer. Protocol 1 reaches it
// through pivbd's trusted WIF API.
func RouteSubjectToken(ctx context.Context, cfg *config.Config, req SubjectTokenRequest, now func() time.Time) (SubjectTokenResult, error) {
	if cfg == nil {
		return SubjectTokenResult{}, &tokenapi.APIError{Status: 500, Code: tokenapi.CodeConfig, Message: "PIVB configuration is unavailable"}
	}
	if err := req.Attachment.Validate(); err != nil || !req.Attachment.RouteRequired() {
		if err == nil {
			err = &attachment.PolicyError{Message: "routed mint requires route-required attachment policy"}
		}
		return SubjectTokenResult{}, err
	}
	req.RouteSocket = req.Attachment.RouteSocket
	source, _, err := agentsource.Validate(req.RequestSource, req.Alias)
	if err != nil {
		return SubjectTokenResult{}, &RequestSourceError{Err: err}
	}
	req.RequestSource = source
	alias, ok := cfg.Aliases[req.Alias]
	if !ok {
		return SubjectTokenResult{}, &UnknownAliasError{Alias: req.Alias}
	}
	provider := cfg.Provider()
	if want := provider.ExternalAccountAudience(); req.ExternalAccountAudience != want {
		return SubjectTokenResult{}, &RequestMismatchError{Field: "external_account_audience", Got: req.ExternalAccountAudience, Want: want}
	}
	if req.ImpersonatedEmail != alias.Target {
		return SubjectTokenResult{}, &RequestMismatchError{Field: "impersonated_email", Got: req.ImpersonatedEmail, Want: alias.Target}
	}
	keys := cfg.KeysBySerial()
	if now == nil {
		now = time.Now
	}
	started := now().UTC()
	client := forwardapi.NewClientWithTimeout(req.RouteSocket, 25*time.Second)
	defer client.HTTP.CloseIdleConnections()
	response, err := client.Mint(ctx, forwardapi.MintRequest{
		Alias: req.Alias, ExternalAccountAudience: req.ExternalAccountAudience,
		ImpersonatedEmail: req.ImpersonatedEmail, RequestSource: &req.RequestSource,
	})
	if err != nil {
		return SubjectTokenResult{}, mapRouteError(err)
	}
	if response.Card.Serial != response.ExpectedCard.Serial || response.Card.KeyID != response.ExpectedCard.KeyID ||
		!equalBytes(response.Card.SPKIDER, response.ExpectedCard.SPKIDER) {
		return SubjectTokenResult{}, routeSecurityError("forwarded PIVB response card does not match the active workspace route")
	}
	verified, err := wif.VerifyForwarded(response.IDToken, response.Card.SPKIDER)
	if err != nil {
		return SubjectTokenResult{}, routeSecurityError("verify forwarded PIVB assertion: " + err.Error())
	}
	claims := verified.Claims
	provider = cfg.Provider()
	key, enrolled := keys[response.Card.Serial]
	if !enrolled || key.JWKKid != response.Card.KeyID || claims.KeyID != response.Card.KeyID {
		return SubjectTokenResult{}, routeSecurityError(fmt.Sprintf("forwarded PIVB card %d/%s is not enrolled on this origin", response.Card.Serial, response.Card.KeyID))
	}
	if claims.Iss != provider.IssuerURI || claims.Aud != provider.OIDCAudience() ||
		claims.Sub != wif.SubjectPrefix+response.Card.KeyID || claims.Alias != req.Alias ||
		claims.Target != alias.Target || claims.Serial != strconv.FormatUint(uint64(response.Card.Serial), 10) || claims.Jti == "" {
		return SubjectTokenResult{}, routeSecurityError("forwarded PIVB assertion claims do not match the requested local configuration")
	}
	// Providers backdate iat by one ClockSkew. Allow one additional skew for
	// an origin clock ahead of the provider and one skew in the other
	// direction; exp is independently checked against the origin clock.
	if claims.Exp-claims.Iat != int64(wif.Lifetime/time.Second) || response.ExpirationTime != claims.Exp ||
		!claims.ExpiresAt().After(now().UTC()) || claims.Iat < started.Add(-2*wif.ClockSkew).Unix() ||
		claims.Iat > now().UTC().Add(wif.ClockSkew).Unix() {
		return SubjectTokenResult{}, routeFreshnessError("forwarded PIVB assertion is stale or has an invalid lifetime")
	}
	if response.Card.KeyID != verified.HeaderKeyID {
		return SubjectTokenResult{}, routeSecurityError("forwarded PIVB response card does not match the signed token")
	}
	return SubjectTokenResult{
		IDToken: response.IDToken, ExpiresAt: claims.ExpiresAt(), Serial: response.Card.Serial,
		KeyID: response.Card.KeyID, SPKIDER: append([]byte(nil), response.Card.SPKIDER...), ForwardContext: response.ForwardContext,
	}, nil
}

func routeProtocolError(message string) error {
	return &tokenapi.APIError{Status: 502, Code: tokenapi.CodeConfig, Message: message, Remedy: "upgrade PIVB and ZKA together and re-claim the workspace bundle"}
}

func routeSecurityError(message string) error {
	return &tokenapi.APIError{
		Status: 502, Code: tokenapi.CodeConfig, Message: message, SecurityRelevant: true,
		Remedy: "inspect the selected ZKA workspace route, provider identity, and enrolled card; release and re-claim the bundle only if the binding is wrong",
	}
}

func routeFreshnessError(message string) error {
	return &tokenapi.APIError{
		Status: 502, Code: tokenapi.CodeConfig, Message: message,
		Remedy: "check the origin and provider clocks, then inspect the selected ZKA workspace route before retrying",
	}
}

func mapRouteError(err error) error {
	var apiErr *tokenapi.APIError
	var protocolErr *forwardapi.ProtocolError
	if errors.As(err, &apiErr) {
		return apiErr
	}
	if errors.As(err, &protocolErr) {
		return routeProtocolError(protocolErr.Error())
	}
	return &tokenapi.APIError{Status: 503, Code: tokenapi.CodeUnavailable, Message: "selected PIVB workspace route is unavailable", Remedy: "check the ZKA workspace claim and route status"}
}

func (c *Core) Status() Status {
	c.mu.RLock()
	defer c.mu.RUnlock()
	status := Status{
		PINCached:         len(c.pin) != 0,
		PINVerifiedSerial: c.pinVerifiedSerial,
		WIFProvider:       c.cfg.Provider().Resource(),
		Version:           c.version,
	}
	if c.lastSign != nil {
		status.LastSignAlias = c.lastSign.Alias
		status.LastSignTarget = c.lastSign.Target
		status.LastSignSerial = c.lastSign.Serial
		status.LastSignKeyID = c.lastSign.KeyID
		status.LastSignAt = c.lastSign.At
		status.LastSignRoute = c.lastSign.Route
		if c.lastSign.ForwardContext.OperationID != "" {
			forward := c.lastSign.ForwardContext
			status.LastSignForward = &forward
		}
	}
	status.Mints = c.mintCountersLocked()
	status.ReuseWindows = c.reuseWindowsLocked()
	return status
}

// recordMintLocked appends one completed mint to the rolling window and warns
// when a single session's rate crosses the threshold. The caller holds c.mu.
// It is bookkeeping only: the mint has already succeeded, and nothing here can
// change that outcome or reach the card.
func (c *Core) recordMintLocked(rec mintRecord) {
	c.mintRing = append(c.mintRing, rec)
	cutoff := rec.at.Add(-mintRingWindow)
	kept := c.mintRing[:0]
	for _, entry := range c.mintRing {
		if entry.at.After(cutoff) {
			kept = append(kept, entry)
		}
	}
	c.mintRing = kept
	if overflow := len(c.mintRing) - mintRingCap; overflow > 0 {
		// Drop the oldest, compacting in place so the ring cannot creep
		// forward through an ever-growing backing array.
		c.mintRing = c.mintRing[:copy(c.mintRing, c.mintRing[overflow:])]
	}
	if rec.sessionID == "" {
		return
	}

	since := rec.at.Add(-mintWarnWindow)
	recent := 0
	for _, entry := range c.mintRing {
		if entry.sessionID == rec.sessionID && entry.at.After(since) {
			recent++
		}
	}
	// One line per window per session, so a busy agent cannot flood the
	// journal with the evidence that it is busy.
	if recent >= mintWarnThreshold && !c.warnedAt[rec.sessionID].After(since) {
		c.loggerLocked().Warn("session mint rate exceeds threshold",
			"session_id", rec.sessionID, "alias", rec.alias, "mints_5m", recent)
		if c.warnedAt == nil {
			c.warnedAt = make(map[string]time.Time)
		}
		c.warnedAt[rec.sessionID] = rec.at
	}
	for session, at := range c.warnedAt {
		if !at.After(cutoff) {
			delete(c.warnedAt, session)
		}
	}
}

// mintCountersLocked aggregates the rolling window without pruning it, so
// Status keeps the read lock; pruning happens only when a mint appends. It
// returns nil when nothing was minted in the window, leaving Status silent
// about a rate rather than reporting a row of zeros.
func (c *Core) mintCountersLocked() *MintCounters {
	if len(c.mintRing) == 0 {
		return nil
	}
	now := c.now().UTC()
	counters := MintCounters{PerAlias60m: make(map[string]int), PerSession60m: make(map[string]int)}
	for _, entry := range c.mintRing {
		age := now.Sub(entry.at)
		if age >= mintRingWindow {
			continue
		}
		counters.Total60m++
		if !entry.reused {
			counters.Signatures60m++
		}
		if age < time.Minute {
			counters.Total1m++
		}
		if age < 5*time.Minute {
			counters.Total5m++
		}
		if entry.alias != "" {
			counters.PerAlias60m[entry.alias]++
		}
		if entry.sessionID != "" {
			counters.PerSession60m[entry.sessionID]++
		}
	}
	if counters.Total60m == 0 {
		return nil
	}
	if len(counters.PerAlias60m) == 0 {
		counters.PerAlias60m = nil
	}
	if len(counters.PerSession60m) == 0 {
		counters.PerSession60m = nil
	}
	return &counters
}

// loggerLocked reads c.logger, so the caller holds c.mu.
func (c *Core) loggerLocked() *slog.Logger {
	if c.logger != nil {
		return c.logger
	}
	return slog.Default()
}

// signingLabel renders what the operator is asked to consent to. When the
// alias configures a reuse window the prompt says so, because the touch is no
// longer buying one credential: it is buying every byte-identical request for
// the next reuse seconds.
func signingLabel(req SubjectTokenRequest, target string, reuse time.Duration) string {
	label := agentsource.SigningLabel(req.RequestSource, req.Alias, target)
	if fc := req.ForwardContext; fc.OperationID != "" {
		label = fmt.Sprintf("%s [ZKA origin=%s workspace=%s bundle=%s generation=%d operation=%s]",
			label, fc.OriginNodeID, fc.WorkspaceID, fc.Bundle, fc.ClaimGeneration, fc.OperationID)
	}
	if reuse > 0 {
		label += fmt.Sprintf("\nauthorises %s touch-free for %s", req.Alias, reuse)
	}
	return label
}

func (c *Core) takePIN() ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.pin) == 0 {
		return nil, ErrLocked
	}
	copyPIN := append([]byte(nil), c.pin...)
	if c.cfg.PINCache == "never" {
		c.clearPINLocked()
	}
	return copyPIN, nil
}

func (c *Core) clearPINLocked() {
	zero(c.pin)
	c.pin = nil
	c.pinVerifiedSerial = 0
}

// recordPINVerification updates cached-PIN state after a signing attempt. A
// nonzero serial means the signer verified the cached PIN against that card
// during the operation; a PINError can demand the cache be dropped.
func (c *Core) recordPINVerification(serial uint32, signErr error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	var pinErr *pivsigner.PINError
	if errors.As(signErr, &pinErr) {
		if pinErr.ClearCachedPIN {
			c.clearPINLocked()
			// A PIN the card rejected leaves no basis for trading on anything
			// that PIN authorised.
			c.purgeAllLocked()
		}
		return
	}
	if serial != 0 && len(c.pin) != 0 {
		c.pinVerifiedSerial = serial
		c.purgeOtherSerialsLocked(serial)
	}
}

func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

func equalBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var different byte
	for i := range a {
		different |= a[i] ^ b[i]
	}
	return different == 0
}
