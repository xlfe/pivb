package core

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/xlfe/pivb/internal/agentsource"
	"github.com/xlfe/pivb/internal/attachment"
	"github.com/xlfe/pivb/internal/config"
	"github.com/xlfe/pivb/internal/forwardapi"
	"github.com/xlfe/pivb/internal/pivsigner"
	"github.com/xlfe/pivb/internal/wif"
)

// forwardedRequest is a mint arriving from a ZKA origin: the local branch sees
// it with a claimed card identity and a workspace claim attached.
func forwardedRequest(t *testing.T, signer *fakeSigner, workspace string, generation uint64) SubjectTokenRequest {
	t.Helper()
	req := roRequest()
	req.ExpectedCard = forwardapi.CardIdentity{
		Serial: serialA, KeyID: kidA,
		SPKIDER: append([]byte(nil), signer.cards[serialA].cert.RawSubjectPublicKeyInfo...),
	}
	req.ForwardContext = forwardapi.ForwardContext{
		OriginNodeID: strings.Repeat("a", 32), WorkspaceID: workspace, Bundle: "work",
		ClaimGeneration: generation, ProviderNodeID: strings.Repeat("c", 32),
		OperationID: strings.Repeat("e", 32),
	}
	return req
}

// pendingWorkspaceOf reports the workspace claim of the mint currently inside
// the card, which is how a test knows a touch is really in flight.
func pendingWorkspaceOf(c *Core) string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.pendingWorkspace
}

func TestSingleFlightCoalescesConcurrentIdenticalRequests(t *testing.T) {
	c, signer := newTestCore(t, testConfig("session"), serialA)
	startTickClock(c)
	unlockOK(t, c, pinA)

	results := mintRace(t, c, signer, roRequest(), 8)

	counts := signer.snapshotCounts()
	if counts.signatures != 1 {
		t.Fatalf("eight identical concurrent requests spent %d signatures, want 1: %+v", counts.signatures, counts)
	}
	if labels := signer.snapshotLabels(); len(labels) != 1 {
		t.Errorf("touch prompts = %q, want exactly one", labels)
	}
	reused := 0
	for i, result := range results {
		if result.IDToken != results[0].IDToken {
			t.Fatalf("request %d received a token the shared touch did not produce", i)
		}
		if result.Reused {
			reused++
		}
	}
	if reused != 7 {
		t.Errorf("%d of 8 results reported Reused, want the 7 that were queued behind the touch", reused)
	}
	// The request that was not queued behind anything is the one that spent the
	// touch, and it is the only one that counts as a signature.
	counters := c.Status().Mints
	if counters == nil || counters.Total60m != 8 || counters.Signatures60m != 1 {
		t.Errorf("mint counters = %+v, want 8 mints on 1 signature", counters)
	}
}

func TestSingleFlightDoesNotCoalesceSequentialRequests(t *testing.T) {
	c, signer := newTestCore(t, testConfig("session"), serialA)
	startTickClock(c)
	unlockOK(t, c, pinA)

	first := parseToken(t, mintOK(t, c, roRequest()).IDToken)
	second := parseToken(t, mintOK(t, c, roRequest()).IDToken)

	if got := signer.snapshotCounts().signatures; got != 2 {
		t.Fatalf("two sequential identical requests spent %d signatures, want 2", got)
	}
	if first.claims["jti"] == second.claims["jti"] {
		t.Errorf("both tokens carry jti %v", first.claims["jti"])
	}
}

func TestSingleFlightDisabledIsByteForByteToday(t *testing.T) {
	c, signer := newTestCore(t, testConfig("session"), serialA)
	c.SetSingleFlightForTest(false)
	startTickClock(c)
	unlockOK(t, c, pinA)

	results := mintRace(t, c, signer, roRequest(), 8)

	if got := signer.snapshotCounts().signatures; got != 8 {
		t.Fatalf("coalescing disabled spent %d signatures, want one per request", got)
	}
	seen := make(map[string]bool, len(results))
	for i, result := range results {
		if result.Reused {
			t.Errorf("request %d was answered from another request's signature", i)
		}
		if seen[result.IDToken] {
			t.Errorf("request %d repeated a token", i)
		}
		seen[result.IDToken] = true
	}
	// With neither coalescing nor a window configured, the daemon holds no
	// assertion at all.
	if size := c.cacheSize(); size != 0 {
		t.Errorf("cache holds %d assertions, want none", size)
	}
}

func TestReuseServesWithinWindowAndRespectsFloor(t *testing.T) {
	t.Run("inside the window the touch is not spent again", func(t *testing.T) {
		c, signer := newTestCore(t, reuseConfig("session", 120), serialA)
		clock := startTickClock(c)
		unlockOK(t, c, pinA)

		first := mintOK(t, c, roRequest())
		clock.advance(60 * time.Second)
		second := mintOK(t, c, roRequest())

		if got := signer.snapshotCounts().signatures; got != 1 {
			t.Fatalf("a request inside the window spent %d signatures, want 1", got)
		}
		if second.IDToken != first.IDToken {
			t.Error("the reused request returned a token the touch did not produce")
		}
		if first.Reused || !second.Reused {
			t.Errorf("Reused = %t then %t, want false then true", first.Reused, second.Reused)
		}
	})

	t.Run("an assertion too close to expiry is never served", func(t *testing.T) {
		// 280 seconds is past what configuration accepts. The floor is a serve
		// time check in its own right, not a restatement of that bound.
		c, signer := newTestCore(t, reuseConfig("session", 280), serialA)
		clock := startTickClock(c)
		unlockOK(t, c, pinA)

		first := mintOK(t, c, roRequest())
		clock.advance(250 * time.Second)
		second := mintOK(t, c, roRequest())

		if got := signer.snapshotCounts().signatures; got != 2 {
			t.Fatalf("an assertion inside its window but past the validity floor was reused: %d signatures, want 2", got)
		}
		if second.Reused || second.IDToken == first.IDToken {
			t.Error("a request past the validity floor was served from the cache")
		}
	})
}

// TestReuseKeyCoversEveryRequestField walks every field of the tuple a touch
// authorises, including the ones request validation rejects before they could
// reach the cache, and pins what is deliberately outside it.
func TestReuseKeyCoversEveryRequestField(t *testing.T) {
	base := roRequest()
	base.RequestSource = agentsource.Agent("codex:proj/ro", strings.Repeat("a", agentsource.SessionIDLength))
	base.ExpectedCard = forwardapi.CardIdentity{Serial: serialA, KeyID: kidA, SPKIDER: []byte{1, 2, 3}}
	base.ForwardContext = forwardapi.ForwardContext{
		OriginNodeID: strings.Repeat("b", 32), WorkspaceID: strings.Repeat("c", 32), Bundle: "work",
		ClaimGeneration: 7, ProviderNodeID: strings.Repeat("d", 32),
		ProviderAttachID: strings.Repeat("e", 32), OperationID: strings.Repeat("f", 32),
	}
	baseAlias := config.Alias{Cloud: "gcp", Target: roTarget, LifetimeS: 3600}
	baseKey := reuseKeyFor(base, baseAlias)

	diverges := map[string]func(*SubjectTokenRequest, *config.Alias){
		"alias":               func(r *SubjectTokenRequest, _ *config.Alias) { r.Alias = "deploy" },
		"target":              func(_ *SubjectTokenRequest, a *config.Alias) { a.Target = deployTarget },
		"audience":            func(r *SubjectTokenRequest, _ *config.Alias) { r.ExternalAccountAudience = testOIDCAudience },
		"source kind":         func(r *SubjectTokenRequest, _ *config.Alias) { r.RequestSource.Kind = agentsource.KindLocal },
		"source label":        func(r *SubjectTokenRequest, _ *config.Alias) { r.RequestSource.Label = "codex:other/ro" },
		"session id":          func(r *SubjectTokenRequest, _ *config.Alias) { r.RequestSource.SessionID = strings.Repeat("9", 32) },
		"attachment mode":     func(r *SubjectTokenRequest, _ *config.Alias) { r.Attachment.Mode = attachment.ModeRouteRequired },
		"attachment protocol": func(r *SubjectTokenRequest, _ *config.Alias) { r.Attachment.Protocol = 2 },
		"route socket":        func(r *SubjectTokenRequest, _ *config.Alias) { r.Attachment.RouteSocket = "/run/zka/route.sock" },
		"card serial":         func(r *SubjectTokenRequest, _ *config.Alias) { r.ExpectedCard.Serial = serialB },
		"card key id":         func(r *SubjectTokenRequest, _ *config.Alias) { r.ExpectedCard.KeyID = kidB },
		"card spki":           func(r *SubjectTokenRequest, _ *config.Alias) { r.ExpectedCard.SPKIDER = []byte{9, 9, 9} },
		"origin node":         func(r *SubjectTokenRequest, _ *config.Alias) { r.ForwardContext.OriginNodeID = strings.Repeat("0", 32) },
		"workspace":           func(r *SubjectTokenRequest, _ *config.Alias) { r.ForwardContext.WorkspaceID = strings.Repeat("1", 32) },
		"bundle":              func(r *SubjectTokenRequest, _ *config.Alias) { r.ForwardContext.Bundle = "other" },
		"claim generation":    func(r *SubjectTokenRequest, _ *config.Alias) { r.ForwardContext.ClaimGeneration = 8 },
	}
	for name, mutate := range diverges {
		t.Run(name, func(t *testing.T) {
			req, alias := base, baseAlias
			mutate(&req, &alias)
			if reuseKeyFor(req, alias) == baseKey {
				t.Errorf("a request differing only in its %s shares a touch with the original", name)
			}
		})
	}

	// Per-request identifiers stay outside the tuple on purpose: they name one
	// request rather than one requester, and every forwarded mint carries new
	// ones. ProviderNodeID is the daemon's own asserted identity, constant for
	// the daemon and absent from the assertion it signs. RouteSocket is the
	// caller's hint; the local branch takes the route from the attachment.
	shared := map[string]func(*SubjectTokenRequest){
		"operation id":       func(r *SubjectTokenRequest) { r.ForwardContext.OperationID = strings.Repeat("7", 32) },
		"provider attach id": func(r *SubjectTokenRequest) { r.ForwardContext.ProviderAttachID = strings.Repeat("8", 32) },
		"provider node id":   func(r *SubjectTokenRequest) { r.ForwardContext.ProviderNodeID = strings.Repeat("6", 32) },
		"caller route hint":  func(r *SubjectTokenRequest) { r.RouteSocket = "/run/zka/ignored.sock" },
	}
	for name, mutate := range shared {
		t.Run("shared despite "+name, func(t *testing.T) {
			req := base
			mutate(&req)
			if reuseKeyFor(req, baseAlias) != baseKey {
				t.Errorf("a request differing only in its %s was refused the touch it belongs to", name)
			}
		})
	}
}

// TestReuseKeyMismatchMintsFresh is the end-to-end half: every divergence a
// validated request can actually carry buys its own touch, and a difference in
// the per-request operation identifier does not.
func TestReuseKeyMismatchMintsFresh(t *testing.T) {
	session := strings.Repeat("a", agentsource.SessionIDLength)
	baseRequest := func() SubjectTokenRequest {
		req := agentRequest(roRequest(), "codex:proj/ro", session)
		req.ForwardContext = forwardapi.ForwardContext{
			OriginNodeID: strings.Repeat("c", 32), WorkspaceID: strings.Repeat("d", 32), Bundle: "work",
			ClaimGeneration: 7, ProviderNodeID: strings.Repeat("e", 32), OperationID: strings.Repeat("f", 32),
		}
		return req
	}

	tests := map[string]struct {
		mutate    func(SubjectTokenRequest, *fakeSigner) SubjectTokenRequest
		wantFresh bool
	}{
		"identical": {
			mutate: func(req SubjectTokenRequest, _ *fakeSigner) SubjectTokenRequest { return req },
		},
		"another operation of the same claim": {
			mutate: func(req SubjectTokenRequest, _ *fakeSigner) SubjectTokenRequest {
				req.ForwardContext.OperationID = strings.Repeat("9", 32)
				return req
			},
		},
		"another provider attachment of the same claim": {
			mutate: func(req SubjectTokenRequest, _ *fakeSigner) SubjectTokenRequest {
				req.ForwardContext.ProviderAttachID = strings.Repeat("8", 32)
				return req
			},
		},
		"another alias": {
			mutate: func(req SubjectTokenRequest, _ *fakeSigner) SubjectTokenRequest {
				next := agentRequest(deployRequest(), "codex:proj/deploy", session)
				next.ForwardContext = req.ForwardContext
				return next
			},
			wantFresh: true,
		},
		"another agent session": {
			mutate: func(req SubjectTokenRequest, _ *fakeSigner) SubjectTokenRequest {
				req.RequestSource = agentsource.Agent("codex:proj/ro", strings.Repeat("b", agentsource.SessionIDLength))
				return req
			},
			wantFresh: true,
		},
		"another source label": {
			mutate: func(req SubjectTokenRequest, _ *fakeSigner) SubjectTokenRequest {
				req.RequestSource = agentsource.Agent("claude:proj/ro", session)
				return req
			},
			wantFresh: true,
		},
		"no agent session at all": {
			mutate: func(req SubjectTokenRequest, _ *fakeSigner) SubjectTokenRequest {
				req.RequestSource = agentsource.Source{}
				return req
			},
			wantFresh: true,
		},
		"a claimed card identity": {
			mutate: func(req SubjectTokenRequest, signer *fakeSigner) SubjectTokenRequest {
				req.ExpectedCard = forwardapi.CardIdentity{
					Serial: serialA, KeyID: kidA,
					SPKIDER: append([]byte(nil), signer.cards[serialA].cert.RawSubjectPublicKeyInfo...),
				}
				return req
			},
			wantFresh: true,
		},
		"another workspace claim generation": {
			mutate: func(req SubjectTokenRequest, _ *fakeSigner) SubjectTokenRequest {
				req.ForwardContext.ClaimGeneration = 8
				return req
			},
			wantFresh: true,
		},
		"another bundle": {
			mutate: func(req SubjectTokenRequest, _ *fakeSigner) SubjectTokenRequest {
				req.ForwardContext.Bundle = "other"
				return req
			},
			wantFresh: true,
		},
		"another workspace": {
			mutate: func(req SubjectTokenRequest, _ *fakeSigner) SubjectTokenRequest {
				req.ForwardContext.WorkspaceID = strings.Repeat("9", 32)
				return req
			},
			wantFresh: true,
		},
		"another origin node": {
			mutate: func(req SubjectTokenRequest, _ *fakeSigner) SubjectTokenRequest {
				req.ForwardContext.OriginNodeID = strings.Repeat("9", 32)
				return req
			},
			wantFresh: true,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			c, signer := newTestCore(t, reuseConfig("session", 120), serialA)
			startTickClock(c)
			unlockOK(t, c, pinA)

			base := mintOK(t, c, baseRequest())
			result := mintOK(t, c, test.mutate(baseRequest(), signer))

			wantSignatures := 1
			if test.wantFresh {
				wantSignatures = 2
			}
			if got := signer.snapshotCounts().signatures; got != wantSignatures {
				t.Fatalf("signatures = %d, want %d", got, wantSignatures)
			}
			if test.wantFresh && (result.Reused || result.IDToken == base.IDToken) {
				t.Error("a request outside the authorised tuple was served from the cache")
			}
			if !test.wantFresh && (!result.Reused || result.IDToken != base.IDToken) {
				t.Error("a request inside the authorised tuple was made to buy its own touch")
			}
		})
	}
}

func TestLockPurgesReuseState(t *testing.T) {
	c, signer := newTestCore(t, reuseConfig("session", 120), serialA)
	startTickClock(c)
	unlockOK(t, c, pinA)
	mintOK(t, c, roRequest())

	if windows := c.Status().ReuseWindows; len(windows) != 1 {
		t.Fatalf("status reports %d windows before Lock, want 1", len(windows))
	}

	c.Lock()

	if size := c.cacheSize(); size != 0 {
		t.Errorf("Lock left %d assertions behind", size)
	}
	if windows := c.Status().ReuseWindows; windows != nil {
		t.Errorf("Lock left windows behind: %+v", windows)
	}
	unlockOK(t, c, pinA)
	if result := mintOK(t, c, roRequest()); result.Reused {
		t.Error("a request after Lock was served from a window Lock should have closed")
	}
	if got := signer.snapshotCounts().signatures; got != 2 {
		t.Errorf("signatures = %d, want a fresh touch after Lock", got)
	}
}

func TestCardReaderChangePurges(t *testing.T) {
	tests := map[string]struct {
		disturb func(*fakeSigner)
		// wantHeld is what the fresh touch leaves behind. A daemon that cannot
		// enumerate readers at all keeps nothing, because an entry it could
		// never probe again is one it must never serve.
		wantHeld int
	}{
		"the card was replaced": {
			disturb: func(s *fakeSigner) { s.setReaders([]string{"Some Other Reader 00 00"}, nil) }, wantHeld: 1,
		},
		"a second reader appeared": {
			disturb: func(s *fakeSigner) { s.setReaders([]string{"Yubico YubiKey OTP+FIDO+CCID 00 00", "gpg"}, nil) }, wantHeld: 1,
		},
		"the card was removed": {
			disturb: func(s *fakeSigner) { s.setReaders(nil, nil) }, wantHeld: 1,
		},
		"enumeration stopped working": {
			disturb: func(s *fakeSigner) { s.setReaders(nil, errors.New("pcscd is unavailable")) }, wantHeld: 0,
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			c, signer := newTestCore(t, reuseConfig("session", 120), serialA)
			startTickClock(c)
			unlockOK(t, c, pinA)
			mintOK(t, c, roRequest())

			test.disturb(signer)
			result := mintOK(t, c, roRequest())

			if result.Reused {
				t.Error("an assertion was served after the reader it was signed on changed")
			}
			if got := signer.snapshotCounts().signatures; got != 2 {
				t.Errorf("signatures = %d, want the changed reader to have cost a fresh touch", got)
			}
			if size := c.cacheSize(); size != test.wantHeld {
				t.Errorf("cache holds %d assertions after the fresh touch, want %d", size, test.wantHeld)
			}
		})
	}
}

func TestNotifierPollPurgesOnReaderChange(t *testing.T) {
	c, signer := newTestCore(t, reuseConfig("session", 120), serialA)
	startTickClock(c)
	unlockOK(t, c, pinA)
	mintOK(t, c, roRequest())

	signer.setReaders(nil, nil)
	c.pollReaders()

	if size := c.cacheSize(); size != 0 {
		t.Errorf("the poll left %d assertions behind after the card was removed", size)
	}
}

func TestSwapPurgesViaPINVerification(t *testing.T) {
	c, signer := newTestCore(t, reuseConfig("session", 120), serialA)
	startTickClock(c)
	unlockOK(t, c, pinA)
	mintOK(t, c, roRequest())

	// The fleet key is swapped and a different alias is minted on it. That
	// signature is the daemon's first evidence of the new card, and the
	// assertions the old one authorised go with it.
	signer.setCurrent(serialB)
	mintOK(t, c, deployRequest())

	if size := c.cacheSize(); size != 1 {
		t.Fatalf("cache holds %d assertions after the swap, want only the new card's", size)
	}
	if _, entry := onlyEntry(t, c); entry.serial != serialB {
		t.Fatalf("the surviving assertion is bound to YubiKey %d, want %d", entry.serial, serialB)
	}
	if result := mintOK(t, c, roRequest()); result.Reused {
		t.Error("an assertion the removed card authorised was served after the swap")
	}
}

func TestRejectedCachedPINPurgesReuseState(t *testing.T) {
	c, signer := newTestCore(t, reuseConfig("session", 120), serialA)
	startTickClock(c)
	unlockOK(t, c, pinA)
	mintOK(t, c, roRequest())

	// The swapped key has a different PIN, so the cached one is rejected and
	// dropped. Nothing it authorised survives that.
	signer.mu.Lock()
	signer.pins[serialB] = pinB
	signer.mu.Unlock()
	signer.setCurrent(serialB)

	if _, err := c.SubjectToken(context.Background(), deployRequest()); err == nil {
		t.Fatal("the swapped key with a different PIN minted a token")
	}
	if size := c.cacheSize(); size != 0 {
		t.Errorf("a rejected cached PIN left %d assertions behind", size)
	}
}

func TestUnlockPurgesAnotherCardsAssertions(t *testing.T) {
	c, signer := newTestCore(t, reuseConfig("session", 120), serialA)
	startTickClock(c)
	unlockOK(t, c, pinA)
	mintOK(t, c, roRequest())

	signer.setCurrent(serialB)
	unlockOK(t, c, pinA)

	if size := c.cacheSize(); size != 0 {
		t.Errorf("unlocking against another card left %d of its predecessor's assertions", size)
	}
}

func TestInvalidateWorkspacePurgesByGeneration(t *testing.T) {
	workspaceX := strings.Repeat("1", 32)
	workspaceY := strings.Repeat("2", 32)

	c, signer := newTestCore(t, reuseConfig("session", 200), serialA)
	startTickClock(c)
	unlockOK(t, c, pinA)

	mintOK(t, c, forwardedRequest(t, signer, workspaceX, 6))
	mintOK(t, c, forwardedRequest(t, signer, workspaceX, 7))
	mintOK(t, c, forwardedRequest(t, signer, workspaceY, 7))
	if size := c.cacheSize(); size != 3 {
		t.Fatalf("cache holds %d assertions, want 3", size)
	}

	if purged := c.InvalidateWorkspace(workspaceX, 6); purged != 1 {
		t.Fatalf("InvalidateWorkspace(X, 6) purged %d assertions, want only generation 6 of X", purged)
	}
	if size := c.cacheSize(); size != 2 {
		t.Fatalf("cache holds %d assertions after the invalidation, want 2", size)
	}

	// The watermark outlives the entries: a mint for the invalidated generation
	// still succeeds, but nothing it produces is kept.
	before := signer.snapshotCounts().signatures
	mintOK(t, c, forwardedRequest(t, signer, workspaceX, 6))
	mintOK(t, c, forwardedRequest(t, signer, workspaceX, 6))
	if got := signer.snapshotCounts().signatures - before; got != 2 {
		t.Errorf("the invalidated generation spent %d signatures over two mints, want 2", got)
	}

	// A claim that advances past the watermark is cacheable again.
	before = signer.snapshotCounts().signatures
	mintOK(t, c, forwardedRequest(t, signer, workspaceX, 8))
	if result := mintOK(t, c, forwardedRequest(t, signer, workspaceX, 8)); !result.Reused {
		t.Error("a workspace re-claimed at a higher generation was refused its own window")
	}
	if got := signer.snapshotCounts().signatures - before; got != 1 {
		t.Errorf("the re-claimed generation spent %d signatures, want 1", got)
	}

	t.Run("releasing every generation", func(t *testing.T) {
		if purged := c.InvalidateWorkspace(workspaceY, 0); purged != 1 {
			t.Fatalf("InvalidateWorkspace(Y, 0) purged %d assertions, want 1", purged)
		}
		before := signer.snapshotCounts().signatures
		mintOK(t, c, forwardedRequest(t, signer, workspaceY, 7))
		mintOK(t, c, forwardedRequest(t, signer, workspaceY, 7))
		if got := signer.snapshotCounts().signatures - before; got != 2 {
			t.Errorf("the released generation spent %d signatures over two mints, want 2", got)
		}
		// A release is followed by a re-claim, which must be able to cache.
		before = signer.snapshotCounts().signatures
		mintOK(t, c, forwardedRequest(t, signer, workspaceY, 8))
		if result := mintOK(t, c, forwardedRequest(t, signer, workspaceY, 8)); !result.Reused {
			t.Error("a workspace re-claimed after a full release was refused its own window")
		}
		if got := signer.snapshotCounts().signatures - before; got != 1 {
			t.Errorf("the re-claimed generation spent %d signatures, want 1", got)
		}
	})

	if purged := c.InvalidateWorkspace("", 0); purged != 0 {
		t.Errorf("InvalidateWorkspace with no workspace purged %d assertions", purged)
	}
	// A local mint carries no workspace claim and is untouched by any of this.
	if purged := c.InvalidateWorkspace(workspaceX, 0); purged != 2 {
		t.Errorf("releasing X purged %d assertions, want its two generation-8 entries", purged)
	}
}

// TestInvalidateWorkspaceBeatsAnInFlightMint is the race the watermark exists
// for: the release lands while the touch is still being waited on, so it finds
// nothing to purge and can only work by refusing the insert that follows.
func TestInvalidateWorkspaceBeatsAnInFlightMint(t *testing.T) {
	workspace := strings.Repeat("1", 32)
	for name, maxGeneration := range map[string]uint64{"bounded generation": 7, "every generation": 0} {
		t.Run(name, func(t *testing.T) {
			c, signer := newTestCore(t, reuseConfig("session", 200), serialA)
			startTickClock(c)
			unlockOK(t, c, pinA)

			gate := make(chan struct{})
			signer.setSignGate(gate)
			go func() {
				defer close(gate)
				for range 5000 {
					if pendingWorkspaceOf(c) == workspace {
						break
					}
					time.Sleep(time.Millisecond)
				}
				c.InvalidateWorkspace(workspace, maxGeneration)
			}()

			req := forwardedRequest(t, signer, workspace, 7)
			mintOK(t, c, req)
			signer.setSignGate(nil)

			if size := c.cacheSize(); size != 0 {
				t.Fatalf("a mint invalidated mid-touch kept %d assertions", size)
			}
			before := signer.snapshotCounts().signatures
			mintOK(t, c, req)
			if got := signer.snapshotCounts().signatures - before; got != 1 {
				t.Errorf("the next mint spent %d signatures, want its own touch", got)
			}
		})
	}
}

func TestPurgedEntriesAreZeroized(t *testing.T) {
	c, _ := newTestCore(t, reuseConfig("session", 120), serialA)
	startTickClock(c)
	unlockOK(t, c, pinA)
	result := mintOK(t, c, roRequest())

	_, entry := onlyEntry(t, c)
	held := entry.token
	if len(held) == 0 || string(held) != result.IDToken {
		t.Fatal("the cached entry does not hold the minted assertion")
	}

	c.Lock()

	for i, b := range held {
		if b != 0 {
			t.Fatalf("purged token byte %d is %#x, want the assertion wiped", i, b)
		}
	}
}

func TestNeverModeReuseServesWithoutPIN(t *testing.T) {
	c, signer := newTestCore(t, reuseConfig("never", 120), serialA)
	startTickClock(c)
	unlockOK(t, c, pinA)

	first := mintOK(t, c, roRequest())
	if status := c.Status(); status.PINCached {
		t.Fatal("never mode kept the PIN after minting")
	}

	// The PIN this alias was allowed one mint with is gone, and the request is
	// still inside the window that mint's touch authorised.
	second, err := c.SubjectToken(context.Background(), roRequest())
	if err != nil {
		t.Fatalf("a request inside the window was refused for want of a PIN: %v", err)
	}
	if !second.Reused || second.IDToken != first.IDToken {
		t.Error("the request inside the window was not served from the touch that authorised it")
	}
	counts := signer.snapshotCounts()
	if counts.signatures != 1 || counts.verifies != 1 {
		t.Errorf("card work = %+v, want the single unlock and the single signature", counts)
	}
	// Outside every window the daemon is locked again, exactly as never mode
	// says: the reuse window widens nothing beyond the tuple it was opened for.
	if _, lockedErr := c.SubjectToken(context.Background(), deployRequest()); !errors.Is(lockedErr, ErrLocked) {
		t.Errorf("a request outside every window returned %v, want ErrLocked", lockedErr)
	}
}

func TestNotifierSweepFiresPreAndExpiryOnce(t *testing.T) {
	c, _ := newTestCore(t, reuseConfig("session", 200), serialA)
	start := time.Unix(testNowUnix, 0).UTC()

	windowed := &cacheEntry{
		key:          reuseKey{alias: "ro"},
		token:        []byte("assertion"),
		completedAt:  start,
		expiresAt:    start.Add(270 * time.Second),
		windowEndsAt: start.Add(200 * time.Second),
	}
	coalescedOnly := &cacheEntry{
		key:          reuseKey{alias: "deploy"},
		token:        []byte("other"),
		completedAt:  start,
		expiresAt:    start.Add(270 * time.Second),
		windowEndsAt: start,
	}
	c.cache = map[reuseKey]*cacheEntry{windowed.key: windowed, coalescedOnly.key: coalescedOnly}
	held := windowed.token

	// Nothing is due yet, and the next thing that has to happen is the reader
	// poll.
	messages, next := c.notifierSweep(start.Add(time.Second))
	if len(messages) != 0 {
		t.Fatalf("a fresh window announced %q", messages)
	}
	if want := start.Add(time.Second + readerPollInterval); !next.Equal(want) {
		t.Errorf("next deadline = %s, want the reader poll at %s", next, want)
	}

	// One lead before the window closes, and once only.
	messages, next = c.notifierSweep(start.Add(140 * time.Second))
	if len(messages) != 1 || messages[0] != "window for ro expires in 60s" {
		t.Fatalf("pre-expiry messages = %q", messages)
	}
	if want := start.Add(140*time.Second + readerPollInterval); !next.Equal(want) {
		t.Errorf("next deadline = %s, want %s", next, want)
	}
	if repeated, _ := c.notifierSweep(start.Add(150 * time.Second)); len(repeated) != 0 {
		t.Errorf("the same window announced itself again: %q", repeated)
	}

	// The window closes: one notice, and the assertion is gone and wiped. The
	// entry that only ever coalesced says nothing and stays.
	messages, _ = c.notifierSweep(start.Add(200 * time.Second))
	if len(messages) != 1 || messages[0] != "window for ro expired; next mint needs a touch" {
		t.Fatalf("expiry messages = %q", messages)
	}
	if size := c.cacheSize(); size != 1 {
		t.Errorf("cache holds %d assertions after the window closed, want only the coalescing entry", size)
	}
	for i, b := range held {
		if b != 0 {
			t.Fatalf("expired token byte %d is %#x, want the assertion wiped", i, b)
		}
	}

	// The coalescing entry leaves silently when its assertion dies, and an
	// empty cache stops asking to be woken.
	messages, next = c.notifierSweep(start.Add(270 * time.Second))
	if len(messages) != 0 {
		t.Errorf("a coalescing entry announced its expiry: %q", messages)
	}
	if size := c.cacheSize(); size != 0 {
		t.Errorf("cache holds %d assertions after everything expired", size)
	}
	if !next.IsZero() {
		t.Errorf("an empty cache asked to be woken at %s", next)
	}
}

// TestNotifierSweepSkipsPreNoticeForShortWindows keeps a window no longer than
// the lead from announcing its own opening.
func TestNotifierSweepSkipsPreNoticeForShortWindows(t *testing.T) {
	c, _ := newTestCore(t, reuseConfig("session", 30), serialA)
	start := time.Unix(testNowUnix, 0).UTC()
	entry := &cacheEntry{
		key:          reuseKey{alias: "ro"},
		token:        []byte("assertion"),
		completedAt:  start,
		expiresAt:    start.Add(270 * time.Second),
		windowEndsAt: start.Add(30 * time.Second),
	}
	c.cache = map[reuseKey]*cacheEntry{entry.key: entry}

	if messages, _ := c.notifierSweep(start.Add(time.Second)); len(messages) != 0 {
		t.Errorf("a 30 second window announced itself immediately: %q", messages)
	}
	messages, _ := c.notifierSweep(start.Add(30 * time.Second))
	if len(messages) != 1 || messages[0] != "window for ro expired; next mint needs a touch" {
		t.Errorf("messages at the close of a short window = %q", messages)
	}
}

func TestRunNotifierDeliversAndStops(t *testing.T) {
	c, _ := newTestCore(t, reuseConfig("session", 200), serialA)
	now := time.Unix(testNowUnix, 0).UTC()
	c.SetNowForTest(func() time.Time { return now })
	delivered := make(chan string, 4)
	c.SetNotify(func(message string) { delivered <- message })

	entry := &cacheEntry{
		key:          reuseKey{alias: "ro"},
		token:        []byte("assertion"),
		completedAt:  now.Add(-300 * time.Second),
		expiresAt:    now.Add(60 * time.Second),
		windowEndsAt: now.Add(-100 * time.Second),
	}
	c.cache = map[reuseKey]*cacheEntry{entry.key: entry}

	ctx, cancel := context.WithCancel(context.Background())
	stopped := make(chan struct{})
	go func() {
		c.RunNotifier(ctx)
		close(stopped)
	}()

	select {
	case message := <-delivered:
		if message != "window for ro expired; next mint needs a touch" {
			t.Errorf("delivered %q", message)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the notifier delivered nothing for a window that had already closed")
	}
	cancel()
	select {
	case <-stopped:
	case <-time.After(5 * time.Second):
		t.Fatal("the notifier did not stop with its context")
	}
}

func TestStatusReportsReuseWindows(t *testing.T) {
	session := strings.Repeat("a", agentsource.SessionIDLength)
	c, _ := newTestCore(t, reuseConfig("session", 120), serialA)
	clock := startTickClock(c)
	unlockOK(t, c, pinA)

	first := mintOK(t, c, agentRequest(roRequest(), "codex:proj/ro", session))
	clock.advance(10 * time.Second)
	mintOK(t, c, deployRequest())

	windows := c.Status().ReuseWindows
	if len(windows) != 2 {
		t.Fatalf("status reports %d windows, want 2: %+v", len(windows), windows)
	}
	if windows[0].Alias != "ro" || windows[1].Alias != "deploy" {
		t.Errorf("windows are not ordered by the one closing first: %+v", windows)
	}
	if windows[0].SessionID != session {
		t.Errorf("window session = %q, want %q", windows[0].SessionID, session)
	}
	if windows[1].SessionID != "" {
		t.Errorf("a local-wif window reported session %q", windows[1].SessionID)
	}
	if windows[0].Serial != serialA {
		t.Errorf("window serial = %d, want %d", windows[0].Serial, serialA)
	}
	if !windows[0].TokenExpiresAt.Equal(first.ExpiresAt) {
		t.Errorf("window token expiry = %s, want %s", windows[0].TokenExpiresAt, first.ExpiresAt)
	}
	if !windows[0].WindowEndsAt.Before(windows[0].TokenExpiresAt) {
		t.Errorf("window outlives the assertion it reuses: ends %s, expires %s", windows[0].WindowEndsAt, windows[0].TokenExpiresAt)
	}

	// A daemon that only coalesces has nothing to report: no window was opened.
	plain, _ := newTestCore(t, testConfig("session"), serialA)
	startTickClock(plain)
	unlockOK(t, plain, pinA)
	mintOK(t, plain, roRequest())
	if windows := plain.Status().ReuseWindows; windows != nil {
		t.Errorf("a coalescing-only daemon reported windows: %+v", windows)
	}
}

func TestReusedMintRecordsNoSignature(t *testing.T) {
	c, signer := newTestCore(t, reuseConfig("session", 120), serialA)
	startTickClock(c)
	unlockOK(t, c, pinA)

	mintOK(t, c, roRequest())
	for range 3 {
		if result := mintOK(t, c, roRequest()); !result.Reused {
			t.Fatal("a request inside the window bought its own touch")
		}
	}

	counters := c.Status().Mints
	if counters == nil {
		t.Fatal("status reports no mint counters")
	}
	if counters.Total60m != 4 {
		t.Errorf("Total60m = %d, want every credential counted", counters.Total60m)
	}
	if counters.Signatures60m != 1 {
		t.Errorf("Signatures60m = %d, want the one touch that was spent", counters.Signatures60m)
	}
	if got := signer.snapshotCounts().signatures; got != 1 {
		t.Errorf("the card signed %d times, want 1", got)
	}
}

func TestReuseWindowIsNamedOnTheTouchPrompt(t *testing.T) {
	c, signer := newTestCore(t, reuseConfig("session", 210), serialA)
	startTickClock(c)
	unlockOK(t, c, pinA)
	mintOK(t, c, roRequest())

	labels := signer.snapshotLabels()
	if len(labels) != 1 {
		t.Fatalf("touch prompts = %q, want one", labels)
	}
	if want := "authorises ro touch-free for 3m30s"; !strings.Contains(labels[0], want) {
		t.Errorf("touch prompt %q does not state what the touch grants (%q)", labels[0], want)
	}

	// Without a window the prompt is exactly what it was.
	plain, plainSigner := newTestCore(t, testConfig("session"), serialA)
	startTickClock(plain)
	unlockOK(t, plain, pinA)
	mintOK(t, plain, roRequest())
	if got := plainSigner.snapshotLabels()[0]; got != "ro → "+roTarget+" (local-wif)" {
		t.Errorf("touch prompt without a window = %q", got)
	}
}

// TestReuseCacheIsBounded pins the eviction rule: the cache never grows past
// its cap, and what leaves is the assertion authorised longest ago.
func TestReuseCacheIsBounded(t *testing.T) {
	c, _ := newTestCore(t, reuseConfig("session", 120), serialA)
	start := time.Unix(testNowUnix, 0).UTC()
	oldest := reuseKey{alias: "oldest"}

	c.mu.Lock()
	for i := range reuseCacheCap + 1 {
		key := oldest
		if i != 0 {
			key = reuseKey{alias: "alias", sessionID: strconv.Itoa(i)}
		}
		c.insertLocked(&cacheEntry{key: key, token: []byte("assertion"), completedAt: start.Add(time.Duration(i) * time.Second)})
	}
	held := len(c.cache)
	_, keptOldest := c.cache[oldest]
	c.mu.Unlock()

	if held != reuseCacheCap {
		t.Errorf("cache holds %d assertions, want the cap of %d", held, reuseCacheCap)
	}
	if keptOldest {
		t.Error("eviction kept the assertion authorised longest ago")
	}
}

// TestReuseNeverReachesTheRoutedBranch keeps the origin side out of the cache:
// a route-required request is forwarded every time, whatever it looks like.
func TestReuseNeverReachesTheRoutedBranch(t *testing.T) {
	fixture := loadFixture(t, "a")
	now := time.Unix(testNowUnix, 0).UTC()
	card := forwardapi.CardIdentity{Serial: serialA, KeyID: kidA, SPKIDER: append([]byte(nil), fixture.cert.RawSubjectPublicKeyInfo...)}
	claims, err := wif.NewClaims(testConfig("session").Provider(), "ro", roTarget, serialA, kidA, testJTI, now)
	if err != nil {
		t.Fatal(err)
	}
	input, err := wif.SigningInput(claims)
	if err != nil {
		t.Fatal(err)
	}
	signature, err := rsa.SignPKCS1v15(rand.Reader, fixture.key, crypto.SHA256, wif.SigningDigest(input))
	if err != nil {
		t.Fatal(err)
	}
	token, err := wif.Assemble(input, signature)
	if err != nil {
		t.Fatal(err)
	}
	socket := serveForwardResponse(t, forwardapi.MintResponse{
		Version: forwardapi.ProtocolVersion, IDToken: token, ExpirationTime: claims.Exp,
		Card: card, ExpectedCard: card,
		ForwardContext: forwardapi.ForwardContext{
			OriginNodeID: strings.Repeat("a", 32), WorkspaceID: strings.Repeat("b", 32), Bundle: "work",
			ClaimGeneration: 7, ProviderNodeID: strings.Repeat("c", 32), OperationID: strings.Repeat("d", 32),
		},
	})

	c, _ := newTestCore(t, reuseConfig("session", 120), serialA)
	c.SetNowForTest(func() time.Time { return now })
	req := roRequest()
	req.Attachment = attachment.RouteRequired(attachment.ProtocolEnvironment, socket)

	for i := range 3 {
		result, mintErr := c.SubjectToken(context.Background(), req)
		if mintErr != nil {
			t.Fatalf("routed SubjectToken %d: %v", i, mintErr)
		}
		if result.Reused {
			t.Fatal("an origin served a forwarded mint from its own cache")
		}
	}
	if size := c.cacheSize(); size != 0 {
		t.Errorf("the origin cached %d forwarded assertions, want none", size)
	}
	if windows := c.Status().ReuseWindows; windows != nil {
		t.Errorf("the origin reported windows for forwarded mints: %+v", windows)
	}
}

// TestSignerWithoutReaderEnumerationStillReuses keeps the presence probe
// optional: a signer that cannot enumerate readers disables it rather than
// failing it.
func TestSignerWithoutReaderEnumerationStillReuses(t *testing.T) {
	base := &fakeSigner{
		current: serialA,
		cards:   map[uint32]fixtureKey{serialA: loadFixture(t, "a"), serialB: loadFixture(t, "b")},
		pins:    map[uint32]string{serialA: pinA, serialB: pinA},
		retries: map[uint32]int{serialA: 3, serialB: 3},
	}
	c := New(reuseConfig("session", 120), blindSigner{base}, testVersion)
	startTickClock(c)
	unlockOK(t, c, pinA)

	mintOK(t, c, roRequest())
	if result := mintOK(t, c, roRequest()); !result.Reused {
		t.Error("a signer that cannot enumerate readers was refused its own window")
	}
	if got := base.snapshotCounts().signatures; got != 1 {
		t.Errorf("signatures = %d, want 1", got)
	}
}

// blindSigner hides fakeSigner's ListReaderNames without hiding anything else.
type blindSigner struct{ inner pivsigner.Signer }

func (s blindSigner) VerifyPIN(ctx context.Context, pin string) (uint32, int, error) {
	return s.inner.VerifyPIN(ctx, pin)
}

func (s blindSigner) Sign(ctx context.Context, label, pin string, digestFor func(uint32, *x509.Certificate) ([]byte, error)) ([]byte, uint32, error) {
	return s.inner.Sign(ctx, label, pin, digestFor)
}
