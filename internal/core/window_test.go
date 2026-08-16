package core

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/xlfe/pivb/internal/config"
)

// grantConfig is testConfig with a provider grant maximum and a touch-free
// window on every alias: the two independent settings a granted window has to
// be reconciled with.
func grantConfig(maxGrantWindowS, reuseS int) *config.Config {
	cfg := reuseConfig("session", reuseS)
	cfg.MaxGrantWindowS = maxGrantWindowS
	return cfg
}

// windowedRequest is a forwarded mint whose claim asks to be covered for
// seconds, ending at deadline. The claim's own anchor is deadline minus what
// it asked for, and that anchor is what a shorter grant is measured from.
func windowedRequest(t *testing.T, signer *fakeSigner, seconds int64, deadline time.Time) SubjectTokenRequest {
	t.Helper()
	req := forwardedRequest(t, signer, strings.Repeat("b", 32), 7)
	req.ForwardContext.WindowSeconds = seconds
	req.ForwardContext.WindowDeadline = deadline.Unix()
	return req
}

func testStart() time.Time { return time.Unix(testNowUnix, 0).UTC() }

// TestWindowedMintIsRefusedWhenTheProviderGrantsNone pins the default: a card
// whose operator has granted no windows will not quietly serve a claim that
// asked to be covered by one.
func TestWindowedMintIsRefusedWhenTheProviderGrantsNone(t *testing.T) {
	c, signer := newTestCore(t, reuseConfig("session", 120), serialA)
	startTickClock(c)
	unlockOK(t, c, pinA)

	start := testStart()
	_, err := c.SubjectToken(context.Background(), windowedRequest(t, signer, 900, start.Add(900*time.Second)))
	var refused *WindowNotAllowedError
	if !errors.As(err, &refused) {
		t.Fatalf("SubjectToken error = %v, want a WindowNotAllowedError", err)
	}
	if refused.Requested != 900 {
		t.Errorf("the refusal names %d requested seconds, want 900", refused.Requested)
	}
	if got := signer.snapshotCounts().signatures; got != 0 {
		t.Errorf("a refused window still spent %d signatures", got)
	}

	// What is refused is the coverage, not the mint: the same claim without a
	// window is served exactly as it was before this provider knew about them.
	result := mintOK(t, c, forwardedRequest(t, signer, strings.Repeat("b", 32), 7))
	if result.GrantedWindowSeconds != 0 || result.GrantedWindowDeadline != 0 {
		t.Errorf("a windowless mint reported a grant of %ds until %d",
			result.GrantedWindowSeconds, result.GrantedWindowDeadline)
	}
}

// TestGrantedWindowIsClampedToTheProviderMaximum pins the arithmetic of a
// grant: never more than the operator allows, and always ending at the claim's
// own anchor so re-asking near the end cannot lengthen it.
func TestGrantedWindowIsClampedToTheProviderMaximum(t *testing.T) {
	start := testStart()
	for _, tc := range []struct {
		name        string
		requested   int64
		wantGranted int64
	}{
		{"more than the operator grants", 1800, 900},
		{"less than the operator grants", 600, 600},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, signer := newTestCore(t, grantConfig(900, 120), serialA)
			startTickClock(c)
			unlockOK(t, c, pinA)

			// The claim anchored its window at start, so it sent a deadline that
			// far past it.
			deadline := start.Add(time.Duration(tc.requested) * time.Second)
			result := mintOK(t, c, windowedRequest(t, signer, tc.requested, deadline))

			if result.GrantedWindowSeconds != tc.wantGranted {
				t.Errorf("granted %ds, want %ds", result.GrantedWindowSeconds, tc.wantGranted)
			}
			if want := start.Add(time.Duration(tc.wantGranted) * time.Second).Unix(); result.GrantedWindowDeadline != want {
				t.Errorf("granted deadline = %d, want %d: a shorter grant ends earlier from the claim's anchor, not later from the mint",
					result.GrantedWindowDeadline, want)
			}
		})
	}
}

// TestAnExpiredWindowIsWindowlessRatherThanRefused pins what happens when a
// claim's window has already closed: the mint reverts to a touch apiece, which
// is what a mint carrying no window has always been. The provider operator's
// own standing consent — the alias reuse window — is unaffected by a remote
// claim running out.
func TestAnExpiredWindowIsWindowlessRatherThanRefused(t *testing.T) {
	start := testStart()
	// The claim's window closed a minute before this mint arrived.
	closed := start.Add(-60 * time.Second)

	t.Run("the alias reuse window still applies", func(t *testing.T) {
		c, signer := newTestCore(t, grantConfig(900, 120), serialA)
		clock := startTickClock(c)
		unlockOK(t, c, pinA)
		req := windowedRequest(t, signer, 900, closed)

		first := mintOK(t, c, req)
		if first.GrantedWindowSeconds != 0 || first.GrantedWindowDeadline != 0 {
			t.Errorf("a closed window was granted %ds until %d, want nothing",
				first.GrantedWindowSeconds, first.GrantedWindowDeadline)
		}
		clock.advance(60 * time.Second)
		if second := mintOK(t, c, req); !second.Reused {
			t.Error("a closed remote window disabled the provider's own reuse policy")
		}
		if got := signer.snapshotCounts().signatures; got != 1 {
			t.Errorf("signatures = %d, want the one touch the alias window covers", got)
		}
	})

	t.Run("without one every mint still costs a touch", func(t *testing.T) {
		c, signer := newTestCore(t, grantConfig(900, 0), serialA)
		clock := startTickClock(c)
		unlockOK(t, c, pinA)
		req := windowedRequest(t, signer, 900, closed)

		for i := range 2 {
			if result := mintOK(t, c, req); result.Reused {
				t.Fatalf("mint %d was served touch-free by an alias that configures no reuse", i)
			}
			clock.advance(5 * time.Second)
		}
		if got := signer.snapshotCounts().signatures; got != 2 {
			t.Errorf("signatures = %d, want one per mint", got)
		}
	})
}

// TestAGrantedWindowCapsTouchFreeReuse is the point of the whole feature: the
// grant bounds how long one touch keeps answering, even when the alias would
// have gone on answering for longer.
func TestAGrantedWindowCapsTouchFreeReuse(t *testing.T) {
	start := testStart()
	c, signer := newTestCore(t, grantConfig(50, 120), serialA)
	clock := startTickClock(c)
	unlockOK(t, c, pinA)

	// The alias would reuse one touch for 120 seconds; this claim's window has
	// only 50 seconds left to give.
	req := windowedRequest(t, signer, 600, start.Add(600*time.Second))
	first := mintOK(t, c, req)
	if first.GrantedWindowSeconds != 50 {
		t.Fatalf("granted %ds, want the provider maximum of 50", first.GrantedWindowSeconds)
	}
	deadline := time.Unix(first.GrantedWindowDeadline, 0).UTC()

	_, entry := onlyEntry(t, c)
	if !entry.windowEndsAt.Equal(deadline) {
		t.Errorf("the entry stops serving at %s, want the granted deadline %s", entry.windowEndsAt, deadline)
	}
	if uncapped := entry.completedAt.Add(120 * time.Second); !deadline.Before(uncapped) {
		t.Fatalf("this test caps nothing: the grant ends %s and the alias window %s", deadline, uncapped)
	}
	if remaining := entry.expiresAt.Sub(deadline); remaining < reuseValidityFloor {
		t.Fatalf("the assertion has only %s left at the deadline, so the floor would refuse it anyway", remaining)
	}

	// Inside the grant, and well inside the alias window, the touch is not
	// spent again.
	clock.setTo(deadline.Add(-10 * time.Second))
	if second := mintOK(t, c, req); !second.Reused {
		t.Error("a request inside the granted window spent a second touch")
	}

	// Past it, with the alias window and the assertion both still good, the
	// next mint is a fresh touch and carries no grant at all.
	clock.setTo(deadline)
	third := mintOK(t, c, req)
	if third.Reused {
		t.Error("a request past the granted deadline was served touch-free")
	}
	if third.GrantedWindowSeconds != 0 || third.GrantedWindowDeadline != 0 {
		t.Errorf("a mint past the deadline reported a grant of %ds until %d",
			third.GrantedWindowSeconds, third.GrantedWindowDeadline)
	}
	if got := signer.snapshotCounts().signatures; got != 2 {
		t.Errorf("signatures = %d, want the one inside the window and the one after it", got)
	}
}

// TestAGrantedWindowNeverCreatesReuse keeps the two settings one-directional: a
// remote claim can shorten what one touch covers, never buy touch-free minting
// the card's own operator did not configure.
func TestAGrantedWindowNeverCreatesReuse(t *testing.T) {
	start := testStart()
	c, signer := newTestCore(t, grantConfig(900, 0), serialA)
	clock := startTickClock(c)
	unlockOK(t, c, pinA)
	req := windowedRequest(t, signer, 900, start.Add(900*time.Second))

	for i := range 3 {
		result := mintOK(t, c, req)
		if result.Reused {
			t.Fatalf("mint %d inside a 900 second grant was served without a touch", i)
		}
		if result.GrantedWindowSeconds != 900 {
			t.Errorf("mint %d was granted %ds, want the full 900 it asked for", i, result.GrantedWindowSeconds)
		}
		clock.advance(5 * time.Second)
	}
	if got := signer.snapshotCounts().signatures; got != 3 {
		t.Errorf("signatures = %d, want one per mint", got)
	}
	// The entries exist only to coalesce, so the operator is shown no window.
	if windows := c.Status().ReuseWindows; windows != nil {
		t.Errorf("an alias configuring no reuse reported windows: %+v", windows)
	}
}

// TestACacheHitReportsTheSameGrant keeps the answer to "how long am I covered
// for" the same whether or not the assertion had to be signed. The grant is
// recomputed from the request every time, so no per-claim state is kept.
func TestACacheHitReportsTheSameGrant(t *testing.T) {
	start := testStart()
	c, signer := newTestCore(t, grantConfig(900, 120), serialA)
	clock := startTickClock(c)
	unlockOK(t, c, pinA)
	req := windowedRequest(t, signer, 600, start.Add(600*time.Second))

	first := mintOK(t, c, req)
	clock.advance(30 * time.Second)
	second := mintOK(t, c, req)

	if !second.Reused {
		t.Fatal("a request inside both windows spent a second touch")
	}
	if first.GrantedWindowSeconds != 600 {
		t.Errorf("the mint was granted %ds, want the 600 it asked for", first.GrantedWindowSeconds)
	}
	if second.GrantedWindowSeconds != first.GrantedWindowSeconds || second.GrantedWindowDeadline != first.GrantedWindowDeadline {
		t.Errorf("the hit reported %ds until %d, want the mint's %ds until %d",
			second.GrantedWindowSeconds, second.GrantedWindowDeadline,
			first.GrantedWindowSeconds, first.GrantedWindowDeadline)
	}
}

// TestWindowlessForwardedMintsAreUnaffected keeps a claim that asks for no
// window exactly where it was: the alias reuse window is its own bound and
// nothing about grants touches it.
func TestWindowlessForwardedMintsAreUnaffected(t *testing.T) {
	c, signer := newTestCore(t, grantConfig(900, 120), serialA)
	clock := startTickClock(c)
	unlockOK(t, c, pinA)
	req := forwardedRequest(t, signer, strings.Repeat("b", 32), 7)

	first := mintOK(t, c, req)
	clock.advance(60 * time.Second)
	second := mintOK(t, c, req)

	if !second.Reused {
		t.Error("a windowless forwarded request inside the alias window spent a second touch")
	}
	for i, result := range []SubjectTokenResult{first, second} {
		if result.GrantedWindowSeconds != 0 || result.GrantedWindowDeadline != 0 {
			t.Errorf("result %d reported a grant of %ds until %d, want none",
				i, result.GrantedWindowSeconds, result.GrantedWindowDeadline)
		}
	}
	_, entry := onlyEntry(t, c)
	if want := entry.completedAt.Add(120 * time.Second); !entry.windowEndsAt.Equal(want) {
		t.Errorf("the entry stops serving at %s, want the alias's own %s", entry.windowEndsAt, want)
	}
}

// TestTheNotifierAnnouncesTheGrantedDeadline checks that what the operator is
// shown and told is the grant's end rather than the alias window's, without
// the notifier knowing anything about grants.
func TestTheNotifierAnnouncesTheGrantedDeadline(t *testing.T) {
	start := testStart()
	c, signer := newTestCore(t, grantConfig(120, 200), serialA)
	startTickClock(c)
	unlockOK(t, c, pinA)

	// The alias would keep this touch for 200 seconds; the claim's window ends
	// after 120.
	result := mintOK(t, c, windowedRequest(t, signer, 600, start.Add(600*time.Second)))
	deadline := time.Unix(result.GrantedWindowDeadline, 0).UTC()
	if want := start.Add(120 * time.Second); !deadline.Equal(want) {
		t.Fatalf("granted deadline = %s, want %s", deadline, want)
	}

	windows := c.Status().ReuseWindows
	if len(windows) != 1 || !windows[0].WindowEndsAt.Equal(deadline) {
		t.Fatalf("status reports %+v, want one window ending at the granted deadline %s", windows, deadline)
	}

	if messages, _ := c.notifierSweep(deadline.Add(-reuseNotifyLead - time.Second)); len(messages) != 0 {
		t.Fatalf("the notifier announced the closing early: %q", messages)
	}
	messages, _ := c.notifierSweep(deadline.Add(-reuseNotifyLead))
	if len(messages) != 1 || messages[0] != "window for ro expires in 60s" {
		t.Fatalf("pre-expiry messages = %q", messages)
	}
	messages, _ = c.notifierSweep(deadline)
	if len(messages) != 1 || messages[0] != "window for ro expired; next mint needs a touch" {
		t.Fatalf("expiry messages = %q", messages)
	}
	if size := c.cacheSize(); size != 0 {
		t.Errorf("%d assertions outlived the granted window", size)
	}
}

// TestForwardDiscoveryAdvertisesTheGrantWindowMaximum lets an origin see what
// it can expect before it claims anything, from either half of discovery.
func TestForwardDiscoveryAdvertisesTheGrantWindowMaximum(t *testing.T) {
	c, _ := newTestCore(t, grantConfig(900, 0), serialA)
	description, err := c.DescribeForwardProvider(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if description.MaxGrantWindowS != 900 {
		t.Errorf("description advertises max_grant_window_s = %d, want 900", description.MaxGrantWindowS)
	}
	if got := c.ForwardPolicy().MaxGrantWindowS; got != 900 {
		t.Errorf("policy advertises max_grant_window_s = %d, want 900", got)
	}

	// A provider that grants none advertises none, which is what an origin
	// reads to know its claims will be refused rather than clamped.
	silent, _ := newTestCore(t, testConfig("session"), serialA)
	silentDescription, err := silent.DescribeForwardProvider(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if silentDescription.MaxGrantWindowS != 0 || silent.ForwardPolicy().MaxGrantWindowS != 0 {
		t.Errorf("a provider granting no windows advertised %d/%d",
			silentDescription.MaxGrantWindowS, silent.ForwardPolicy().MaxGrantWindowS)
	}
}
