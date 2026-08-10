package pivsigner

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"io"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-piv/piv-go/v2/piv"
)

var sharingErr = errors.New("SCARD_E_SHARING_VIOLATION: 0x8010000b")

type fakeCard struct {
	serial         uint32
	serialErr      error
	cert           *x509.Certificate
	certErr        error
	retries        int
	verifyErr      error
	private        crypto.PrivateKey
	privateErr     error
	closeCount     atomic.Int32
	certificateGet atomic.Int32
}

func (c *fakeCard) Close() error            { c.closeCount.Add(1); return nil }
func (c *fakeCard) Serial() (uint32, error) { return c.serial, c.serialErr }
func (c *fakeCard) Certificate(piv.Slot) (*x509.Certificate, error) {
	c.certificateGet.Add(1)
	return c.cert, c.certErr
}
func (c *fakeCard) Retries() (int, error)  { return c.retries, nil }
func (c *fakeCard) VerifyPIN(string) error { return c.verifyErr }
func (c *fakeCard) PrivateKey(piv.Slot, crypto.PublicKey, piv.KeyAuth) (crypto.PrivateKey, error) {
	return c.private, c.privateErr
}

type fakeCryptoSigner struct {
	public *rsa.PublicKey
	err    error
	delay  time.Duration
	calls  atomic.Int32
}

func (s *fakeCryptoSigner) Public() crypto.PublicKey { return s.public }
func (s *fakeCryptoSigner) Sign(io.Reader, []byte, crypto.SignerOpts) ([]byte, error) {
	s.calls.Add(1)
	if s.delay > 0 {
		time.Sleep(s.delay)
	}
	return []byte("signature"), s.err
}

func testCertificate(t *testing.T) (*x509.Certificate, *rsa.PrivateKey) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return &x509.Certificate{PublicKey: &key.PublicKey}, key
}

func TestOpenSelectedSkipsBusyForeignReader(t *testing.T) {
	configured := &fakeCard{serial: 22}
	var handoffs atomic.Int32
	h := &Hardware{
		Serials:     []uint32{22},
		listReaders: func() ([]string, error) { return []string{"gpg-key", "pivb-key"}, nil },
		openReader: func(reader string) (card, error) {
			if reader == "gpg-key" {
				return nil, sharingErr
			}
			return configured, nil
		},
		handoff: func(context.Context) error { handoffs.Add(1); return nil },
	}
	yk, serial, err := h.openSelectedRaw()
	if err != nil {
		t.Fatal(err)
	}
	if serial != 22 {
		t.Fatalf("serial = %d, want 22", serial)
	}
	_ = yk.Close()
	if handoffs.Load() != 0 {
		t.Fatal("contention on a non-configured reader armed recovery")
	}
}

func TestOpenSelectedReportsAllFailuresOnlyWhenNoConfiguredCardFound(t *testing.T) {
	h := &Hardware{
		Serials:     []uint32{22},
		listReaders: func() ([]string, error) { return []string{"busy", "broken"}, nil },
		openReader: func(reader string) (card, error) {
			if reader == "busy" {
				return nil, sharingErr
			}
			return nil, errors.New("reader disappeared")
		},
	}
	_, _, err := h.openSelectedRaw()
	var selection *SelectionError
	if !errors.As(err, &selection) || len(selection.Failures) != 2 {
		t.Fatalf("error = %#v, want SelectionError with both reader failures", err)
	}
	if !IsSharingViolation(err) {
		t.Fatalf("aggregated selection error lost sharing cause: %v", err)
	}
}

func TestRecoveryPollsBeforeHandoff(t *testing.T) {
	var opens atomic.Int32
	var handoffs atomic.Int32
	h := shortRecoveryHardware(func(string) (card, error) {
		if opens.Add(1) < 3 {
			return nil, sharingErr
		}
		return &fakeCard{serial: 22}, nil
	})
	h.recoveryGrace = 80 * time.Millisecond
	h.recoveryLimit = 200 * time.Millisecond
	h.handoff = func(context.Context) error { handoffs.Add(1); return nil }
	ctx, cancel := context.WithTimeout(context.Background(), 900*time.Millisecond)
	defer cancel()
	yk, _, err := h.acquireCard(ctx, operationInfo{Origin: OriginForwarded, ID: "op"}, h.newRecoveryBudget())
	if err != nil {
		t.Fatal(err)
	}
	_ = yk.Close()
	if handoffs.Load() != 0 {
		t.Fatalf("handoffs = %d, transient contention should clear during grace polling", handoffs.Load())
	}
}

func TestDescribeAndVerifyPINUseRecoveryAcquisition(t *testing.T) {
	cert, _ := testCertificate(t)
	for _, name := range []string{"describe", "verify PIN"} {
		t.Run(name, func(t *testing.T) {
			var opens atomic.Int32
			h := shortRecoveryHardware(func(string) (card, error) {
				if opens.Add(1) == 1 {
					return nil, sharingErr
				}
				return &fakeCard{serial: 22, cert: cert, retries: 3}, nil
			})
			h.recoveryGrace = 80 * time.Millisecond
			h.recoveryLimit = 200 * time.Millisecond
			ctx, cancel := context.WithTimeout(context.Background(), 900*time.Millisecond)
			defer cancel()
			// Carry the bounded context through the public method under test.
			var err error
			if name == "describe" {
				_, _, err = h.Describe(ctx)
			} else {
				_, _, err = h.VerifyPIN(ctx, "123456")
			}
			if err != nil {
				t.Fatal(err)
			}
			if opens.Load() < 2 {
				t.Fatalf("opens = %d, public path did not recover acquisition", opens.Load())
			}
		})
	}
}

func TestRecoveryHandsOffOnlyAfterRunningScdaemonIsMeasured(t *testing.T) {
	var released atomic.Bool
	var handoffs atomic.Int32
	h := shortRecoveryHardware(func(string) (card, error) {
		if !released.Load() {
			return nil, sharingErr
		}
		return &fakeCard{serial: 22}, nil
	})
	h.inspectSCD = func(context.Context) (scdaemonState, error) { return scdaemonRunning, nil }
	h.handoff = func(context.Context) error {
		handoffs.Add(1)
		released.Store(true)
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 900*time.Millisecond)
	defer cancel()
	yk, _, err := h.acquireCard(ctx, operationInfo{Origin: OriginForwarded, ID: "op"}, h.newRecoveryBudget())
	if err != nil {
		t.Fatal(err)
	}
	_ = yk.Close()
	if handoffs.Load() != 1 {
		t.Fatalf("handoffs = %d, want exactly one", handoffs.Load())
	}
}

func TestRecoveryPollsForDelayedReleaseAfterSuccessfulHandoff(t *testing.T) {
	var opens atomic.Int32
	var handedOff atomic.Bool
	var handoffs atomic.Int32
	h := shortRecoveryHardware(func(string) (card, error) {
		attempt := opens.Add(1)
		if handedOff.Load() && attempt >= 4 {
			return &fakeCard{serial: 22}, nil
		}
		return nil, sharingErr
	})
	h.recoveryLimit = 300 * time.Millisecond
	h.handoff = func(context.Context) error {
		handoffs.Add(1)
		handedOff.Store(true)
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 900*time.Millisecond)
	defer cancel()
	yk, _, err := h.acquireCard(ctx, operationInfo{Origin: OriginForwarded, ID: "delayed"}, h.newRecoveryBudget())
	if err != nil {
		t.Fatal(err)
	}
	_ = yk.Close()
	if handoffs.Load() != 1 || opens.Load() < 4 {
		t.Fatalf("handoffs/opens = %d/%d, want one hand-off and delayed post-hand-off polling", handoffs.Load(), opens.Load())
	}
}

func TestHandoffFailureIsNonFatalAndPreservesInitialCause(t *testing.T) {
	var opens atomic.Int32
	h := shortRecoveryHardware(func(string) (card, error) {
		if opens.Add(1) >= 3 {
			return &fakeCard{serial: 22}, nil
		}
		return nil, sharingErr
	})
	h.handoff = func(context.Context) error { return errors.New("gpgconf unavailable") }
	ctx, cancel := context.WithTimeout(context.Background(), 900*time.Millisecond)
	defer cancel()
	yk, _, err := h.acquireCard(ctx, operationInfo{Origin: OriginForwarded, ID: "nonfatal"}, h.newRecoveryBudget())
	if err != nil {
		t.Fatalf("polling did not recover after non-fatal handoff failure: %v", err)
	}
	_ = yk.Close()

	persistent := shortRecoveryHardware(func(string) (card, error) { return nil, sharingErr })
	persistent.handoff = func(context.Context) error { return errors.New("gpgconf unavailable") }
	ctx2, cancel2 := context.WithTimeout(context.Background(), 900*time.Millisecond)
	defer cancel2()
	_, _, err = persistent.acquireCard(ctx2, operationInfo{Origin: OriginForwarded, ID: "persistent"}, persistent.newRecoveryBudget())
	var contention *ContentionError
	if !errors.As(err, &contention) || !errors.Is(err, sharingErr) {
		t.Fatalf("persistent error = %T %v, want typed contention retaining initial sharing cause", err, err)
	}
	if contention.HandoffError == nil || !contention.HandoffAttempted {
		t.Fatalf("contention = %+v, want separate non-fatal handoff failure", contention)
	}
}

func TestDiagnosticRescanIsBoundedAndProcessSingle(t *testing.T) {
	blocked := make(chan struct{})
	var opens atomic.Int32
	h := &Hardware{
		Serials:     []uint32{22},
		listReaders: func() ([]string, error) { return []string{"reader"}, nil },
		openReader: func(string) (card, error) {
			opens.Add(1)
			<-blocked
			return nil, sharingErr
		},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	started := time.Now()
	h.diagnosticRescan(ctx, operationInfo{Origin: OriginForwarded, ID: "first"})
	if elapsed := time.Since(started); elapsed > 500*time.Millisecond {
		t.Fatalf("diagnostic scan took %s, want 250ms cap", elapsed)
	}
	if !h.diagnosticWorker.Load() {
		t.Fatal("blocked diagnostic worker was not retained as process-global in-flight state")
	}
	secondStarted := time.Now()
	h.diagnosticRescan(ctx, operationInfo{Origin: OriginForwarded, ID: "second"})
	if elapsed := time.Since(secondStarted); elapsed > 50*time.Millisecond {
		t.Fatalf("second diagnostic waited %s instead of log-and-skip", elapsed)
	}
	if opens.Load() != 1 || h.hasSelfHolder() {
		t.Fatalf("diagnostic opens/self-holder = %d/%v, want one blocked waiter and no holder", opens.Load(), h.hasSelfHolder())
	}
	close(blocked)
	deadline := time.Now().Add(time.Second)
	for h.diagnosticWorker.Load() && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if h.diagnosticWorker.Load() {
		t.Fatal("diagnostic worker did not clear after blocked open returned")
	}
}

func TestSelfHolderSuppressionIsStickyButFinalClassificationUsesLastState(t *testing.T) {
	h := shortRecoveryHardware(func(string) (card, error) { return nil, sharingErr })
	h.openSessions.Add(1)
	var sleeps atomic.Int32
	h.sleep = func(ctx context.Context, delay time.Duration) error {
		if sleeps.Add(1) == 1 {
			h.openSessions.Add(-1)
		}
		timer := time.NewTimer(delay)
		defer timer.Stop()
		select {
		case <-timer.C:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 900*time.Millisecond)
	defer cancel()
	_, _, err := h.acquireCard(ctx, operationInfo{Origin: OriginForwarded, ID: "sticky"}, h.newRecoveryBudget())
	var contention *ContentionError
	if !errors.As(err, &contention) {
		t.Fatalf("error = %T %v, want ContentionError", err, err)
	}
	if !contention.EverSelfHeld || contention.LastSelfHeld || contention.HandoffAttempted {
		t.Fatalf("contention state = %+v, want sticky suppression with final holder=false", contention)
	}
}

func TestRecoveryUnknownFallsBackToOneHandoff(t *testing.T) {
	var released atomic.Bool
	var handoffs atomic.Int32
	h := shortRecoveryHardware(func(string) (card, error) {
		if released.Load() {
			return &fakeCard{serial: 22}, nil
		}
		return nil, sharingErr
	})
	h.inspectSCD = func(context.Context) (scdaemonState, error) {
		return scdaemonUnknown, errors.New("inspection timed out")
	}
	h.handoff = func(context.Context) error { handoffs.Add(1); released.Store(true); return nil }
	ctx, cancel := context.WithTimeout(context.Background(), 900*time.Millisecond)
	defer cancel()
	yk, _, err := h.acquireCard(ctx, operationInfo{Origin: OriginAgentSession, ID: "session"}, h.newRecoveryBudget())
	if err != nil {
		t.Fatal(err)
	}
	_ = yk.Close()
	if handoffs.Load() != 1 {
		t.Fatalf("unknown scdaemon state made %d handoffs, want current-semantics fallback once", handoffs.Load())
	}
}

func TestRecoveryStoppedScdaemonAndSelfHolderSuppressHandoff(t *testing.T) {
	tests := []struct {
		name       string
		selfHolder bool
		state      scdaemonState
	}{
		{name: "measured stopped", state: scdaemonStopped},
		{name: "successful in-process session", selfHolder: true, state: scdaemonRunning},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var handoffs atomic.Int32
			h := shortRecoveryHardware(func(string) (card, error) { return nil, sharingErr })
			h.inspectSCD = func(context.Context) (scdaemonState, error) { return tc.state, nil }
			h.handoff = func(context.Context) error { handoffs.Add(1); return nil }
			if tc.selfHolder {
				h.openSessions.Add(1)
				defer h.openSessions.Add(-1)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 900*time.Millisecond)
			defer cancel()
			_, _, err := h.acquireCard(ctx, operationInfo{Origin: OriginForwarded, ID: "op"}, h.newRecoveryBudget())
			if err == nil {
				t.Fatal("persistent contention unexpectedly recovered")
			}
			if handoffs.Load() != 0 {
				t.Fatalf("handoffs = %d, want suppression", handoffs.Load())
			}
		})
	}
}

func TestBlockedOpenWorkerDoesNotSuppressHandoff(t *testing.T) {
	var released atomic.Bool
	var handoffs atomic.Int32
	h := shortRecoveryHardware(func(string) (card, error) {
		if released.Load() {
			return &fakeCard{serial: 22}, nil
		}
		return nil, sharingErr
	})
	h.blockedOpenEvents.Add(1)
	h.openWorkers.Add(1) // a waiter, not an opened session
	defer h.openWorkers.Add(-1)
	h.inspectSCD = func(context.Context) (scdaemonState, error) { return scdaemonRunning, nil }
	h.handoff = func(context.Context) error { handoffs.Add(1); released.Store(true); return nil }
	ctx, cancel := context.WithTimeout(context.Background(), 900*time.Millisecond)
	defer cancel()
	yk, _, err := h.acquireCard(ctx, operationInfo{Origin: OriginForwarded, ID: "op"}, h.newRecoveryBudget())
	if err != nil {
		t.Fatal(err)
	}
	_ = yk.Close()
	if handoffs.Load() != 1 {
		t.Fatalf("blocked opener suppressed handoff; calls = %d", handoffs.Load())
	}
}

func TestAutomatedOriginsShareCooldownWhileInteractiveOriginsAreExempt(t *testing.T) {
	h := &Hardware{}
	now := time.Unix(100, 0)
	for _, op := range []operationInfo{{Origin: OriginForwarded}, {Origin: OriginAgentSession}} {
		if allowed, _ := h.reserveHandoff(op, now); !allowed {
			t.Fatalf("first two automated reservations should be allowed: %v", op.Origin)
		}
	}
	if allowed, retry := h.reserveHandoff(operationInfo{Origin: OriginForwarded}, now); allowed || retry != handoffWindow {
		t.Fatalf("third automated reservation = (%v, %s), want denied for 10s", allowed, retry)
	}
	if allowed, retry := h.reserveHandoff(operationInfo{Origin: OriginUnclassified}, now); allowed || retry != handoffWindow {
		t.Fatalf("unclassified reservation = (%v, %s), want safe throttled default", allowed, retry)
	}
	for _, origin := range []OperationOrigin{OriginLocalWIF, OriginUnlock} {
		if allowed, _ := h.reserveHandoff(operationInfo{Origin: origin}, now); !allowed {
			t.Fatalf("interactive/cooperative origin %s was throttled", origin)
		}
	}
}

func TestInspectScdaemonStates(t *testing.T) {
	tests := []struct {
		name string
		out  string
		err  error
		want scdaemonState
	}{
		{name: "running", out: "OK\n", want: scdaemonRunning},
		{name: "no agent", out: "gpg-connect-agent: no gpg-agent running in this session\n", want: scdaemonStopped},
		{name: "live agent no scdaemon", out: "ERR 67108988 False <GPG Agent>\n", want: scdaemonStopped},
		{name: "inspection unavailable", out: "permission denied", err: errors.New("exit 1"), want: scdaemonUnknown},
		{name: "unrecognized successful output", out: "unexpected diagnostic", want: scdaemonUnknown},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h := &Hardware{
				GnuPGHome: "/missing/is-lazy",
				lookPath:  func(name string) (string, error) { return "/usr/bin/" + name, nil },
				command: func(_ context.Context, _ string, args []string, _ string) ([]byte, error) {
					if len(args) == 1 && args[0] == "--version" {
						return []byte("gpg-connect-agent test"), nil
					}
					return []byte(tc.out), tc.err
				},
			}
			got, evidence, _ := h.inspectScdaemon(context.Background())
			if got != tc.want {
				t.Fatalf("state = %s, want %s", got, tc.want)
			}
			if evidence != firstLine(tc.out) {
				t.Fatalf("evidence = %q, want %q", evidence, firstLine(tc.out))
			}
		})
	}
}

func TestRecoveryLogsScdaemonVerdictEvidence(t *testing.T) {
	var logs bytes.Buffer
	h := shortRecoveryHardware(func(string) (card, error) { return nil, sharingErr })
	h.Logger = slog.New(slog.NewTextHandler(&logs, nil))
	h.inspectSCD = func(context.Context) (scdaemonState, error) { return scdaemonStopped, nil }
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_, _, err := h.acquireCard(ctx, operationInfo{Origin: OriginForwarded, ID: "evidence"}, h.newRecoveryBudget())
	if err == nil {
		t.Fatal("persistent contention unexpectedly recovered")
	}
	if !strings.Contains(logs.String(), "scd_running=false scd_response=injected") {
		t.Fatalf("recovery log omitted verdict evidence:\n%s", logs.String())
	}
}

func TestDefaultGnuPGHomeIsLoggedButNotForced(t *testing.T) {
	t.Setenv("GNUPGHOME", "")
	t.Setenv("HOME", "/home/tester")
	var gotArgs []string
	var gotHome string
	h := &Hardware{
		lookPath: func(name string) (string, error) { return "/resolved/" + name, nil },
		command: func(_ context.Context, path string, args []string, home string) ([]byte, error) {
			if len(args) == 1 && args[0] == "--version" {
				return []byte("gpg-connect-agent test"), nil
			}
			if path == "/resolved/gpgconf" {
				return []byte("/run/user/1000/gnupg/S.gpg-agent"), nil
			}
			gotArgs = append([]string(nil), args...)
			gotHome = home
			return []byte("OK\n"), nil
		},
	}
	state, _, err := h.inspectScdaemon(context.Background())
	if err != nil || state != scdaemonRunning {
		t.Fatalf("inspection = %s/%v", state, err)
	}
	if gotHome != "" {
		t.Fatalf("command GNUPGHOME = %q, want inherited GnuPG default", gotHome)
	}
	want := []string{"--no-autostart", "GETINFO scd_running", "/bye"}
	if len(gotArgs) != len(want) {
		t.Fatalf("args = %q, want %q", gotArgs, want)
	}
	for i := range want {
		if gotArgs[i] != want[i] {
			t.Fatalf("args = %q, want %q", gotArgs, want)
		}
	}
}

func TestProbeWorkerSharesLateResultWithNextBoundedWaiter(t *testing.T) {
	releaseOpen := make(chan struct{})
	lateCard := &fakeCard{serial: 22}
	var opens atomic.Int32
	h := &Hardware{
		Serials:     []uint32{22},
		listReaders: func() ([]string, error) { return []string{"reader"}, nil },
		openReader: func(string) (card, error) {
			opens.Add(1)
			<-releaseOpen
			return lateCard, nil
		},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, _, started, err := h.openProbeContext(ctx); err == nil || started != 1 {
		t.Fatal("blocked probe unexpectedly succeeded")
	}
	if !h.hasProbeWorker() {
		t.Fatal("underlying blocked probe was not retained as in-flight")
	}
	type probeResult struct {
		yk      card
		serial  uint32
		started int
		err     error
	}
	result := make(chan probeResult, 1)
	secondCtx, secondCancel := context.WithTimeout(context.Background(), time.Second)
	defer secondCancel()
	go func() {
		yk, serial, started, err := h.openProbeContext(secondCtx)
		result <- probeResult{yk: yk, serial: serial, started: started, err: err}
	}()
	deadline := time.Now().Add(time.Second)
	attached := false
	for time.Now().Before(deadline) {
		h.probeMu.Lock()
		waiters := 0
		if h.probe != nil {
			waiters = h.probe.waiters
		}
		h.probeMu.Unlock()
		if waiters == 1 {
			attached = true
			break
		}
		time.Sleep(time.Millisecond)
	}
	if !attached {
		close(releaseOpen)
		t.Fatal("second bounded waiter did not join the in-flight probe")
	}
	if opens.Load() != 1 {
		t.Fatalf("underlying opens = %d, want one", opens.Load())
	}
	close(releaseOpen)
	got := <-result
	if got.err != nil || got.serial != 22 || got.started != 0 {
		t.Fatalf("shared probe result = card:%v serial:%d started:%v err:%v", got.yk != nil, got.serial, got.started, got.err)
	}
	if !h.hasSelfHolder() {
		t.Fatal("shared result delivered to a live caller was not tracked")
	}
	_ = got.yk.Close()
	if h.hasSelfHolder() {
		t.Fatal("shared probe holder remained registered after close")
	}
}

func TestAbandonedProbeLateOpenClosesWithoutRegisteringHolder(t *testing.T) {
	releaseOpen := make(chan struct{})
	lateCard := &fakeCard{serial: 22}
	h := &Hardware{
		Serials:     []uint32{22},
		listReaders: func() ([]string, error) { return []string{"reader"}, nil },
		openReader: func(string) (card, error) {
			<-releaseOpen
			return lateCard, nil
		},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, _, _, err := h.openProbeContext(ctx); err == nil {
		t.Fatal("blocked probe unexpectedly succeeded")
	}
	close(releaseOpen)
	deadline := time.Now().Add(time.Second)
	for (h.hasProbeWorker() || lateCard.closeCount.Load() == 0) && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if h.hasProbeWorker() || h.hasSelfHolder() {
		t.Fatal("abandoned late probe remained active or registered a holder")
	}
	if lateCard.closeCount.Load() != 1 {
		t.Fatalf("late card closes = %d, want one", lateCard.closeCount.Load())
	}
}

func TestContentionCountsSharedProbeWaitsSeparatelyFromRealOpens(t *testing.T) {
	releaseOpen := make(chan struct{})
	closed := false
	defer func() {
		if !closed {
			close(releaseOpen)
		}
	}()
	var opens atomic.Int32
	h := &Hardware{
		Serials:       []uint32{22},
		recoveryGrace: 5 * time.Millisecond,
		recoveryLimit: 700 * time.Millisecond,
		listReaders:   func() ([]string, error) { return []string{"reader"}, nil },
		openReader: func(string) (card, error) {
			if opens.Add(1) <= 2 {
				return nil, sharingErr // initial selection and diagnostic rescan
			}
			<-releaseOpen
			return nil, sharingErr
		},
		inspectSCD: func(context.Context) (scdaemonState, error) { return scdaemonStopped, nil },
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_, _, err := h.acquireCard(ctx, operationInfo{Origin: OriginForwarded, ID: "shared-waits"}, h.newRecoveryBudget())
	var contention *ContentionError
	if !errors.As(err, &contention) {
		t.Fatalf("error = %T %v, want ContentionError", err, err)
	}
	if contention.Attempts != 2 || contention.ProbeWaits < 2 {
		t.Fatalf("attempt accounting = opens:%d probe_waits:%d, want two real opens and multiple bounded waits", contention.Attempts, contention.ProbeWaits)
	}
	if opens.Load() != 3 {
		t.Fatalf("underlying selection calls = %d, want initial + diagnostic + one shared probe", opens.Load())
	}
	close(releaseOpen)
	closed = true
	deadline := time.Now().Add(time.Second)
	for h.hasProbeWorker() && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if h.hasProbeWorker() {
		t.Fatal("shared probe worker did not clear after the underlying open returned")
	}
}

func TestGnuPGHomePassedAsFlagAndEnvironmentContext(t *testing.T) {
	var gotArgs []string
	var gotHome string
	var sawVersion bool
	var sawAgentSocket bool
	h := &Hardware{
		GnuPGHome: "/custom/gnupg",
		lookPath:  func(name string) (string, error) { return "/resolved/" + name, nil },
		command: func(_ context.Context, _ string, args []string, home string) ([]byte, error) {
			if len(args) == 1 && args[0] == "--version" {
				sawVersion = true
				return []byte("gpgconf 2.4.9"), nil
			}
			for _, arg := range args {
				if arg == "agent-socket" {
					sawAgentSocket = true
					return []byte("/run/user/1000/gnupg/S.gpg-agent"), nil
				}
			}
			gotArgs = append([]string(nil), args...)
			gotHome = home
			return nil, nil
		},
	}
	if err := h.handoffScdaemon(context.Background()); err != nil {
		t.Fatal(err)
	}
	if gotHome != "/custom/gnupg" {
		t.Fatalf("command home = %q", gotHome)
	}
	if !sawVersion || !sawAgentSocket {
		t.Fatalf("synchronous GnuPG diagnostics = version:%v agent-socket:%v, want both", sawVersion, sawAgentSocket)
	}
	want := []string{"--homedir", "/custom/gnupg", "--kill", "scdaemon"}
	if len(gotArgs) != len(want) {
		t.Fatalf("args = %q, want %q", gotArgs, want)
	}
	for i := range want {
		if gotArgs[i] != want[i] {
			t.Fatalf("args = %q, want %q", gotArgs, want)
		}
	}
}

func TestPrimeGnuPGDiagnosticsRunsSynchronouslyOnce(t *testing.T) {
	var commands atomic.Int32
	var orderMu sync.Mutex
	var order []string
	h := &Hardware{
		lookPath: func(name string) (string, error) { return "/resolved/" + name, nil },
		command: func(_ context.Context, path string, args []string, _ string) ([]byte, error) {
			commands.Add(1)
			label := path + " --version"
			for _, arg := range args {
				if arg == "agent-socket" {
					label = "agent-socket"
					orderMu.Lock()
					order = append(order, label)
					orderMu.Unlock()
					return []byte("/run/user/1000/gnupg/S.gpg-agent"), nil
				}
			}
			orderMu.Lock()
			order = append(order, label)
			orderMu.Unlock()
			return []byte("GnuPG 2.4.9"), nil
		},
	}
	h.PrimeGnuPGDiagnostics()
	h.PrimeGnuPGDiagnostics()
	if commands.Load() != 3 {
		t.Fatalf("diagnostic commands = %d, want two versions plus one agent-socket lookup exactly once", commands.Load())
	}
	if len(order) != 3 || order[0] != "agent-socket" {
		t.Fatalf("diagnostic order = %q, want agent-socket evidence first", order)
	}
}

func TestCappedOutputRetainsBoundAndTruncationEvidence(t *testing.T) {
	output := &cappedOutput{limit: maxGnuPGOutput}
	payload := bytes.Repeat([]byte("x"), maxGnuPGOutput+512)
	n, err := output.Write(payload)
	if err != nil || n != len(payload) {
		t.Fatalf("write = %d/%v, want all %d child bytes consumed", n, err, len(payload))
	}
	got := output.bytes()
	if len(got) != maxGnuPGOutput {
		t.Fatalf("captured output length = %d, want %d", len(got), maxGnuPGOutput)
	}
	if !bytes.Contains(got, []byte("output truncated at 4096 bytes")) {
		t.Fatalf("captured output omitted truncation marker: %q", got[len(got)-64:])
	}
}

func TestReplaceEnvironmentOverridesGnuPGHomeWithoutDuplicates(t *testing.T) {
	got := replaceEnvironment([]string{"PATH=/bin", "GNUPGHOME=/old", "GNUPGHOME=/older"}, "GNUPGHOME", "/new")
	want := []string{"PATH=/bin", "GNUPGHOME=/new"}
	if len(got) != len(want) {
		t.Fatalf("environment = %q, want %q", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("environment = %q, want %q", got, want)
		}
	}
}

func TestExhaustedAcquisitionMarkerPrecedesSharingClassifier(t *testing.T) {
	var opens atomic.Int32
	h := &Hardware{
		Serials:       []uint32{22},
		Deadline:      20 * time.Second,
		recoveryLimit: time.Nanosecond,
		listReaders:   func() ([]string, error) { return []string{"reader"}, nil },
		openReader: func(string) (card, error) {
			opens.Add(1)
			return nil, sharingErr
		},
	}
	_, _, err := h.Sign(context.Background(), "test", "123456", func(uint32, *x509.Certificate) ([]byte, error) {
		t.Fatal("digest requested without an acquired card")
		return nil, nil
	})
	if err == nil || !IsSharingViolation(err) {
		t.Fatalf("error = %v, want handled sharing violation", err)
	}
	// One initial open and one diagnostic rescan. A whole-attempt retry would
	// add another initial open despite the handled marker.
	if opens.Load() != 2 {
		t.Fatalf("opens = %d, want 2; exhausted acquisition was retried by the outer classifier", opens.Load())
	}
}

func TestAcquisitionExhaustedBudgetLateViolationStillMakesFreshAttemptAndRebuildsDigest(t *testing.T) {
	cert, key := testCertificate(t)
	firstSigner := &fakeCryptoSigner{public: &key.PublicKey, err: sharingErr}
	secondSigner := &fakeCryptoSigner{public: &key.PublicKey}
	first := &fakeCard{serial: 22, cert: cert, retries: 3, private: firstSigner}
	second := &fakeCard{serial: 22, cert: cert, retries: 3, private: secondSigner}
	var opens atomic.Int32
	var clockMu sync.Mutex
	clockNow := time.Unix(100, 0)
	h := &Hardware{
		Serials:       []uint32{22},
		Deadline:      20 * time.Second,
		recoveryGrace: 80 * time.Millisecond,
		recoveryLimit: 51 * time.Millisecond,
		listReaders:   func() ([]string, error) { return []string{"reader"}, nil },
		openReader: func(string) (card, error) {
			switch opens.Add(1) {
			case 1, 2:
				return nil, sharingErr // initial open and diagnostic rescan
			case 3:
				return first, nil
			default:
				return second, nil
			}
		},
		now: func() time.Time {
			clockMu.Lock()
			defer clockMu.Unlock()
			return clockNow
		},
		sleep: func(_ context.Context, delay time.Duration) error {
			clockMu.Lock()
			clockNow = clockNow.Add(delay)
			clockMu.Unlock()
			return nil
		},
	}
	h.setVerifiedSerial(22)
	var digestRequests atomic.Int32
	sig, serial, err := h.Sign(context.Background(), "test", "123456", func(uint32, *x509.Certificate) ([]byte, error) {
		digestRequests.Add(1)
		return make([]byte, 32), nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if string(sig) != "signature" || serial != 22 {
		t.Fatalf("result = %q/%d", sig, serial)
	}
	if digestRequests.Load() != 2 {
		t.Fatalf("digest requests = %d, want a rebuild for the fresh card attempt", digestRequests.Load())
	}
	if firstSigner.calls.Load() != 1 || secondSigner.calls.Load() != 1 {
		t.Fatalf("signature calls = first:%d second:%d, want one each", firstSigner.calls.Load(), secondSigner.calls.Load())
	}
	if opens.Load() != 4 {
		t.Fatalf("opens = %d, want initial + diagnostic + recovered acquisition + fresh retry", opens.Load())
	}
}

func TestShortDeadlineReturnsTouchWindowErrorWithoutNotification(t *testing.T) {
	cert, key := testCertificate(t)
	signer := &fakeCryptoSigner{public: &key.PublicKey}
	fake := &fakeCard{serial: 22, cert: cert, retries: 3, private: signer}
	var notifications atomic.Int32
	h := &Hardware{
		Serials:     []uint32{22},
		Deadline:    15 * time.Second,
		listReaders: func() ([]string, error) { return []string{"pivb"}, nil },
		openReader:  func(string) (card, error) { return fake, nil },
		notifyFunc:  func(string) { notifications.Add(1) },
	}
	h.setVerifiedSerial(22)
	_, _, err := h.Sign(context.Background(), "test", "123456", func(uint32, *x509.Certificate) ([]byte, error) {
		return make([]byte, 32), nil
	})
	var touchWindow *TouchWindowError
	if !errors.As(err, &touchWindow) {
		t.Fatalf("error = %T %v, want TouchWindowError", err, err)
	}
	if notifications.Load() != 0 || signer.calls.Load() != 0 {
		t.Fatalf("short deadline prompted/signed: notifications=%d signatures=%d", notifications.Load(), signer.calls.Load())
	}
}

func TestTouchWindowReserveAppliesOnlyToFirstAttemptUsingRealDeadline(t *testing.T) {
	cert, key := testCertificate(t)
	firstSigner := &fakeCryptoSigner{public: &key.PublicKey, err: sharingErr, delay: 250 * time.Millisecond}
	secondSigner := &fakeCryptoSigner{public: &key.PublicKey}
	first := &fakeCard{serial: 22, cert: cert, retries: 3, private: firstSigner}
	second := &fakeCard{serial: 22, cert: cert, retries: 3, private: secondSigner}
	var opens atomic.Int32
	h := &Hardware{
		Serials:             []uint32{22},
		Deadline:            600 * time.Millisecond,
		minTouchWindow:      400 * time.Millisecond,
		minRetryTouchWindow: 100 * time.Millisecond,
		listReaders:         func() ([]string, error) { return []string{"reader"}, nil },
		openReader: func(string) (card, error) {
			if opens.Add(1) == 1 {
				return first, nil
			}
			return second, nil
		},
	}
	h.setVerifiedSerial(22)
	var digests atomic.Int32
	sig, serial, err := h.Sign(context.Background(), "test", "123456", func(uint32, *x509.Certificate) ([]byte, error) {
		digests.Add(1)
		return make([]byte, 32), nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if string(sig) != "signature" || serial != 22 {
		t.Fatalf("result = %q/%d", sig, serial)
	}
	if digests.Load() != 2 || firstSigner.calls.Load() != 1 || secondSigner.calls.Load() != 1 {
		t.Fatalf("digests/signatures = %d/%d/%d, want rebuilt digest and one call per attempt", digests.Load(), firstSigner.calls.Load(), secondSigner.calls.Load())
	}
}

func TestRetryTouchWindowKeepsSmallDoomedPromptFloor(t *testing.T) {
	cert, key := testCertificate(t)
	firstSigner := &fakeCryptoSigner{public: &key.PublicKey, err: sharingErr, delay: 250 * time.Millisecond}
	secondSigner := &fakeCryptoSigner{public: &key.PublicKey}
	first := &fakeCard{serial: 22, cert: cert, retries: 3, private: firstSigner}
	second := &fakeCard{serial: 22, cert: cert, retries: 3, private: secondSigner}
	var opens atomic.Int32
	var notifications atomic.Int32
	h := &Hardware{
		Serials:             []uint32{22},
		Deadline:            800 * time.Millisecond,
		minTouchWindow:      200 * time.Millisecond,
		minRetryTouchWindow: 650 * time.Millisecond,
		listReaders:         func() ([]string, error) { return []string{"reader"}, nil },
		openReader: func(string) (card, error) {
			if opens.Add(1) == 1 {
				return first, nil
			}
			return second, nil
		},
		notifyFunc: func(string) { notifications.Add(1) },
	}
	h.setVerifiedSerial(22)
	_, _, err := h.Sign(context.Background(), "test", "123456", func(uint32, *x509.Certificate) ([]byte, error) {
		return make([]byte, 32), nil
	})
	var touchWindow *TouchWindowError
	if !errors.As(err, &touchWindow) {
		t.Fatalf("error = %T %v, want retry TouchWindowError", err, err)
	}
	if notifications.Load() != 1 || firstSigner.calls.Load() != 1 || secondSigner.calls.Load() != 0 {
		t.Fatalf("notifications/signatures = %d/%d/%d, retry emitted a doomed prompt", notifications.Load(), firstSigner.calls.Load(), secondSigner.calls.Load())
	}
}

func shortRecoveryHardware(open func(string) (card, error)) *Hardware {
	return &Hardware{
		Serials:       []uint32{22},
		listReaders:   func() ([]string, error) { return []string{"reader"}, nil },
		openReader:    open,
		recoveryGrace: 5 * time.Millisecond,
		recoveryLimit: 80 * time.Millisecond,
		inspectSCD:    func(context.Context) (scdaemonState, error) { return scdaemonRunning, nil },
	}
}
