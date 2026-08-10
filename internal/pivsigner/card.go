package pivsigner

import (
	"context"
	"crypto"
	"crypto/x509"
	"errors"
	"fmt"
	"sync"

	"github.com/go-piv/piv-go/v2/piv"
)

// card is the hardware seam used by the recovery tests. *piv.YubiKey
// implements it directly.
type card interface {
	Close() error
	Serial() (uint32, error)
	Certificate(piv.Slot) (*x509.Certificate, error)
	Retries() (int, error)
	VerifyPIN(string) error
	PrivateKey(piv.Slot, crypto.PublicKey, piv.KeyAuth) (crypto.PrivateKey, error)
}

type readerFailure struct {
	Reader string
	Stage  string
	Err    error
}

// SelectionError retains every reader failure when no configured card could
// be selected. Its multi-unwrapper deliberately preserves the PC/SC cause for
// IsSharingViolation and structured diagnostics.
type SelectionError struct {
	Readers  []string
	Wanted   []uint32
	Failures []readerFailure
}

func (e *SelectionError) Error() string {
	if len(e.Failures) == 0 {
		return fmt.Sprintf("no configured YubiKey present (wanted serials %v; readers %v)", e.Wanted, e.Readers)
	}
	parts := make([]error, 0, len(e.Failures)+1)
	parts = append(parts, fmt.Errorf("no configured YubiKey could be opened (wanted serials %v; readers %v)", e.Wanted, e.Readers))
	for _, failure := range e.Failures {
		parts = append(parts, fmt.Errorf("%s smart card %q: %w", failure.Stage, failure.Reader, failure.Err))
	}
	return errors.Join(parts...).Error()
}

func (e *SelectionError) Unwrap() []error {
	errs := make([]error, 0, len(e.Failures))
	for _, failure := range e.Failures {
		errs = append(errs, failure.Err)
	}
	return errs
}

type trackedCard struct {
	card
	h    *Hardware
	once sync.Once
}

func (c *trackedCard) Close() error {
	var err error
	c.once.Do(func() {
		err = c.card.Close()
		c.h.openSessions.Add(-1)
	})
	return err
}

type openResult struct {
	card   card
	serial uint32
	err    error
}

// probeCall is one non-cancellable PC/SC open shared by every bounded recovery
// waiter that arrives while it is in flight. All fields except done are guarded
// by Hardware.probeMu.
type probeCall struct {
	done    chan struct{}
	result  openResult
	ready   bool
	claimed bool
	waiters int
}

func (h *Hardware) readers() ([]string, error) {
	if h.listReaders != nil {
		return h.listReaders()
	}
	return piv.Cards()
}

func (h *Hardware) open(reader string) (card, error) {
	if h.openReader != nil {
		return h.openReader(reader)
	}
	return piv.Open(reader)
}

// openSelectedUntracked continues past readers it cannot open. A busy
// unrelated reader must not prevent discovery of a later configured YubiKey.
// It deliberately does not register the returned session as a self-holder:
// asynchronous callers do that only after delivering it to a live caller.
func (h *Hardware) openSelectedUntracked() (card, uint32, error) {
	readers, err := h.readers()
	if err != nil {
		return nil, 0, fmt.Errorf("enumerate smart cards: %w", err)
	}
	wanted := make(map[uint32]struct{}, len(h.Serials))
	for _, serial := range h.Serials {
		wanted[serial] = struct{}{}
	}
	var selected card
	var selectedSerial uint32
	var failures []readerFailure
	for _, reader := range readers {
		yk, openErr := h.open(reader)
		if openErr != nil {
			failures = append(failures, readerFailure{Reader: reader, Stage: "open", Err: openErr})
			continue
		}
		serial, serialErr := yk.Serial()
		if serialErr != nil {
			_ = yk.Close()
			failures = append(failures, readerFailure{Reader: reader, Stage: "read serial for", Err: serialErr})
			continue
		}
		if _, ok := wanted[serial]; !ok {
			_ = yk.Close()
			continue
		}
		if selected != nil {
			_ = yk.Close()
			_ = selected.Close()
			return nil, 0, fmt.Errorf("multiple configured YubiKeys are present (%d and %d); leave exactly one inserted", selectedSerial, serial)
		}
		selected, selectedSerial = yk, serial
	}
	if selected == nil {
		return nil, 0, &SelectionError{Readers: append([]string(nil), readers...), Wanted: append([]uint32(nil), h.Serials...), Failures: failures}
	}
	return selected, selectedSerial, nil
}

func (h *Hardware) trackCard(yk card) card {
	h.openSessions.Add(1)
	return &trackedCard{card: yk, h: h}
}

// openSelectedRaw is the synchronous selection entry point used by tests and
// callers that immediately assume ownership of the returned session.
func (h *Hardware) openSelectedRaw() (card, uint32, error) {
	yk, serial, err := h.openSelectedUntracked()
	if err != nil {
		return nil, 0, err
	}
	return h.trackCard(yk), serial, nil
}

// openSelectedContext bounds the caller even though PC/SC has no cancellable
// open API. A late worker is a waiter, not a self-holder. If it eventually
// opens a session after the caller has gone away, it closes that session
// before returning without ever registering it as a self-holder.
func (h *Hardware) openSelectedContext(ctx context.Context) (card, uint32, error) {
	result := make(chan openResult)
	h.openWorkers.Add(1)
	go func() {
		yk, serial, err := h.openSelectedUntracked()
		h.openWorkers.Add(-1)
		r := openResult{card: yk, serial: serial, err: err}
		select {
		case result <- r:
		case <-ctx.Done():
			if yk != nil {
				_ = yk.Close()
			}
			h.logger().Warn("late smart-card open worker completed after its caller stopped waiting", "error", err)
		}
	}()
	select {
	case r := <-result:
		if r.err != nil {
			return nil, 0, r.err
		}
		return h.trackCard(r.card), r.serial, nil
	case <-ctx.Done():
		h.blockedOpenEvents.Add(1)
		h.logger().Warn("smart-card open worker remains blocked after its caller stopped waiting", "open_workers", h.openWorkers.Load(), "ever_blocked_in_open", true)
		return nil, 0, fmt.Errorf("open smart card: %w", ctx.Err())
	}
}

// openProbeContext shares one underlying non-cancellable PC/SC open among all
// recovery callers that arrive while it is in flight. Each caller keeps its own
// deadline. started reports how many real opens this call launched, allowing
// recovery diagnostics to count actual attempts rather than waiters.
func (h *Hardware) openProbeContext(ctx context.Context) (yk card, serial uint32, started int, err error) {
	startedAttempts := 0
	for {
		h.probeMu.Lock()
		call := h.probe
		if call == nil {
			call = &probeCall{done: make(chan struct{})}
			h.probe = call
			startedAttempts++
			h.openWorkers.Add(1)
			go h.runProbe(call)
		}
		call.waiters++
		h.probeMu.Unlock()

		select {
		case <-ctx.Done():
			h.releaseProbeWaiter(call)
			h.blockedOpenEvents.Add(1)
			h.logger().Warn("smart-card recovery probe remains blocked after its caller stopped waiting", "open_workers", h.openWorkers.Load(), "ever_blocked_in_open", true)
			return nil, 0, startedAttempts, fmt.Errorf("open smart card recovery probe: %w", ctx.Err())
		case <-call.done:
			h.probeMu.Lock()
			call.waiters--
			result := call.result
			if result.err != nil {
				if call.waiters == 0 && h.probe == call {
					h.probe = nil
				}
				h.probeMu.Unlock()
				return nil, 0, startedAttempts, result.err
			}
			if !call.claimed {
				call.claimed = true
				if h.probe == call {
					h.probe = nil
				}
				h.probeMu.Unlock()
				return h.trackCard(result.card), result.serial, startedAttempts, nil
			}
			h.probeMu.Unlock()
			// Another concurrent recovery claimed the shared successful open.
			// Start or join the next probe within this caller's own deadline.
			if err := ctx.Err(); err != nil {
				return nil, 0, startedAttempts, err
			}
		}
	}
}

func (h *Hardware) runProbe(call *probeCall) {
	yk, serial, err := h.openSelectedUntracked()
	h.openWorkers.Add(-1)

	var closeLate card
	h.probeMu.Lock()
	call.result = openResult{card: yk, serial: serial, err: err}
	call.ready = true
	close(call.done)
	if h.probe == call {
		h.probe = nil
	}
	if call.waiters == 0 {
		if yk != nil {
			closeLate = yk
		}
	}
	h.probeMu.Unlock()
	if closeLate != nil {
		_ = closeLate.Close()
		h.logger().Warn("late smart-card recovery probe opened a session after every caller stopped waiting; closed it without registering a self-holder")
	}
}

func (h *Hardware) releaseProbeWaiter(call *probeCall) {
	var closeLate card
	h.probeMu.Lock()
	call.waiters--
	if call.ready && call.waiters == 0 {
		if h.probe == call {
			h.probe = nil
		}
		if call.result.card != nil && !call.claimed {
			call.claimed = true
			closeLate = call.result.card
		}
	}
	h.probeMu.Unlock()
	if closeLate != nil {
		_ = closeLate.Close()
	}
}

func (h *Hardware) hasProbeWorker() bool {
	h.probeMu.Lock()
	defer h.probeMu.Unlock()
	return h.probe != nil
}

func (h *Hardware) hasSelfHolder() bool { return h.openSessions.Load() > 0 }

// Compile-time assertion keeps the concrete hardware seam honest when
// piv-go changes.
var _ card = (*piv.YubiKey)(nil)
