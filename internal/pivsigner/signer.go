package pivsigner

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"os/exec"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/go-piv/piv-go/v2/piv"
)

const (
	sharingViolationCode   = "0x8010000b"
	signResultDrainTimeout = 2 * time.Second
)

// piv-go v2.6 maps SCARD_E_SHARING_VIOLATION to this text and does not expose
// the return code through its public error API.
const sharingViolationPIVGoText = "the smart card cannot be accessed because of other connections outstanding"

type PINError struct {
	Retries        int
	Err            error
	Remedy         string
	ClearCachedPIN bool
}

func (e *PINError) Error() string {
	if e.Retries >= 0 {
		return fmt.Sprintf("PIN verification failed (%d retries remaining): %v", e.Retries, e.Err)
	}
	return "PIN verification failed: " + e.Err.Error()
}

func (e *PINError) Unwrap() error { return e.Err }

// Signer is the hardware seam. Sign opens one ephemeral PIV session, reads
// the live slot-9c certificate, and asks digestFor for the digest to sign.
// digestFor receives the serial and certificate observed inside that same
// session, so the caller can bind claims to the exact key that will sign and
// refuse a certificate that no longer matches enrolled configuration.
type Signer interface {
	VerifyPIN(ctx context.Context, pin string) (serial uint32, retries int, err error)
	Sign(ctx context.Context, label, pin string, digestFor func(serial uint32, cert *x509.Certificate) ([]byte, error)) (signature []byte, serial uint32, err error)
}

// Describer is implemented by hardware signers that can report the exact
// slot-9c public identity without verifying a PIN or requesting a touch.
type Describer interface {
	Describe(ctx context.Context) (serial uint32, cert *x509.Certificate, err error)
}

type LeaseManager interface {
	Acquire(ctx context.Context, operation string, acquireBudget time.Duration) (release func(), err error)
}

type requireLeaseKey struct{}

// RequireLease marks a workspace-forwarded operation. These operations must
// coordinate with ZKA and fail closed if its lease service is unavailable.
// Direct-local PIVB operations retain their pre-ZKA behavior.
func RequireLease(ctx context.Context) context.Context {
	return context.WithValue(ctx, requireLeaseKey{}, true)
}

type leaseUnavailable interface {
	LeaseUnavailable() bool
}

type Hardware struct {
	Serials   []uint32
	Notify    []string
	Logger    *slog.Logger
	Deadline  time.Duration
	Lease     LeaseManager
	GnuPGHome string

	mu             sync.Mutex
	verifiedSerial uint32

	openSessions      atomic.Int64
	openWorkers       atomic.Int64
	blockedOpenEvents atomic.Uint64
	diagnosticWorker  atomic.Bool
	probeMu           sync.Mutex
	probe             *probeCall
	recoveryMu        sync.Mutex
	handoffs          []time.Time
	gpgConnectLogOnce sync.Once
	gpgconfLogOnce    sync.Once
	gnupgTargetOnce   sync.Once

	// Injectable package seams. Production leaves these nil and uses piv-go,
	// os/exec, and the real clock.
	listReaders         func() ([]string, error)
	openReader          func(string) (card, error)
	inspectSCD          func(context.Context) (scdaemonState, error)
	handoff             func(context.Context) error
	command             func(context.Context, string, []string, string) ([]byte, error)
	lookPath            func(string) (string, error)
	now                 func() time.Time
	sleep               func(context.Context, time.Duration) error
	notifyFunc          func(string)
	recoveryGrace       time.Duration
	recoveryLimit       time.Duration
	minTouchWindow      time.Duration
	minRetryTouchWindow time.Duration
}

func (h *Hardware) Describe(ctx context.Context) (uint32, *x509.Certificate, error) {
	op := operationFrom(ctx, OriginForwarded)
	release, err := h.acquireLease(ctx, "pivb-describe", 2*time.Second)
	if err != nil {
		return 0, nil, err
	}
	defer release()
	select {
	case <-ctx.Done():
		return 0, nil, ctx.Err()
	default:
	}
	yk, serial, err := h.acquireCard(ctx, op, h.newRecoveryBudget())
	if err != nil {
		return 0, nil, err
	}
	defer yk.Close()
	cert, err := yk.Certificate(piv.SlotSignature)
	if err != nil {
		return 0, nil, fmt.Errorf("read certificate from PIV slot 9c on YubiKey %d: %w", serial, err)
	}
	if _, err := wifPublicKey(cert); err != nil {
		return 0, nil, fmt.Errorf("PIV slot 9c on YubiKey %d: %w", serial, err)
	}
	return serial, cert, nil
}

func wifPublicKey(cert *x509.Certificate) (*rsa.PublicKey, error) {
	public, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok || public.N.BitLen() != 2048 || public.E != 65537 {
		return nil, errors.New("must contain an RSA-2048/F4 certificate")
	}
	return public, nil
}

func (h *Hardware) VerifyPIN(ctx context.Context, pin string) (uint32, int, error) {
	op := operationFrom(ctx, OriginUnlock)
	release, err := h.acquireLease(ctx, "pivb-unlock", 2*time.Second)
	if err != nil {
		return 0, -1, err
	}
	defer release()
	yk, serial, err := h.acquireCard(ctx, op, h.newRecoveryBudget())
	if err != nil {
		return 0, -1, err
	}
	defer yk.Close()

	retries, err := yk.Retries()
	if err != nil {
		return serial, -1, fmt.Errorf("read PIN retries for YubiKey %d: %w", serial, err)
	}
	if retries <= 1 {
		return serial, retries, &PINError{Retries: retries, Err: errors.New("refusing to spend the final PIN attempt")}
	}
	select {
	case <-ctx.Done():
		return serial, retries, ctx.Err()
	default:
	}
	if err := yk.VerifyPIN(pin); err != nil {
		var authErr piv.AuthErr
		if errors.As(err, &authErr) {
			return serial, authErr.Retries, &PINError{Retries: authErr.Retries, Err: err}
		}
		return serial, retries, &PINError{Retries: retries, Err: err}
	}
	h.setVerifiedSerial(serial)
	return serial, retries, nil
}

func (h *Hardware) Sign(ctx context.Context, label, pin string, digestFor func(uint32, *x509.Certificate) ([]byte, error)) ([]byte, uint32, error) {
	op := operationFrom(ctx, OriginUnclassified)
	// Lease acquisition precedes the hardware deadline. The mint-specific one
	// second acquisition cap plus 20 second hardware window and two second
	// cancellation drain gives callers a hard 23 second upper bound. A bounded
	// first-use GnuPG diagnostic may ignore the hardware context, but it runs in
	// this worker and is therefore covered by the cancellation drain. In the
	// worst case, unresolved connect-agent and gpgconf diagnostics can use two
	// 250ms fallback windows of that headroom, but acquisition diagnostics do not
	// register an open card session.
	release, err := h.acquireLease(ctx, "pivb-mint", time.Second)
	if err != nil {
		return nil, 0, err
	}
	defer release()
	deadline := h.Deadline
	if deadline == 0 {
		deadline = 20 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, deadline)
	defer cancel()
	budget := h.newRecoveryBudget()

	sig, serial, err := h.signAttempt(ctx, op, budget, true, label, pin, digestFor)
	var handled *acquisitionHandledError
	if err == nil || errors.As(err, &handled) || !IsSharingViolation(err) {
		return sig, serial, err
	}
	// A sharing violation may surface after acquisition (certificate, PIN, or
	// transmit). Keep the audited whole-attempt retry: the retry re-reads the
	// certificate and digestFor rebuilds the digest for the card that signs.
	retrySig, retrySerial, retryErr := h.signAttempt(ctx, op, budget, false, label, pin, digestFor)
	if retryErr != nil {
		h.logger().Warn("fresh signing attempt after sharing violation failed", "operation", op.Origin, "operation_id", op.ID, "initial_error", err, "retry_error", retryErr)
	}
	return retrySig, retrySerial, retryErr
}

func (h *Hardware) acquireLease(ctx context.Context, operation string, budget time.Duration) (func(), error) {
	if h.Lease == nil {
		return func() {}, nil
	}
	release, err := h.Lease.Acquire(ctx, operation, budget)
	if err != nil {
		var unavailable leaseUnavailable
		required, _ := ctx.Value(requireLeaseKey{}).(bool)
		if !required && errors.As(err, &unavailable) && unavailable.LeaseUnavailable() {
			h.logger().Warn("ZKA smart-card lease is unavailable; continuing direct-local PIVB operation", "operation", operation, "error", err)
			return func() {}, nil
		}
		return nil, fmt.Errorf("acquire cooperative smart-card lease: %w", err)
	}
	return release, nil
}

type signResult struct {
	sig    []byte
	serial uint32
	err    error
}

func (h *Hardware) signAttempt(ctx context.Context, op operationInfo, budget *recoveryBudget, reserveTouchWindow bool, label, pin string, digestFor func(uint32, *x509.Certificate) ([]byte, error)) ([]byte, uint32, error) {
	result := make(chan signResult, 1)
	go func() {
		yk, serial, err := h.acquireCard(ctx, op, budget)
		if err != nil {
			result <- signResult{err: err}
			return
		}
		finish := func(r signResult) {
			// The close/unregister happens before the result is observable, so a
			// following request cannot mistake this completed worker for an
			// orphan that still owns the card.
			_ = yk.Close()
			result <- r
		}
		// Failures before verifyCachedPIN must not report a serial: a nonzero
		// serial in the result tells the caller the cached PIN was verified
		// against that card during this operation.
		cert, err := yk.Certificate(piv.SlotSignature)
		if err != nil {
			finish(signResult{err: fmt.Errorf("read certificate from PIV slot 9c on YubiKey %d: %w", serial, err)})
			return
		}
		if _, err := wifPublicKey(cert); err != nil {
			finish(signResult{err: fmt.Errorf("PIV slot 9c on YubiKey %d %w", serial, err)})
			return
		}
		digest, err := digestFor(serial, cert)
		if err != nil {
			finish(signResult{err: fmt.Errorf("build signing digest for YubiKey %d: %w", serial, err)})
			return
		}
		if err := h.verifyCachedPIN(yk, serial, pin); err != nil {
			finish(signResult{err: err})
			return
		}
		key, err := yk.PrivateKey(piv.SlotSignature, cert.PublicKey, piv.KeyAuth{PIN: pin})
		if err != nil {
			finish(signResult{serial: serial, err: fmt.Errorf("open PIV private key on YubiKey %d: %w", serial, err)})
			return
		}
		signer, ok := key.(crypto.Signer)
		if !ok {
			finish(signResult{serial: serial, err: errors.New("PIV private key does not implement crypto.Signer")})
			return
		}
		if deadline, ok := ctx.Deadline(); ok {
			remaining := time.Until(deadline)
			minimum := h.minRetryTouchWindow
			if reserveTouchWindow {
				minimum = h.minTouchWindow
				if minimum <= 0 {
					minimum = 16 * time.Second
				}
			} else if minimum <= 0 {
				minimum = 2 * time.Second
			}
			if remaining < minimum {
				if remaining < 0 {
					remaining = 0
				}
				finish(signResult{serial: serial, err: &TouchWindowError{Remaining: remaining}})
				return
			}
		}
		h.notify("Touch YubiKey to sign " + label)
		sig, err := signer.Sign(rand.Reader, digest, crypto.SHA256)
		if err != nil {
			err = fmt.Errorf("sign with PIV slot 9c on YubiKey %d: %w", serial, err)
		}
		finish(signResult{sig: sig, serial: serial, err: err})
	}()

	select {
	case <-ctx.Done():
		timer := time.NewTimer(signResultDrainTimeout)
		defer timer.Stop()
		select {
		case <-result:
		case <-timer.C:
			h.logger().Warn("PIV signing worker did not finish promptly after cancellation; a follow-up operation may briefly see the card path as busy", "self_holder", h.hasSelfHolder(), "open_workers", h.openWorkers.Load())
		}
		return nil, 0, fmt.Errorf("PIV signing deadline: %w", ctx.Err())
	case r := <-result:
		return r.sig, r.serial, r.err
	}
}

func (h *Hardware) verifyCachedPIN(yk card, serial uint32, pin string) error {
	if h.getVerifiedSerial() == serial {
		return nil
	}
	retries, err := yk.Retries()
	if err != nil {
		return fmt.Errorf("read PIN retries for swapped YubiKey %d: %w", serial, err)
	}
	if retries <= 1 {
		return &PINError{
			Retries: retries,
			Err:     fmt.Errorf("refusing to try the cached PIN on swapped YubiKey %d and spend the final PIN attempt", serial),
			Remedy:  "run `pivb unlock` with this key inserted after checking or resetting its PIV PIN",
		}
	}
	if err := yk.VerifyPIN(pin); err != nil {
		if authErr := (piv.AuthErr{}); errors.As(err, &authErr) {
			retries = authErr.Retries
		}
		h.setVerifiedSerial(0)
		return &PINError{
			Retries:        retries,
			Err:            fmt.Errorf("cached PIN was rejected by swapped YubiKey %d; fleet keys may have different PINs: %w", serial, err),
			Remedy:         "run `pivb unlock` with this key inserted; use the same PIV PIN on every fleet key for seamless swaps",
			ClearCachedPIN: true,
		}
	}
	h.setVerifiedSerial(serial)
	return nil
}

func (h *Hardware) getVerifiedSerial() uint32 {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.verifiedSerial
}

func (h *Hardware) setVerifiedSerial(serial uint32) {
	h.mu.Lock()
	h.verifiedSerial = serial
	h.mu.Unlock()
}

func IsSharingViolation(err error) bool {
	if err == nil {
		return false
	}
	s := strings.ToLower(err.Error())
	return strings.Contains(s, sharingViolationCode) ||
		strings.Contains(s, "sharing violation") ||
		strings.Contains(s, sharingViolationPIVGoText)
}

func (h *Hardware) notify(message string) {
	if h.notifyFunc != nil {
		h.notifyFunc(message)
		return
	}
	if len(h.Notify) == 0 {
		return
	}
	args := append(append([]string(nil), h.Notify[1:]...), message)
	cmd := exec.Command(h.Notify[0], args...)
	if err := cmd.Start(); err != nil {
		h.logger().Warn("desktop notification failed", "error", err)
		return
	}
	go func() {
		if err := cmd.Wait(); err != nil {
			h.logger().Warn("desktop notification failed", "error", err)
		}
	}()
}

func (h *Hardware) logger() *slog.Logger {
	if h.Logger != nil {
		return h.Logger
	}
	return slog.Default()
}

// CheckPCSC verifies that the system smart-card service is reachable. An empty
// reader list is valid: the user service must start even when no key is inserted.
func CheckPCSC() error {
	if _, err := piv.Cards(); err != nil {
		return fmt.Errorf("pcscd is unavailable: %w", err)
	}
	return nil
}
