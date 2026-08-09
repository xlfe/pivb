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
	Acquire(ctx context.Context, operation string) (release func(), err error)
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
	Serials  []uint32
	Notify   []string
	Logger   *slog.Logger
	Deadline time.Duration
	Lease    LeaseManager

	mu             sync.Mutex
	verifiedSerial uint32
}

func (h *Hardware) Describe(ctx context.Context) (uint32, *x509.Certificate, error) {
	release, err := h.acquireLease(ctx, "pivb-describe")
	if err != nil {
		return 0, nil, err
	}
	defer release()
	select {
	case <-ctx.Done():
		return 0, nil, ctx.Err()
	default:
	}
	yk, serial, err := h.openSelected()
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
	release, err := h.acquireLease(ctx, "pivb-unlock")
	if err != nil {
		return 0, -1, err
	}
	defer release()
	yk, serial, err := h.openSelected()
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
	deadline := h.Deadline
	if deadline == 0 {
		deadline = 20 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, deadline)
	defer cancel()
	release, err := h.acquireLease(ctx, "pivb-mint")
	if err != nil {
		return nil, 0, err
	}
	defer release()

	sig, serial, err := h.signAttempt(ctx, label, pin, digestFor)
	if err == nil || !IsSharingViolation(err) {
		return sig, serial, err
	}
	h.logger().Warn("PIV session hit confirmed sharing violation; handing card off from scdaemon and retrying once", "error", err)
	if killErr := exec.CommandContext(ctx, "gpgconf", "--kill", "scdaemon").Run(); killErr != nil {
		return nil, 0, fmt.Errorf("sharing violation; kill scdaemon before retry: %w", killErr)
	}
	return h.signAttempt(ctx, label, pin, digestFor)
}

func (h *Hardware) acquireLease(ctx context.Context, operation string) (func(), error) {
	if h.Lease == nil {
		return func() {}, nil
	}
	release, err := h.Lease.Acquire(ctx, operation)
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

func (h *Hardware) signAttempt(ctx context.Context, label, pin string, digestFor func(uint32, *x509.Certificate) ([]byte, error)) ([]byte, uint32, error) {
	result := make(chan signResult, 1)
	go func() {
		yk, serial, err := h.openSelected()
		if err != nil {
			result <- signResult{err: err}
			return
		}
		defer yk.Close()
		// Failures before verifyCachedPIN must not report a serial: a nonzero
		// serial in the result tells the caller the cached PIN was verified
		// against that card during this operation.
		cert, err := yk.Certificate(piv.SlotSignature)
		if err != nil {
			result <- signResult{err: fmt.Errorf("read certificate from PIV slot 9c on YubiKey %d: %w", serial, err)}
			return
		}
		if _, err := wifPublicKey(cert); err != nil {
			result <- signResult{err: fmt.Errorf("PIV slot 9c on YubiKey %d %w", serial, err)}
			return
		}
		digest, err := digestFor(serial, cert)
		if err != nil {
			result <- signResult{err: fmt.Errorf("build signing digest for YubiKey %d: %w", serial, err)}
			return
		}
		if err := h.verifyCachedPIN(yk, serial, pin); err != nil {
			result <- signResult{err: err}
			return
		}
		key, err := yk.PrivateKey(piv.SlotSignature, cert.PublicKey, piv.KeyAuth{PIN: pin})
		if err != nil {
			result <- signResult{serial: serial, err: fmt.Errorf("open PIV private key on YubiKey %d: %w", serial, err)}
			return
		}
		signer, ok := key.(crypto.Signer)
		if !ok {
			result <- signResult{serial: serial, err: errors.New("PIV private key does not implement crypto.Signer")}
			return
		}
		h.notify("Touch YubiKey to sign " + label)
		sig, err := signer.Sign(rand.Reader, digest, crypto.SHA256)
		if err != nil {
			err = fmt.Errorf("sign with PIV slot 9c on YubiKey %d: %w", serial, err)
		}
		result <- signResult{sig: sig, serial: serial, err: err}
	}()

	select {
	case <-ctx.Done():
		timer := time.NewTimer(signResultDrainTimeout)
		defer timer.Stop()
		select {
		case <-result:
		case <-timer.C:
			h.logger().Warn("PIV signing worker did not release the card promptly after cancellation; a follow-up operation may briefly see it as busy")
		}
		return nil, 0, fmt.Errorf("PIV signing deadline: %w", ctx.Err())
	case r := <-result:
		return r.sig, r.serial, r.err
	}
}

func (h *Hardware) verifyCachedPIN(yk *piv.YubiKey, serial uint32, pin string) error {
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

func (h *Hardware) openSelected() (*piv.YubiKey, uint32, error) {
	cards, err := piv.Cards()
	if err != nil {
		return nil, 0, fmt.Errorf("enumerate smart cards: %w", err)
	}
	wanted := make(map[uint32]struct{}, len(h.Serials))
	for _, serial := range h.Serials {
		wanted[serial] = struct{}{}
	}
	var selected *piv.YubiKey
	var selectedSerial uint32
	for _, card := range cards {
		yk, err := piv.Open(card)
		if err != nil {
			if selected != nil {
				selected.Close()
			}
			return nil, 0, fmt.Errorf("open smart card %q: %w", card, err)
		}
		serial, err := yk.Serial()
		if err != nil {
			yk.Close()
			if selected != nil {
				selected.Close()
			}
			return nil, 0, fmt.Errorf("read serial for smart card %q: %w", card, err)
		}
		if _, ok := wanted[serial]; !ok {
			yk.Close()
			continue
		}
		if selected != nil {
			yk.Close()
			selected.Close()
			return nil, 0, fmt.Errorf("multiple configured YubiKeys are present (%d and %d); leave exactly one inserted", selectedSerial, serial)
		}
		selected, selectedSerial = yk, serial
	}
	if selected == nil {
		return nil, 0, fmt.Errorf("no configured YubiKey present (wanted serials %v)", h.Serials)
	}
	return selected, selectedSerial, nil
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
