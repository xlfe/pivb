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
	"sync"
	"time"

	"github.com/xlfe/pivb/internal/agentsource"
	"github.com/xlfe/pivb/internal/config"
	"github.com/xlfe/pivb/internal/pivsigner"
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
}

type SubjectTokenResult struct {
	IDToken   string
	ExpiresAt time.Time
	Serial    uint32
	KeyID     string
}

// SignEvent records the metadata of the last successful signature for
// card-free status reporting. It contains no token material.
type SignEvent struct {
	Alias  string
	Target string
	Serial uint32
	KeyID  string
	At     time.Time
}

type Status struct {
	PINCached         bool      `json:"pin_cached"`
	PINVerifiedSerial uint32    `json:"pin_verified_serial"`
	WIFProvider       string    `json:"wif_provider"`
	LastSignAlias     string    `json:"last_sign_alias,omitempty"`
	LastSignTarget    string    `json:"last_sign_target,omitempty"`
	LastSignSerial    uint32    `json:"last_sign_serial,omitempty"`
	LastSignKeyID     string    `json:"last_sign_key_id,omitempty"`
	LastSignAt        time.Time `json:"last_sign_at,omitzero"`
	Version           string    `json:"version"`
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
}

func New(cfg *config.Config, signer pivsigner.Signer, version string) *Core {
	return &Core{
		cfg: cfg, signer: signer, version: version,
		now:    time.Now,
		random: rand.Reader,
	}
}

func (c *Core) SetNowForTest(now func() time.Time) { c.now = now }
func (c *Core) SetRandomForTest(random io.Reader)  { c.random = random }

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
	c.mu.Unlock()
	return retries, nil
}

// Lock discards the cached PIN and the cached signing metadata.
func (c *Core) Lock() {
	c.mintMu.Lock()
	defer c.mintMu.Unlock()
	c.mu.Lock()
	defer c.mu.Unlock()
	c.clearPINLocked()
	c.lastSign = nil
}

// SubjectToken validates the request against configuration, opens one PIV
// signing session, and returns a five-minute RS256 OIDC subject token bound
// to the enrolled key observed in that session. The token is returned to the
// caller and never retained or logged by the daemon.
func (c *Core) SubjectToken(ctx context.Context, req SubjectTokenRequest) (SubjectTokenResult, error) {
	source, _, err := agentsource.Validate(req.RequestSource, req.Alias)
	if err != nil {
		return SubjectTokenResult{}, &RequestSourceError{Err: err}
	}
	req.RequestSource = source
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

	c.mintMu.Lock()
	defer c.mintMu.Unlock()
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
		return wif.SigningDigest(input), nil
	}

	label := agentsource.SigningLabel(req.RequestSource, req.Alias, alias.Target)
	sig, serial, err := c.signer.Sign(ctx, label, string(pin), digestFor)
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
	c.mu.Lock()
	c.lastSign = &SignEvent{Alias: req.Alias, Target: alias.Target, Serial: serial, KeyID: signedKid, At: now}
	c.mu.Unlock()
	return SubjectTokenResult{IDToken: token, ExpiresAt: claims.ExpiresAt(), Serial: serial, KeyID: signedKid}, nil
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
	}
	return status
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
		}
		return
	}
	if serial != 0 && len(c.pin) != 0 {
		c.pinVerifiedSerial = serial
	}
}

func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
