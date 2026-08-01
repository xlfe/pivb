package core

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/xlfe/pivb/internal/config"
	"github.com/xlfe/pivb/internal/pivsigner"
)

var (
	ErrLocked   = errors.New("PIN is not cached; run `pivb unlock` first")
	ErrNoToken  = errors.New("no valid access token; run `pivb use <alias>` or `pivb renew`")
	ErrAudience = errors.New("audience is required")
)

type UnknownAliasError struct{ Alias string }

func (e *UnknownAliasError) Error() string { return fmt.Sprintf("unknown alias %q", e.Alias) }

type Minter interface {
	Mint(ctx context.Context, request MintRequest) (MintedCredential, error)
}

type MintPurpose string

const (
	MintAccess   MintPurpose = "access"
	MintIdentity MintPurpose = "identity"
)

type MintRequest struct {
	AliasName string
	Alias     config.Alias
	PIN       string
	Purpose   MintPurpose
	Audience  string
}

// MintedCredential is deliberately cloud-neutral. Fields carries provider-shaped
// material (for GCP, access_token or token; for future AWS, the STS triple).
type MintedCredential struct {
	Cloud     string
	Subject   string
	Fields    map[string]string
	Value     string
	ExpiresAt time.Time
	Serial    uint32
}

type MintedAccess = MintedCredential
type MintedIdentity = MintedCredential

type Token struct {
	AccessToken string            `json:"access_token"`
	ExpiresAt   time.Time         `json:"expires_at"`
	TargetEmail string            `json:"target_email"`
	Cloud       string            `json:"cloud"`
	Subject     string            `json:"subject"`
	Credential  map[string]string `json:"credential,omitempty"`
}

type Identity struct {
	Token      string            `json:"token"`
	ExpiresAt  time.Time         `json:"expires_at"`
	Cloud      string            `json:"cloud"`
	Subject    string            `json:"subject"`
	Credential map[string]string `json:"credential,omitempty"`
}

type Status struct {
	Cloud          string `json:"cloud"`
	ActiveAlias    string `json:"active_alias"`
	TargetEmail    string `json:"target_email"`
	ProjectID      string `json:"project_id"`
	NumericProject string `json:"numeric_project_id,omitempty"`
	TokenExpiresIn int64  `json:"token_expires_in_s"`
	PINCached      bool   `json:"pin_cached"`
	YubiKeySerial  uint32 `json:"yubikey_serial"`
	Version        string `json:"version"`
}

type Core struct {
	cfg     *config.Config
	signer  pivsigner.Signer
	minter  Minter
	version string
	now     func() time.Time

	mintMu sync.Mutex
	mu     sync.RWMutex
	pin    []byte
	clouds map[string]*cloudState
	serial uint32
}

type cloudState struct {
	active string
	token  *Token
	ids    map[string]Identity
}

func New(cfg *config.Config, signer pivsigner.Signer, minter Minter, version string) *Core {
	return &Core{
		cfg: cfg, signer: signer, minter: minter, version: version,
		now: time.Now,
		clouds: map[string]*cloudState{
			"gcp": {active: cfg.DefaultAlias, ids: make(map[string]Identity)},
		},
	}
}

func (c *Core) SetNowForTest(now func() time.Time) { c.now = now }

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
	c.serial = serial
	c.mu.Unlock()
	return retries, nil
}

func (c *Core) Lock() {
	c.mintMu.Lock()
	defer c.mintMu.Unlock()
	c.mu.Lock()
	defer c.mu.Unlock()
	c.clearPINLocked()
	c.clearTokensLocked()
}

func (c *Core) Use(ctx context.Context, name string) (Token, error) {
	alias, ok := c.cfg.Aliases[name]
	if !ok {
		return Token{}, &UnknownAliasError{Alias: name}
	}
	c.mintMu.Lock()
	defer c.mintMu.Unlock()
	pin, err := c.takePIN()
	if err != nil {
		return Token{}, err
	}
	defer zero(pin)
	t, err := c.minter.Mint(ctx, MintRequest{AliasName: name, Alias: alias, PIN: string(pin), Purpose: MintAccess})
	if err != nil {
		return Token{}, err
	}
	fields := cloneFields(t.Fields)
	if fields == nil {
		fields = map[string]string{"access_token": t.Value}
	}
	newToken := Token{AccessToken: t.Value, ExpiresAt: t.ExpiresAt, TargetEmail: alias.Target, Cloud: alias.Cloud, Subject: alias.Target, Credential: fields}
	c.mu.Lock()
	state := c.cloudStateLocked(alias.Cloud)
	state.active = name
	state.token = &newToken
	state.ids = make(map[string]Identity)
	c.serial = t.Serial
	c.mu.Unlock()
	return newToken, nil
}

func (c *Core) Renew(ctx context.Context) (Token, error) {
	c.mu.RLock()
	name := c.clouds["gcp"].active
	c.mu.RUnlock()
	return c.Use(ctx, name)
}

func (c *Core) Token() (Token, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	state := c.clouds["gcp"]
	if state.token == nil || !state.token.ExpiresAt.After(c.now()) {
		return Token{}, ErrNoToken
	}
	return *state.token, nil
}

func (c *Core) Identity(ctx context.Context, audience string) (Identity, error) {
	if audience == "" {
		return Identity{}, ErrAudience
	}
	c.mu.RLock()
	state := c.clouds["gcp"]
	if id, ok := state.ids[audience]; ok && id.ExpiresAt.After(c.now()) {
		c.mu.RUnlock()
		return id, nil
	}
	c.mu.RUnlock()

	c.mintMu.Lock()
	defer c.mintMu.Unlock()
	// Recheck after acquiring the mint lock.
	c.mu.RLock()
	state = c.clouds["gcp"]
	if id, ok := state.ids[audience]; ok && id.ExpiresAt.After(c.now()) {
		c.mu.RUnlock()
		return id, nil
	}
	name := state.active
	c.mu.RUnlock()
	alias := c.cfg.Aliases[name]
	pin, err := c.takePIN()
	if err != nil {
		return Identity{}, err
	}
	defer zero(pin)
	t, err := c.minter.Mint(ctx, MintRequest{AliasName: name, Alias: alias, PIN: string(pin), Purpose: MintIdentity, Audience: audience})
	if err != nil {
		return Identity{}, err
	}
	fields := cloneFields(t.Fields)
	if fields == nil {
		fields = map[string]string{"token": t.Value}
	}
	id := Identity{Token: t.Value, ExpiresAt: t.ExpiresAt, Cloud: alias.Cloud, Subject: alias.Target, Credential: fields}
	c.mu.Lock()
	c.cloudStateLocked(alias.Cloud).ids[audience] = id
	c.serial = t.Serial
	c.mu.Unlock()
	return id, nil
}

func (c *Core) Status() Status {
	c.mu.RLock()
	defer c.mu.RUnlock()
	state := c.clouds["gcp"]
	alias := c.cfg.Aliases[state.active]
	expires := int64(0)
	if state.token != nil && state.token.ExpiresAt.After(c.now()) {
		expires = int64(state.token.ExpiresAt.Sub(c.now()).Seconds())
	}
	return Status{
		Cloud: alias.Cloud, ActiveAlias: state.active, TargetEmail: alias.Target, ProjectID: alias.ProjectID,
		NumericProject: alias.NumericProjectID, TokenExpiresIn: expires,
		PINCached: len(c.pin) != 0, YubiKeySerial: c.serial, Version: c.version,
	}
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
}

func (c *Core) clearTokensLocked() {
	for _, state := range c.clouds {
		if state.token != nil {
			// Strings cannot be reliably zeroed in Go; sever all references immediately.
			state.token = nil
		}
		state.ids = make(map[string]Identity)
	}
}

func (c *Core) cloudStateLocked(cloud string) *cloudState {
	state := c.clouds[cloud]
	if state == nil {
		state = &cloudState{ids: make(map[string]Identity)}
		c.clouds[cloud] = state
	}
	return state
}

func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

func cloneFields(fields map[string]string) map[string]string {
	if fields == nil {
		return nil
	}
	copyFields := make(map[string]string, len(fields))
	for key, value := range fields {
		copyFields[key] = value
	}
	return copyFields
}
