// Package config loads and validates the closed pivb configuration schema.
// The schema is fail-closed: unknown keys are fatal, retired pre-WIF keys
// produce one migration error, and every identity-bearing value must match a
// conservative grammar before it can reach a signed claim or a generated
// Google artifact.
package config

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/BurntSushi/toml"

	"github.com/xlfe/pivb/internal/wif"
)

const (
	defaultLifetimeS = 3600
	minLifetimeS     = 600
	maxLifetimeS     = 3600
	// The assertion lifetime an alias may configure. The floor is also the
	// default; the ceiling is wif's absolute one, which claim construction
	// enforces again.
	defaultAssertionLifetimeS = int(wif.DefaultLifetime / time.Second)
	minAssertionLifetimeS     = defaultAssertionLifetimeS
	maxAssertionLifetimeS     = int(wif.MaxLifetime / time.Second)
	// minRemainingValidityS is the validity a reused assertion must still have
	// left when it is served, so it can complete a full STS exchange. It is the
	// same floor internal/core enforces at serve time (reuseValidityFloor).
	minRemainingValidityS = 60
)

// migrationDoc is named by the single migration error for retired keys.
const migrationDoc = "README.md"

var (
	projectNumberRE = regexp.MustCompile(`^[1-9][0-9]{0,29}$`)
	poolProviderRE  = regexp.MustCompile(`^[a-z][a-z0-9-]{2,30}[a-z0-9]$`)
	aliasNameRE     = regexp.MustCompile(`^[a-z]([a-z0-9-]{0,30}[a-z0-9])?$`)
	jwkKidRE        = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)
	targetEmailRE   = regexp.MustCompile(`^[a-z]([a-z0-9-]{4,28}[a-z0-9])?@[a-z][a-z0-9-]{4,28}[a-z0-9]\.iam\.gserviceaccount\.com$`)
)

// retiredTopLevelKeys and retiredSuffixes identify pre-WIF configuration
// (both the broker-fleet schema and the older single-key schema) that must
// fail with a migration message rather than a generic unknown-key error.
var retiredTopLevelKeys = map[string]struct{}{
	"listen_metadata":        {},
	"default_alias":          {},
	"remote_allowed_aliases": {},
	"broker_sa":              {},
	"key_id":                 {},
	"yubikey_serials":        {},
}

var retiredSuffixes = []string{".broker_sa", ".key_id", ".project_id", ".numeric_project_id"}

type Config struct {
	PIVSlot   string           `toml:"piv_slot"`
	PINCache  string           `toml:"pin_cache"`
	NotifyCmd []string         `toml:"notify_cmd"`
	GnuPGHome string           `toml:"gnupg_home"`
	WIF       WIF              `toml:"wif"`
	Keys      map[string]Key   `toml:"keys"`
	Aliases   map[string]Alias `toml:"aliases"`
}

type WIF struct {
	ProjectNumber string `toml:"project_number"`
	PoolID        string `toml:"pool_id"`
	ProviderID    string `toml:"provider_id"`
	IssuerURI     string `toml:"issuer_uri"`
}

type Key struct {
	JWKKid string `toml:"jwk_kid"`
}

type Alias struct {
	Cloud     string `toml:"cloud"`
	Target    string `toml:"target"`
	LifetimeS int    `toml:"lifetime_s"`
	// AssertionReuseS is how long after a touch this alias may answer
	// byte-identical requests without another one. Zero, the default, means
	// every credential costs a touch.
	AssertionReuseS int `toml:"assertion_reuse_s"`
	// AssertionLifetimeS is how long one minted assertion stays exchangeable
	// for Google access tokens. Load defaults it; zero survives only in a
	// hand-built struct and reads as the default.
	AssertionLifetimeS int `toml:"assertion_lifetime_s"`
}

// aliasAssertionLifetimeS is the validity of one minted assertion in seconds.
// Load's defaulting pass fills the field in, so a zero here is a configuration
// that never went through it.
func aliasAssertionLifetimeS(alias Alias) int {
	if alias.AssertionLifetimeS <= 0 {
		return defaultAssertionLifetimeS
	}
	return alias.AssertionLifetimeS
}

// maxAssertionLifetimeSFor is the longest assertion an alias may configure: the
// absolute ceiling, tightened to the alias's own access-token lifetime so one
// touch's assertion never outlives the credential it buys. A lifetime_s that is
// itself out of range reports itself and does not also distort this bound.
func maxAssertionLifetimeSFor(alias Alias) int {
	if alias.LifetimeS >= minLifetimeS && alias.LifetimeS < maxAssertionLifetimeS {
		return alias.LifetimeS
	}
	return maxAssertionLifetimeS
}

// maxAssertionReuseS is the largest reuse window an alias may configure. The
// headroom keeps every served assertion at least minRemainingValidityS from
// expiry: wif backdates iat by one ClockSkew at mint time, so that much of the
// lifetime is already spent when the assertion is signed.
func maxAssertionReuseS(alias Alias) int {
	return aliasAssertionLifetimeS(alias) - int(wif.ClockSkew/time.Second) - minRemainingValidityS
}

func DefaultPath() (string, error) {
	if base := os.Getenv("XDG_CONFIG_HOME"); base != "" {
		return filepath.Join(base, "pivb", "config.toml"), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("resolve config home: %w", err)
	}
	return filepath.Join(home, ".config", "pivb", "config.toml"), nil
}

func Load(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config %q: %w", path, err)
	}
	var cfg Config
	md, err := toml.Decode(string(b), &cfg)
	if err != nil {
		return nil, fmt.Errorf("parse config %q: %w", path, err)
	}
	if undecoded := md.Undecoded(); len(undecoded) != 0 {
		names := make([]string, 0, len(undecoded))
		var retired []string
		for _, key := range undecoded {
			name := key.String()
			names = append(names, name)
			if isRetiredKey(name) {
				retired = append(retired, name)
			}
		}
		sort.Strings(names)
		if len(retired) != 0 {
			sort.Strings(retired)
			return nil, fmt.Errorf(
				"config key(s) %s belong to the retired metadata/broker architecture and are no longer supported; migrate to the Workload Identity Federation schema described in %s",
				strings.Join(retired, ", "), migrationDoc)
		}
		return nil, fmt.Errorf("unknown config key(s): %s", strings.Join(names, ", "))
	}
	cfg.applyDefaults()
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func isRetiredKey(name string) bool {
	if _, ok := retiredTopLevelKeys[name]; ok {
		return true
	}
	for _, suffix := range retiredSuffixes {
		if strings.HasSuffix(name, suffix) {
			return true
		}
	}
	return false
}

func (c *Config) applyDefaults() {
	if c.PIVSlot == "" {
		c.PIVSlot = "9c"
	}
	if c.PINCache == "" {
		c.PINCache = "session"
	}
	if c.NotifyCmd == nil {
		c.NotifyCmd = []string{"notify-send", "pivb"}
	}
	for name, alias := range c.Aliases {
		if alias.Cloud == "" {
			alias.Cloud = "gcp"
		}
		if alias.LifetimeS == 0 {
			alias.LifetimeS = defaultLifetimeS
		}
		if alias.AssertionLifetimeS == 0 {
			alias.AssertionLifetimeS = defaultAssertionLifetimeS
		}
		c.Aliases[name] = alias
	}
}

func (c *Config) Validate() error {
	var errs []error
	fail := func(format string, args ...any) {
		errs = append(errs, fmt.Errorf(format, args...))
	}

	if c.PIVSlot != "9c" {
		fail("config key \"piv_slot\" must be \"9c\", got %q", c.PIVSlot)
	}
	if c.PINCache != "session" && c.PINCache != "never" {
		fail("config key \"pin_cache\" must be \"session\" or \"never\", got %q", c.PINCache)
	}
	if c.GnuPGHome != "" && !filepath.IsAbs(c.GnuPGHome) {
		fail("config key \"gnupg_home\" must be an absolute path when set, got %q", c.GnuPGHome)
	}

	if !projectNumberRE.MatchString(c.WIF.ProjectNumber) {
		fail("config key \"wif.project_number\" must be the nonzero decimal project number (not the project ID), got %q", c.WIF.ProjectNumber)
	}
	if !poolProviderRE.MatchString(c.WIF.PoolID) || strings.HasPrefix(c.WIF.PoolID, "gcp-") {
		fail("config key \"wif.pool_id\" must be 4-32 lowercase letters, digits, or hyphens, start with a letter, end with a letter or digit, and not start with \"gcp-\", got %q", c.WIF.PoolID)
	}
	if !poolProviderRE.MatchString(c.WIF.ProviderID) || strings.HasPrefix(c.WIF.ProviderID, "gcp-") {
		fail("config key \"wif.provider_id\" must be 4-32 lowercase letters, digits, or hyphens, start with a letter, end with a letter or digit, and not start with \"gcp-\", got %q", c.WIF.ProviderID)
	}
	if err := validateIssuerURI(c.WIF.IssuerURI); err != nil {
		fail("config key \"wif.issuer_uri\" %s, got %q", err.Error(), c.WIF.IssuerURI)
	}

	if len(c.Keys) == 0 {
		fail("config key \"keys\" must contain at least one [keys.<serial>] table")
	}
	if len(c.Keys) > wif.MaxJWKSKeys {
		fail("config key \"keys\" contains %d keys; Google accepts at most %d uploaded JWKs per OIDC provider", len(c.Keys), wif.MaxJWKSKeys)
	}
	serialNames := make(map[uint32]string, len(c.Keys))
	kids := make(map[string]string, len(c.Keys))
	for serialName, key := range c.Keys {
		serialValue, err := strconv.ParseUint(serialName, 10, 32)
		if err != nil || serialValue == 0 {
			fail("config key %q must use a positive integer YubiKey serial", "keys."+serialName)
			continue
		}
		serial := uint32(serialValue)
		if previous, exists := serialNames[serial]; exists {
			fail("config keys %q and %q name the same YubiKey serial", "keys."+previous, "keys."+serialName)
		} else {
			serialNames[serial] = serialName
		}
		kid := strings.TrimSpace(key.JWKKid)
		if !jwkKidRE.MatchString(kid) {
			fail("config key %q must be the %d-character unpadded base64url SHA-256 of the key's SubjectPublicKeyInfo (derive it with `pivb wif jwks`)", "keys."+serialName+".jwk_kid", wif.KeyIDLength)
			continue
		}
		if previous, exists := kids[kid]; exists {
			fail("config keys %q and %q contain duplicate jwk_kid %q", "keys."+previous+".jwk_kid", "keys."+serialName+".jwk_kid", kid)
		} else {
			kids[kid] = serialName
		}
	}

	if len(c.Aliases) == 0 {
		fail("config key \"aliases\" must contain at least one alias")
	}
	targets := make(map[string]string, len(c.Aliases))
	for name, alias := range c.Aliases {
		prefix := "aliases." + name
		if !aliasNameRE.MatchString(name) {
			fail("config alias name %q must be 1-32 lowercase letters, digits, or hyphens, starting with a letter and ending with a letter or digit", name)
		}
		if alias.Cloud != "gcp" {
			fail("config key %q uses unsupported cloud %q (only \"gcp\" is implemented)", prefix+".cloud", alias.Cloud)
		}
		if !targetEmailRE.MatchString(alias.Target) {
			fail("config key %q must be a service-account email of the form <name>@<project-id>.iam.gserviceaccount.com, got %q", prefix+".target", alias.Target)
		} else if previous, exists := targets[alias.Target]; exists {
			fail("config keys %q and %q share target %q; give each alias a dedicated target service account", "aliases."+previous+".target", prefix+".target", alias.Target)
		} else {
			targets[alias.Target] = name
		}
		if alias.LifetimeS < minLifetimeS || alias.LifetimeS > maxLifetimeS {
			fail("config key %q must be between %d and %d seconds", prefix+".lifetime_s", minLifetimeS, maxLifetimeS)
		}
		if lifetime, maximum := aliasAssertionLifetimeS(alias), maxAssertionLifetimeSFor(alias); lifetime < minAssertionLifetimeS || lifetime > maximum {
			fail("config key %q must be between %d and %d seconds (the lesser of the %ds ceiling and config key %q, so one touch's assertion never outlives the access token it buys), got %d",
				prefix+".assertion_lifetime_s", minAssertionLifetimeS, maximum, maxAssertionLifetimeS, prefix+".lifetime_s", lifetime)
		}
		if maximum := maxAssertionReuseS(alias); alias.AssertionReuseS < 0 || alias.AssertionReuseS > maximum {
			fail("config key %q must be between 0 and %d seconds (%ds assertion lifetime − %ds iat backdating − %ds minimum remaining validity), got %d",
				prefix+".assertion_reuse_s", maximum, aliasAssertionLifetimeS(alias),
				int(wif.ClockSkew/time.Second), minRemainingValidityS, alias.AssertionReuseS)
		}
	}
	return errors.Join(errs...)
}

// validateIssuerURI enforces an HTTPS issuer with no query, fragment, user
// info, or Google-owned host. The issuer is a durable trust-domain identifier
// even though no metadata endpoint is hosted there. The character allowlist
// matters beyond hygiene: the raw issuer is interpolated into a single-quoted
// CEL attribute condition and into the signed iss claim, so quotes,
// backslashes, percent-escapes, and whitespace are rejected outright rather
// than escaped.
func validateIssuerURI(raw string) error {
	if strings.TrimSpace(raw) == "" {
		return errors.New("is required")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return errors.New("must be a valid URL")
	}
	if u.Scheme != "https" {
		return errors.New("must use https")
	}
	if u.Host == "" || u.Hostname() == "" {
		return errors.New("must include a host")
	}
	if u.User != nil {
		return errors.New("must not include user info")
	}
	if u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.RawFragment != "" {
		return errors.New("must not include a query or fragment")
	}
	for _, r := range raw {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == '.' || r == '_' || r == '~' || r == ':' || r == '/' || r == '-':
		default:
			return fmt.Errorf("must contain only letters, digits, and \".-_~:/\" (found %q)", r)
		}
	}
	host := strings.TrimSuffix(strings.ToLower(u.Hostname()), ".")
	for _, banned := range []string{"google.com", "googleapis.com", "googleusercontent.com", "gstatic.com"} {
		if host == banned || strings.HasSuffix(host, "."+banned) {
			return errors.New("must not be a Google-owned issuer")
		}
	}
	return nil
}

// Provider returns the WIF provider identity for audience derivation.
func (c *Config) Provider() wif.Provider {
	return wif.Provider{
		ProjectNumber: c.WIF.ProjectNumber,
		PoolID:        c.WIF.PoolID,
		ProviderID:    c.WIF.ProviderID,
		IssuerURI:     c.WIF.IssuerURI,
	}
}

// AliasTargets maps every alias name to its target service account, in the
// shape consumed by the provider-condition generator.
func (c *Config) AliasTargets() map[string]string {
	targets := make(map[string]string, len(c.Aliases))
	for name, alias := range c.Aliases {
		targets[name] = alias.Target
	}
	return targets
}

// KeysBySerial returns the enrolled keys keyed by numeric serial.
func (c *Config) KeysBySerial() map[uint32]Key {
	keys := make(map[uint32]Key, len(c.Keys))
	for serialName, key := range c.Keys {
		serial, err := strconv.ParseUint(serialName, 10, 32)
		if err == nil && serial != 0 {
			keys[uint32(serial)] = Key{JWKKid: strings.TrimSpace(key.JWKKid)}
		}
	}
	return keys
}

func (c *Config) YubiKeySerials() []uint32 {
	keys := c.KeysBySerial()
	serials := make([]uint32, 0, len(keys))
	for serial := range keys {
		serials = append(serials, serial)
	}
	sort.Slice(serials, func(i, j int) bool { return serials[i] < serials[j] })
	return serials
}
