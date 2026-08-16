package config

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

const (
	kidA = "g4tW--9GFcDvwdryp8vTG76EyUg-QhfOEjBo0YQg3Wg"
	kidB = "klDBeSjlLGunctWm3FyntSOcV9bk3MZ9pNbuDxn_E-I"

	baseIssuer   = "https://auth.example.net/pivb/dep1"
	baseTarget   = "readonly-sa@example-project-id.iam.gserviceaccount.com"
	baseResource = "projects/123456789012/locations/global/workloadIdentityPools/pivb/providers/yubikey-piv"
)

// The valid configuration is composed from independent sections so a test can
// drop a whole section (no keys, no aliases), repeat one (a second key or
// alias table), or rewrite a single line without restating the rest.
const (
	baseGlobals = `piv_slot = "9c"
pin_cache = "session"
notify_cmd = ["notify-send", "pivb"]
`
	baseWIF = `
[wif]
project_number = "123456789012"
pool_id = "pivb"
provider_id = "yubikey-piv"
issuer_uri = "` + baseIssuer + `"
`
	baseKeys = `
[keys.12345678]
jwk_kid = "` + kidA + `"
`
	baseAliases = `
[aliases.ro]
cloud = "gcp"
target = "` + baseTarget + `"
lifetime_s = 3600
`
)

func baseConfig() string { return baseGlobals + baseWIF + baseKeys + baseAliases }

// withGlobal adds one top-level line, which TOML requires to precede every
// table header.
func withGlobal(line string) string {
	return baseGlobals + line + "\n" + baseWIF + baseKeys + baseAliases
}

// withKeyLine adds one line to [keys.12345678].
func withKeyLine(line string) string {
	return baseGlobals + baseWIF + baseKeys + line + "\n" + baseAliases
}

// withAliasLine adds one line to [aliases.ro], the final table.
func withAliasLine(line string) string { return baseConfig() + line + "\n" }

// keyTables renders n [keys.<serial>] tables with distinct serials and kids.
func keyTables(n int) string {
	var b strings.Builder
	for i := 0; i < n; i++ {
		fmt.Fprintf(&b, "\n[keys.%d]\njwk_kid = %q\n", 10000001+i, fmt.Sprintf("%043d", i))
	}
	return b.String()
}

// aliasTable renders one [aliases.<name>] table.
func aliasTable(name, target string) string {
	return fmt.Sprintf("\n[aliases.%s]\ncloud = \"gcp\"\ntarget = %q\nlifetime_s = 3600\n", name, target)
}

// setValue replaces the sole "<key> = ..." line in src with a TOML literal.
func setValue(t testing.TB, src, key, literal string) string {
	t.Helper()
	prefix := key + " = "
	lines := strings.Split(src, "\n")
	found := -1
	for i, line := range lines {
		if !strings.HasPrefix(line, prefix) {
			continue
		}
		if found >= 0 {
			t.Fatalf("config key %q appears more than once in the base config", key)
		}
		found = i
	}
	if found < 0 {
		t.Fatalf("config key %q is absent from the base config", key)
	}
	lines[found] = prefix + literal
	return strings.Join(lines, "\n")
}

// setString is setValue with a quoted string value.
func setString(t testing.TB, src, key, value string) string {
	t.Helper()
	return setValue(t, src, key, strconv.Quote(value))
}

// setTable rewrites the sole occurrence of a table header.
func setTable(t testing.TB, src, oldHeader, newHeader string) string {
	t.Helper()
	if got := strings.Count(src, oldHeader); got != 1 {
		t.Fatalf("table header %q appears %d times, want exactly 1", oldHeader, got)
	}
	return strings.Replace(src, oldHeader, newHeader, 1)
}

func loadFrom(t *testing.T, content string) (*Config, error) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return Load(path)
}

// loadError requires the configuration to be rejected and returns the message.
func loadError(t *testing.T, content string) string {
	t.Helper()
	cfg, err := loadFrom(t, content)
	if err == nil {
		t.Fatalf("Load succeeded, want error; config:\n%s", content)
	}
	if cfg != nil {
		t.Errorf("Load returned a config alongside error: %v", err)
	}
	return err.Error()
}

func wantSubstrings(t *testing.T, got string, want ...string) {
	t.Helper()
	for _, w := range want {
		if !strings.Contains(got, w) {
			t.Errorf("error does not contain %q\ngot: %s", w, got)
		}
	}
}

func rejectSubstrings(t *testing.T, got string, unwanted ...string) {
	t.Helper()
	for _, w := range unwanted {
		if strings.Contains(got, w) {
			t.Errorf("error unexpectedly contains %q\ngot: %s", w, got)
		}
	}
}

// loadCase is one rejected configuration and the substrings its error must
// name, always including the offending config key path.
type loadCase struct {
	name string
	toml string
	want []string
}

func runRejections(t *testing.T, cases []loadCase) {
	t.Helper()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			wantSubstrings(t, loadError(t, tc.toml), tc.want...)
		})
	}
}

func TestLoadValidConfig(t *testing.T) {
	cfg, err := loadFrom(t, baseConfig())
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if cfg.PIVSlot != "9c" {
		t.Errorf("PIVSlot = %q, want %q", cfg.PIVSlot, "9c")
	}
	if cfg.PINCache != "session" {
		t.Errorf("PINCache = %q, want %q", cfg.PINCache, "session")
	}
	if want := []string{"notify-send", "pivb"}; !reflect.DeepEqual(cfg.NotifyCmd, want) {
		t.Errorf("NotifyCmd = %q, want %q", cfg.NotifyCmd, want)
	}
	if cfg.GnuPGHome != "" {
		t.Errorf("GnuPGHome = %q, want empty default", cfg.GnuPGHome)
	}
	if cfg.WIF.ProjectNumber != "123456789012" {
		t.Errorf("WIF.ProjectNumber = %q, want %q", cfg.WIF.ProjectNumber, "123456789012")
	}
	if cfg.WIF.PoolID != "pivb" || cfg.WIF.ProviderID != "yubikey-piv" {
		t.Errorf("WIF pool/provider = %q/%q, want %q/%q", cfg.WIF.PoolID, cfg.WIF.ProviderID, "pivb", "yubikey-piv")
	}
	if cfg.WIF.IssuerURI != baseIssuer {
		t.Errorf("WIF.IssuerURI = %q, want %q", cfg.WIF.IssuerURI, baseIssuer)
	}

	provider := cfg.Provider()
	if got := provider.Resource(); got != baseResource {
		t.Errorf("Resource() = %q, want %q", got, baseResource)
	}
	if got, want := provider.ExternalAccountAudience(), "//iam.googleapis.com/"+baseResource; got != want {
		t.Errorf("ExternalAccountAudience() = %q, want %q", got, want)
	}
	if got, want := provider.OIDCAudience(), "https://iam.googleapis.com/"+baseResource; got != want {
		t.Errorf("OIDCAudience() = %q, want %q", got, want)
	}
	if provider.IssuerURI != baseIssuer {
		t.Errorf("Provider().IssuerURI = %q, want %q", provider.IssuerURI, baseIssuer)
	}

	if got, want := cfg.KeysBySerial(), map[uint32]Key{12345678: {JWKKid: kidA}}; !reflect.DeepEqual(got, want) {
		t.Errorf("KeysBySerial() = %v, want %v", got, want)
	}
	if got, want := cfg.YubiKeySerials(), []uint32{12345678}; !reflect.DeepEqual(got, want) {
		t.Errorf("YubiKeySerials() = %v, want %v", got, want)
	}
	if got, want := cfg.AliasTargets(), map[string]string{"ro": baseTarget}; !reflect.DeepEqual(got, want) {
		t.Errorf("AliasTargets() = %v, want %v", got, want)
	}

	alias, ok := cfg.Aliases["ro"]
	if !ok {
		t.Fatalf("alias %q is missing from %v", "ro", cfg.Aliases)
	}
	if alias.Cloud != "gcp" || alias.Target != baseTarget || alias.LifetimeS != 3600 {
		t.Errorf("alias ro = %+v, want cloud gcp, target %q, lifetime 3600", alias, baseTarget)
	}
}

func TestLoadAppliesDefaults(t *testing.T) {
	minimal := baseWIF + baseKeys + "\n[aliases.ro]\ntarget = \"" + baseTarget + "\"\n"
	cfg, err := loadFrom(t, minimal)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.PIVSlot != "9c" {
		t.Errorf("default PIVSlot = %q, want %q", cfg.PIVSlot, "9c")
	}
	if cfg.PINCache != "session" {
		t.Errorf("default PINCache = %q, want %q", cfg.PINCache, "session")
	}
	if want := []string{"notify-send", "pivb"}; !reflect.DeepEqual(cfg.NotifyCmd, want) {
		t.Errorf("default NotifyCmd = %q, want %q", cfg.NotifyCmd, want)
	}
	if cfg.GnuPGHome != "" {
		t.Errorf("default GnuPGHome = %q, want empty (environment/default resolved lazily)", cfg.GnuPGHome)
	}
	if got := cfg.Aliases["ro"].Cloud; got != "gcp" {
		t.Errorf("default alias cloud = %q, want %q", got, "gcp")
	}
	if got := cfg.Aliases["ro"].LifetimeS; got != defaultLifetimeS {
		t.Errorf("default alias lifetime_s = %d, want %d", got, defaultLifetimeS)
	}
}

func TestLoadRejectsRelativeGnuPGHomeButDoesNotRequireItToExist(t *testing.T) {
	wantSubstrings(t, loadError(t, withGlobal(`gnupg_home = "relative/home"`)), "gnupg_home", "absolute")
	cfg, err := loadFrom(t, withGlobal(`gnupg_home = "/path/that/need/not/be/mounted/yet"`))
	if err != nil {
		t.Fatalf("lazy GnuPG home validation rejected missing path: %v", err)
	}
	if cfg.GnuPGHome != "/path/that/need/not/be/mounted/yet" {
		t.Fatalf("GnuPGHome = %q", cfg.GnuPGHome)
	}
}

func TestLoadRejectsRetiredKeys(t *testing.T) {
	tests := []struct {
		name string
		toml string
		key  string
	}{
		{"listen_metadata", withGlobal(`listen_metadata = "127.0.0.1:8642"`), "listen_metadata"},
		{"default_alias", withGlobal(`default_alias = "ro"`), "default_alias"},
		{"remote_allowed_aliases", withGlobal(`remote_allowed_aliases = ["ro"]`), "remote_allowed_aliases"},
		// The single-key schema that preceded the broker fleet put these at the
		// top level rather than inside a [keys.<serial>] table.
		{"top-level broker_sa", withGlobal(`broker_sa = "x@example-project-id.iam.gserviceaccount.com"`), "broker_sa"},
		{"top-level key_id", withGlobal(`key_id = "abc"`), "key_id"},
		{"top-level yubikey_serials", withGlobal(`yubikey_serials = [12345678]`), "yubikey_serials"},
		{"keys broker_sa", withKeyLine(`broker_sa = "x@example-project-id.iam.gserviceaccount.com"`), "keys.12345678.broker_sa"},
		{"keys key_id", withKeyLine(`key_id = "abc"`), "keys.12345678.key_id"},
		{"aliases project_id", withAliasLine(`project_id = "p"`), "aliases.ro.project_id"},
		{"aliases numeric_project_id", withAliasLine(`numeric_project_id = "123"`), "aliases.ro.numeric_project_id"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := loadError(t, tc.toml)
			wantSubstrings(t, got, "README.md", tc.key)
			rejectSubstrings(t, got, "unknown config key(s)")
		})
	}
}

func TestLoadRejectsUnknownKey(t *testing.T) {
	got := loadError(t, withGlobal("frobnicate = 1"))
	wantSubstrings(t, got, "unknown config key(s)", "frobnicate")
	rejectSubstrings(t, got, "README.md")
}

func TestLoadRejectsInvalidGlobals(t *testing.T) {
	runRejections(t, []loadCase{
		{"piv_slot 9a", setString(t, baseConfig(), "piv_slot", "9a"), []string{`"piv_slot"`, "9a"}},
		{"pin_cache always", setString(t, baseConfig(), "pin_cache", "always"), []string{`"pin_cache"`, "always"}},
	})
}

func TestLoadRejectsInvalidProjectNumber(t *testing.T) {
	cases := make([]loadCase, 0, 6)
	for _, tc := range []struct{ name, value string }{
		{"empty", ""},
		{"zero", "0"},
		{"leading zero", "0123"},
		{"letters", "abc"},
		{"project id", "example-project-id"},
		{"31 digits", strings.Repeat("9", 31)},
	} {
		cases = append(cases, loadCase{
			name: tc.name,
			toml: setString(t, baseConfig(), "project_number", tc.value),
			want: []string{`"wif.project_number"`},
		})
	}
	runRejections(t, cases)
}

func TestLoadRejectsInvalidPoolAndProvider(t *testing.T) {
	var cases []loadCase
	for _, tc := range []struct{ name, value string }{
		{"too short", "abc"},
		{"uppercase", "Pool"},
		{"gcp prefix", "gcp-pool"},
		{"trailing hyphen", "pool-"},
		{"leading hyphen", "-pool"},
		{"33 chars", strings.Repeat("a", 33)},
	} {
		cases = append(cases, loadCase{
			name: "pool_id " + tc.name,
			toml: setString(t, baseConfig(), "pool_id", tc.value),
			want: []string{`"wif.pool_id"`},
		})
	}
	// The provider ID shares the pool grammar; spot-check both rejection paths.
	cases = append(cases,
		loadCase{"provider_id uppercase", setString(t, baseConfig(), "provider_id", "Provider"), []string{`"wif.provider_id"`}},
		loadCase{"provider_id gcp prefix", setString(t, baseConfig(), "provider_id", "gcp-provider"), []string{`"wif.provider_id"`}},
	)
	runRejections(t, cases)
}

func TestLoadRejectsInvalidIssuerURI(t *testing.T) {
	var cases []loadCase
	for _, tc := range []struct{ name, value, reason string }{
		{"empty", "", "is required"},
		{"http", "http://auth.example.net/x", "must use https"},
		{"query", "https://auth.example.net/x?a=b", "must not include a query or fragment"},
		{"empty forced query", "https://auth.example.net/x?", "must not include a query or fragment"},
		{"fragment", "https://auth.example.net/x#f", "must not include a query or fragment"},
		{"unparseable", "https://auth.example.net/%zz", "must be a valid URL"},
		{"user info", "https://user@auth.example.net/x", "must not include user info"},
		{"accounts.google.com", "https://accounts.google.com/x", "must not be a Google-owned issuer"},
		{"sts.googleapis.com", "https://sts.googleapis.com/x", "must not be a Google-owned issuer"},
		{"foo.googleapis.com", "https://foo.googleapis.com/x", "must not be a Google-owned issuer"},
		{"google.com", "https://google.com/x", "must not be a Google-owned issuer"},
		{"evil.google.com", "https://evil.google.com/x", "must not be a Google-owned issuer"},
		{"trailing-dot googleapis", "https://sts.googleapis.com./x", "must not be a Google-owned issuer"},
		{"no host", "https://", "must include a host"},
		// The raw issuer is interpolated into a single-quoted CEL condition
		// and the signed iss claim; the charset allowlist keeps quoting,
		// escaping, and percent-decoding ambiguity out of both.
		{"single quote in path", "https://auth.example.net/x'-or-true", "must contain only letters, digits"},
		{"backslash in path", `https://auth.example.net/x\y`, "must contain only letters, digits"},
		{"space in path", "https://auth.example.net/x y", "must contain only letters, digits"},
		{"percent escape in path", "https://auth.example.net/x%27y", "must contain only letters, digits"},
	} {
		cases = append(cases, loadCase{
			name: tc.name,
			toml: setString(t, baseConfig(), "issuer_uri", tc.value),
			want: []string{`"wif.issuer_uri"`, tc.reason},
		})
	}
	runRejections(t, cases)
}

func TestLoadRejectsInvalidKeys(t *testing.T) {
	withSerial := func(serial string) string {
		return setTable(t, baseConfig(), "[keys.12345678]", "[keys."+serial+"]")
	}
	setKid := func(kid string) string {
		return setString(t, baseConfig(), "jwk_kid", kid)
	}
	duplicateKid := baseGlobals + baseWIF + baseKeys +
		"\n[keys.87654321]\njwk_kid = \"" + kidA + "\"\n" + baseAliases
	duplicateSerial := baseGlobals + baseWIF + baseKeys +
		"\n[keys.0012345678]\njwk_kid = \"" + kidB + "\"\n" + baseAliases

	runRejections(t, []loadCase{
		{"no keys table", baseGlobals + baseWIF + baseAliases, []string{`"keys"`, "at least one"}},
		{"nine keys", baseGlobals + baseWIF + keyTables(9) + baseAliases, []string{`"keys"`, "at most 8"}},
		{"serial zero", withSerial("0"), []string{`"keys.0"`, "positive integer"}},
		{"serial not a number", withSerial("notanumber"), []string{`"keys.notanumber"`, "positive integer"}},
		{"serial overflows uint32", withSerial("99999999999"), []string{`"keys.99999999999"`, "positive integer"}},
		{"duplicate jwk_kid", duplicateKid, []string{"duplicate jwk_kid", kidA}},
		{"duplicate serial", duplicateSerial, []string{"same YubiKey serial", "keys.12345678"}},
		{"kid too short", setKid(kidA[:42]), []string{`"keys.12345678.jwk_kid"`}},
		{"kid with padding", setKid(kidA[:42] + "="), []string{`"keys.12345678.jwk_kid"`}},
		{"kid with plus", setKid(strings.Repeat("a", 42) + "+"), []string{`"keys.12345678.jwk_kid"`}},
		{"kid with slash", setKid(strings.Repeat("a", 42) + "/"), []string{`"keys.12345678.jwk_kid"`}},
		{"kid empty", setKid(""), []string{`"keys.12345678.jwk_kid"`}},
	})
}

func TestLoadRejectsInvalidAliases(t *testing.T) {
	withName := func(name string) string {
		return setTable(t, baseConfig(), "[aliases.ro]", "[aliases."+name+"]")
	}
	setTarget := func(target string) string {
		return setString(t, baseConfig(), "target", target)
	}
	sharedTarget := baseConfig() + aliasTable("rw", baseTarget)

	runRejections(t, []loadCase{
		{"no aliases", baseGlobals + baseWIF + baseKeys, []string{`"aliases"`, "at least one"}},
		{"name uppercase", withName("RO"), []string{"alias name", `"RO"`}},
		{"name leading digit", withName("9ro"), []string{"alias name", `"9ro"`}},
		{"name trailing hyphen", withName("ro-"), []string{"alias name", `"ro-"`}},
		{"name 33 chars", withName(strings.Repeat("a", 33)), []string{"alias name", strings.Repeat("a", 33)}},
		{"cloud aws", setString(t, baseConfig(), "cloud", "aws"), []string{`"aliases.ro.cloud"`, "aws"}},
		{"target not an email", setTarget("not-an-email"), []string{`"aliases.ro.target"`}},
		{"target parts too short", setTarget("x@y.iam.gserviceaccount.com"), []string{`"aliases.ro.target"`}},
		{"target uppercase", setTarget("Readonly-SA@example-project-id.iam.gserviceaccount.com"), []string{`"aliases.ro.target"`}},
		{"target wrong domain", setTarget("sa@example.com"), []string{`"aliases.ro.target"`}},
		{"shared target", sharedTarget, []string{"dedicated target service account", baseTarget}},
		{"lifetime 599", setValue(t, baseConfig(), "lifetime_s", "599"), []string{`"aliases.ro.lifetime_s"`}},
		{"lifetime 3601", setValue(t, baseConfig(), "lifetime_s", "3601"), []string{`"aliases.ro.lifetime_s"`}},
		{
			"assertion reuse one second past the bound",
			withAliasLine("assertion_reuse_s = 211"),
			// The message has to show the operator where 210 comes from, not
			// just assert it.
			[]string{`"aliases.ro.assertion_reuse_s"`, "between 0 and 210 seconds",
				"300s assertion lifetime", "30s iat backdating", "60s minimum remaining validity", "got 211"},
		},
		{
			"assertion reuse negative",
			withAliasLine("assertion_reuse_s = -1"),
			[]string{`"aliases.ro.assertion_reuse_s"`, "got -1"},
		},
	})
}

// TestAssertionReuseBounds pins both edges of the consent window an alias may
// buy with one touch, and the default that buys none.
func TestAssertionReuseBounds(t *testing.T) {
	for _, tc := range []struct {
		name string
		toml string
		want int
	}{
		{"absent", baseConfig(), 0},
		{"zero", withAliasLine("assertion_reuse_s = 0"), 0},
		{"one second", withAliasLine("assertion_reuse_s = 1"), 1},
		{"the whole bound", withAliasLine("assertion_reuse_s = 210"), 210},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := loadFrom(t, tc.toml)
			if err != nil {
				t.Fatalf("Load rejected a valid reuse window: %v", err)
			}
			if got := cfg.Aliases["ro"].AssertionReuseS; got != tc.want {
				t.Errorf("assertion_reuse_s = %d, want %d", got, tc.want)
			}
		})
	}
}

// TestLoadAcceptsGrammarBoundaries pins the accepting edge of each grammar so
// a tightened regexp cannot silently reject a valid deployment.
func TestLoadAcceptsGrammarBoundaries(t *testing.T) {
	tests := []struct {
		name string
		toml string
	}{
		{"pin_cache never", setString(t, baseConfig(), "pin_cache", "never")},
		{"alias name two chars", setTable(t, baseConfig(), "[aliases.ro]", "[aliases.ab]")},
		{"alias name 32 chars", setTable(t, baseConfig(), "[aliases.ro]", "[aliases."+strings.Repeat("a", 32)+"]")},
		{"target six-char local part", setString(t, baseConfig(), "target", "abcdef@example-project-id.iam.gserviceaccount.com")},
		{"target 30-char local part", setString(t, baseConfig(), "target", strings.Repeat("a", 30)+"@example-project-id.iam.gserviceaccount.com")},
		{"pool_id four chars", setString(t, baseConfig(), "pool_id", "abcd")},
		{"pool_id 32 chars", setString(t, baseConfig(), "pool_id", strings.Repeat("a", 32))},
		{"project_number 30 digits", setString(t, baseConfig(), "project_number", strings.Repeat("9", 30))},
		{"issuer with bare host", setString(t, baseConfig(), "issuer_uri", "https://auth.example.net")},
		{"issuer with google in path", setString(t, baseConfig(), "issuer_uri", "https://auth.example.net/google.com")},
		{"lifetime 600", setValue(t, baseConfig(), "lifetime_s", "600")},
		{"lifetime 3600", setValue(t, baseConfig(), "lifetime_s", "3600")},
		{"eight keys", baseGlobals + baseWIF + keyTables(8) + baseAliases},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := loadFrom(t, tc.toml); err != nil {
				t.Fatalf("Load rejected a valid config: %v\n%s", err, tc.toml)
			}
		})
	}
}

func TestYubiKeySerialsAreSorted(t *testing.T) {
	keys := "\n[keys.30000003]\njwk_kid = \"" + fmt.Sprintf("%043d", 3) + "\"\n" +
		"\n[keys.10000001]\njwk_kid = \"" + fmt.Sprintf("%043d", 1) + "\"\n" +
		"\n[keys.20000002]\njwk_kid = \"" + fmt.Sprintf("%043d", 2) + "\"\n"
	cfg, err := loadFrom(t, baseGlobals+baseWIF+keys+baseAliases)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got, want := cfg.YubiKeySerials(), []uint32{10000001, 20000002, 30000003}; !reflect.DeepEqual(got, want) {
		t.Errorf("YubiKeySerials() = %v, want %v", got, want)
	}
}

// TestValidateReportsEveryViolation checks that validation accumulates through
// errors.Join instead of stopping at the first bad value.
func TestValidateReportsEveryViolation(t *testing.T) {
	tests := []struct {
		name string
		toml string
		want []string
	}{
		{
			name: "two globals",
			toml: setString(t, setString(t, baseConfig(), "piv_slot", "9a"), "pin_cache", "always"),
			want: []string{`"piv_slot"`, `"pin_cache"`},
		},
		{
			name: "across sections",
			toml: setString(t, setString(t, baseConfig(), "pool_id", "Pool"), "target", "not-an-email"),
			want: []string{`"wif.pool_id"`, `"aliases.ro.target"`},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := loadFrom(t, tc.toml)
			if err == nil {
				t.Fatalf("Load succeeded, want error")
			}
			wantSubstrings(t, err.Error(), tc.want...)
			joined, ok := err.(interface{ Unwrap() []error })
			if !ok {
				t.Fatalf("error %T is not a joined error", err)
			}
			if got := len(joined.Unwrap()); got != 2 {
				t.Errorf("joined error holds %d errors, want 2: %v", got, err)
			}
		})
	}
}

func TestLoadFileErrors(t *testing.T) {
	t.Run("missing file", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "absent.toml")
		_, err := Load(path)
		if err == nil {
			t.Fatalf("Load(%q) succeeded, want error", path)
		}
		wantSubstrings(t, err.Error(), path)
	})

	t.Run("malformed toml", func(t *testing.T) {
		content := baseConfig() + "\n[aliases.rw\n"
		cfg, err := loadFrom(t, content)
		if err == nil {
			t.Fatalf("Load succeeded on malformed TOML: %+v", cfg)
		}
		wantSubstrings(t, err.Error(), "parse config")
	})
}

func TestDefaultPath(t *testing.T) {
	t.Run("xdg config home", func(t *testing.T) {
		t.Setenv("XDG_CONFIG_HOME", "/xdg")
		got, err := DefaultPath()
		if err != nil {
			t.Fatalf("DefaultPath: %v", err)
		}
		if want := "/xdg/pivb/config.toml"; got != want {
			t.Errorf("DefaultPath() = %q, want %q", got, want)
		}
	})

	t.Run("home fallback", func(t *testing.T) {
		t.Setenv("XDG_CONFIG_HOME", "")
		t.Setenv("HOME", "/home/pivb-test")
		got, err := DefaultPath()
		if err != nil {
			t.Fatalf("DefaultPath: %v", err)
		}
		if want := "/home/pivb-test/.config/pivb/config.toml"; got != want {
			t.Errorf("DefaultPath() = %q, want %q", got, want)
		}
	})

	t.Run("no home", func(t *testing.T) {
		t.Setenv("XDG_CONFIG_HOME", "")
		t.Setenv("HOME", "")
		got, err := DefaultPath()
		if err == nil {
			t.Fatalf("DefaultPath() = %q, want error", got)
		}
		wantSubstrings(t, err.Error(), "resolve config home")
	})
}
