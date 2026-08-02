package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/xlfe/pivb/internal/wif"
)

func certPath(name string) string {
	return filepath.Join("..", "..", "internal", "wif", "testdata", name)
}

// wifConfigTOML renders a fixture config whose [keys.<serial>] tables are the
// given serial/kid pairs.
func wifConfigTOML(keys ...[2]string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "[wif]\nproject_number = \"123456789012\"\npool_id = \"pivb\"\nprovider_id = \"yubikey-piv\"\nissuer_uri = %q\n\n", testIssuerURI)
	for _, key := range keys {
		fmt.Fprintf(&b, "[keys.%s]\njwk_kid = %q\n\n", key[0], key[1])
	}
	fmt.Fprintf(&b, "[aliases.ro]\ntarget = %q\n", testTargetRO)
	return b.String()
}

type jwksDoc struct {
	Keys []struct {
		Kty string `json:"kty"`
		Use string `json:"use"`
		Alg string `json:"alg"`
		Kid string `json:"kid"`
		N   string `json:"n"`
		E   string `json:"e"`
	} `json:"keys"`
}

func TestWIFJWKSOneKey(t *testing.T) {
	var out strings.Builder
	args := []string{"--cert", "12345678=" + certPath("cert-a.pem")}
	if err := wifJWKSCommand(writeConfig(t), args, &out); err != nil {
		t.Fatalf("wif jwks: %v", err)
	}
	var jwks jwksDoc
	if err := json.Unmarshal([]byte(out.String()), &jwks); err != nil {
		t.Fatalf("output is not a JWKS: %v (output %q)", err, out.String())
	}
	if len(jwks.Keys) != 1 {
		t.Fatalf("got %d keys, want 1: %q", len(jwks.Keys), out.String())
	}
	key := jwks.Keys[0]
	if key.Kid != testKidA {
		t.Errorf("kid = %q, want %q", key.Kid, testKidA)
	}
	if key.Kty != "RSA" || key.Use != "sig" || key.Alg != "RS256" {
		t.Errorf("kty/use/alg = %q/%q/%q, want RSA/sig/RS256", key.Kty, key.Use, key.Alg)
	}
	if key.E != "AQAB" || key.N == "" {
		t.Errorf("n/e = %q/%q, want the RSA-2048 modulus and exponent 65537", key.N, key.E)
	}
}

// TestWIFJWKSOrdersBySerial passes the certificates in descending serial order
// to prove the uploaded set is ordered by serial rather than by input order.
func TestWIFJWKSOrdersBySerial(t *testing.T) {
	configPath := writeConfigText(t, wifConfigTOML(
		[2]string{"12345678", testKidA},
		[2]string{"23456789", testKidB},
	))
	args := []string{
		"--cert", "23456789=" + certPath("cert-b.pem"),
		"--cert", "12345678=" + certPath("cert-a.pem"),
	}
	var out strings.Builder
	if err := wifJWKSCommand(configPath, args, &out); err != nil {
		t.Fatalf("wif jwks: %v", err)
	}
	var jwks jwksDoc
	if err := json.Unmarshal([]byte(out.String()), &jwks); err != nil {
		t.Fatalf("output is not a JWKS: %v (output %q)", err, out.String())
	}
	if len(jwks.Keys) != 2 {
		t.Fatalf("got %d keys, want 2: %q", len(jwks.Keys), out.String())
	}
	if jwks.Keys[0].Kid != testKidA || jwks.Keys[1].Kid != testKidB {
		t.Errorf("kids = %q, %q; want %q then %q (serial ascending)",
			jwks.Keys[0].Kid, jwks.Keys[1].Kid, testKidA, testKidB)
	}
}

func TestWIFJWKSErrors(t *testing.T) {
	tests := []struct {
		name   string
		config string
		args   []string
		want   []string
	}{
		{
			name: "no certificates",
			want: []string{"at least one --cert"},
		},
		{
			name: "duplicate serial",
			args: []string{"--cert", "12345678=" + certPath("cert-a.pem"), "--cert", "12345678=" + certPath("cert-b.pem")},
			want: []string{"repeats serial 12345678"},
		},
		{
			name: "missing separator",
			args: []string{"--cert", "12345678"},
			want: []string{"expected <serial>=<pem-path>"},
		},
		{
			name: "empty path",
			args: []string{"--cert", "12345678="},
			want: []string{"expected <serial>=<pem-path>"},
		},
		{
			name: "zero serial",
			args: []string{"--cert", "0=" + certPath("cert-a.pem")},
			want: []string{"must be a positive integer"},
		},
		{
			name: "non-numeric serial",
			args: []string{"--cert", "abc=" + certPath("cert-a.pem")},
			want: []string{"must be a positive integer"},
		},
		{
			name: "unreadable certificate",
			args: []string{"--cert", "12345678=" + certPath("cert-missing.pem")},
			want: []string{"read certificate for YubiKey 12345678"},
		},
		{
			name:   "configured kid mismatch",
			config: wifConfigTOML([2]string{"12345678", testKidB}),
			args:   []string{"--cert", "12345678=" + certPath("cert-a.pem")},
			want:   []string{testKidA, testKidB},
		},
		{
			name: "serial not configured",
			args: []string{"--cert", "23456789=" + certPath("cert-b.pem")},
			want: []string{"[keys.23456789]", testKidB},
		},
		{
			name:   "configured serial has no certificate",
			config: wifConfigTOML([2]string{"12345678", testKidA}, [2]string{"23456789", testKidB}),
			args:   []string{"--cert", "12345678=" + certPath("cert-a.pem")},
			want:   []string{"revoke", "23456789"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			configPath := writeConfig(t)
			if tt.config != "" {
				configPath = writeConfigText(t, tt.config)
			}
			var out strings.Builder
			err := wifJWKSCommand(configPath, tt.args, &out)
			if err == nil {
				t.Fatalf("wif jwks succeeded, want an error (output %q)", out.String())
			}
			for _, want := range tt.want {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("error %q does not mention %q", err, want)
				}
			}
			if out.String() != "" {
				t.Errorf("stdout = %q, want nothing written for a rejected key set", out.String())
			}
		})
	}
}

type credentialDoc struct {
	Type                           string `json:"type"`
	Audience                       string `json:"audience"`
	SubjectTokenType               string `json:"subject_token_type"`
	TokenURL                       string `json:"token_url"`
	ServiceAccountImpersonationURL string `json:"service_account_impersonation_url"`
	ServiceAccountImpersonation    struct {
		TokenLifetimeSeconds int `json:"token_lifetime_seconds"`
	} `json:"service_account_impersonation"`
	CredentialSource struct {
		Executable struct {
			Command       string `json:"command"`
			TimeoutMillis int    `json:"timeout_millis"`
		} `json:"executable"`
	} `json:"credential_source"`
}

func TestWIFCredentials(t *testing.T) {
	const executable = "/usr/local/bin/pivb"
	output := filepath.Join(t.TempDir(), "creds", "ro.json")
	var out strings.Builder
	args := []string{"--alias", "ro", "--output", output, "--executable", executable}
	if err := wifCredentialsCommand(writeConfig(t), args, &out); err != nil {
		t.Fatalf("wif credentials: %v", err)
	}

	data, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	var doc credentialDoc
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("credential file is not JSON: %v (%q)", err, data)
	}
	if doc.Type != "external_account" {
		t.Errorf("type = %q, want external_account", doc.Type)
	}
	if doc.Audience != testAudience {
		t.Errorf("audience = %q, want %q", doc.Audience, testAudience)
	}
	if doc.SubjectTokenType != wif.TokenType {
		t.Errorf("subject_token_type = %q, want %q", doc.SubjectTokenType, wif.TokenType)
	}
	if doc.TokenURL != "https://sts.googleapis.com/v1/token" {
		t.Errorf("token_url = %q", doc.TokenURL)
	}
	wantImpersonation := "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/" + testTargetRO + ":generateAccessToken"
	if doc.ServiceAccountImpersonationURL != wantImpersonation {
		t.Errorf("service_account_impersonation_url = %q, want %q", doc.ServiceAccountImpersonationURL, wantImpersonation)
	}
	if doc.ServiceAccountImpersonation.TokenLifetimeSeconds != 3600 {
		t.Errorf("token_lifetime_seconds = %d, want 3600", doc.ServiceAccountImpersonation.TokenLifetimeSeconds)
	}
	wantCommand := executable + " subject-token --alias ro"
	if doc.CredentialSource.Executable.Command != wantCommand {
		t.Errorf("command = %q, want %q", doc.CredentialSource.Executable.Command, wantCommand)
	}
	if doc.CredentialSource.Executable.TimeoutMillis != 30000 {
		t.Errorf("timeout_millis = %d, want 30000", doc.CredentialSource.Executable.TimeoutMillis)
	}

	info, err := os.Stat(output)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("credential file mode = %#o, want 0600", perm)
	}
	for _, want := range []string{output, `"ro"`, testTargetRO} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("stdout %q does not mention %q", out.String(), want)
		}
	}
}

func TestWIFCredentialsErrors(t *testing.T) {
	tests := []struct {
		name string
		args func(output string) []string
		want string
	}{
		{
			name: "missing output and executable",
			args: func(string) []string { return []string{"--alias", "ro"} },
			want: "usage: pivb wif credentials",
		},
		{
			name: "missing alias",
			args: func(output string) []string {
				return []string{"--output", output, "--executable", "/usr/local/bin/pivb"}
			},
			want: "usage: pivb wif credentials",
		},
		{
			name: "unknown alias",
			args: func(output string) []string {
				return []string{"--alias", "nosuch", "--output", output, "--executable", "/usr/local/bin/pivb"}
			},
			want: `alias "nosuch" is not configured`,
		},
		{
			name: "relative executable",
			args: func(output string) []string {
				return []string{"--alias", "ro", "--output", output, "--executable", "pivb"}
			},
			want: "must be absolute",
		},
		{
			name: "nix store executable",
			args: func(output string) []string {
				return []string{"--alias", "ro", "--output", output, "--executable", "/nix/store/0000000000000000000000000000000a-pivb/bin/pivb"}
			},
			want: "Nix store path",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			output := filepath.Join(t.TempDir(), "ro.json")
			var out strings.Builder
			err := wifCredentialsCommand(writeConfig(t), tt.args(output), &out)
			if err == nil {
				t.Fatalf("wif credentials succeeded, want an error")
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Errorf("error %q does not mention %q", err, tt.want)
			}
			if _, statErr := os.Stat(output); !os.IsNotExist(statErr) {
				t.Errorf("credential file %s exists after a rejected invocation", output)
			}
			if out.String() != "" {
				t.Errorf("stdout = %q, want nothing on failure", out.String())
			}
		})
	}
}

func TestWIFProviderCondition(t *testing.T) {
	var out strings.Builder
	if err := wifProviderConditionCommand(writeConfig(t), nil, &out); err != nil {
		t.Fatalf("wif provider-condition: %v", err)
	}
	got := out.String()
	want := []string{
		"# provider resource\n" + testProviderResource + "\n",
		"# external-account audience (credential files, STS)\n" + testAudience + "\n",
		"# OIDC audience (assertion aud claim)\n" + testOIDCAudience + "\n",
		"# issuer\n" + testIssuerURI + "\n",
		"# gcloud --attribute-mapping\ngoogle.subject=assertion.sub,attribute.alias=assertion.alias,attribute.target=assertion.target,attribute.serial=assertion.serial,attribute.key_id=assertion.key_id\n",
		"assertion.iss == '" + testIssuerURI + "'",
		"assertion.aud == '" + testOIDCAudience + "'",
		"assertion.sub.startsWith('pivb-key:')",
		"(assertion.alias == 'ro' && assertion.target == '" + testTargetRO + "')",
	}
	for _, section := range want {
		if !strings.Contains(got, section) {
			t.Errorf("output does not contain %q\n---\n%s", section, got)
		}
	}
}

func TestWIFProviderConditionRejectsPositionalArgs(t *testing.T) {
	var out strings.Builder
	err := wifProviderConditionCommand(writeConfig(t), []string{"extra"}, &out)
	if err == nil || !strings.Contains(err.Error(), "no positional arguments") {
		t.Fatalf("error = %v, want a positional-argument rejection", err)
	}
}

func TestWIFCommandDispatch(t *testing.T) {
	configPath := writeConfig(t)

	err := wifCommand(configPath, nil)
	if err == nil || !strings.Contains(err.Error(), "usage: pivb wif <jwks|credentials|provider-condition>") {
		t.Errorf("no-argument error = %v, want the wif usage line", err)
	}

	err = wifCommand(configPath, []string{"sign"})
	if err == nil || !strings.Contains(err.Error(), `unknown wif subcommand "sign"`) {
		t.Errorf("unknown subcommand error = %v", err)
	}
}
