package wif_test

import (
	"encoding/json"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/xlfe/pivb/internal/wif"
)

const testExecutable = "/run/current-system/sw/bin/pivb"

// impersonationPrefix is the fixed part of the generateAccessToken URL; the
// target email is the single path segment between it and the suffix.
const impersonationPrefix = "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/"

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

func testSpec() wif.CredentialFileSpec {
	return wif.CredentialFileSpec{
		Provider:        testProvider,
		Alias:           "ro",
		Target:          testTarget,
		LifetimeSeconds: 3600,
		Executable:      testExecutable,
	}
}

func TestCredentialFileGolden(t *testing.T) {
	raw, err := wif.CredentialFile(testSpec())
	if err != nil {
		t.Fatalf("CredentialFile: %v", err)
	}
	if !strings.HasSuffix(string(raw), "\n") {
		t.Errorf("credential file does not end with a newline")
	}

	// output_file would make the auth library cache subject tokens on disk;
	// pivb deliberately omits it so every request re-authorizes.
	if strings.Contains(string(raw), "output_file") {
		t.Errorf("credential file mentions output_file:\n%s", raw)
	}

	var got credentialDoc
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("unmarshal credential file: %v", err)
	}

	// url.PathEscape leaves "@" and ":" unescaped in a path segment, so the
	// email appears verbatim; this is the form Google's own docs use.
	wantImpersonation := impersonationPrefix + testTarget + ":generateAccessToken"

	for _, f := range []struct{ name, got, want string }{
		{"type", got.Type, "external_account"},
		{"audience", got.Audience, testExternalAud},
		{"subject_token_type", got.SubjectTokenType, "urn:ietf:params:oauth:token-type:id_token"},
		{"token_url", got.TokenURL, "https://sts.googleapis.com/v1/token"},
		{"service_account_impersonation_url", got.ServiceAccountImpersonationURL, wantImpersonation},
		{"command", got.CredentialSource.Executable.Command, testExecutable + " subject-token --alias ro"},
	} {
		if f.got != f.want {
			t.Errorf("%s =\n %q\nwant\n %q", f.name, f.got, f.want)
		}
	}
	if got.SubjectTokenType != wif.TokenType {
		t.Errorf("subject_token_type %q does not match wif.TokenType %q", got.SubjectTokenType, wif.TokenType)
	}
	if got.ServiceAccountImpersonation.TokenLifetimeSeconds != 3600 {
		t.Errorf("token_lifetime_seconds = %d, want 3600", got.ServiceAccountImpersonation.TokenLifetimeSeconds)
	}
	if got.CredentialSource.Executable.TimeoutMillis != 30000 {
		t.Errorf("timeout_millis = %d, want 30000", got.CredentialSource.Executable.TimeoutMillis)
	}

	segment := strings.TrimSuffix(strings.TrimPrefix(got.ServiceAccountImpersonationURL, impersonationPrefix), ":generateAccessToken")
	decoded, err := url.PathUnescape(segment)
	if err != nil {
		t.Fatalf("unescape target segment %q: %v", segment, err)
	}
	if decoded != testTarget {
		t.Errorf("target segment decodes to %q, want %q", decoded, testTarget)
	}
}

func TestCredentialFileEscapesTargetSegment(t *testing.T) {
	// A target carrying separators must stay inside one path segment rather
	// than redirecting the impersonation call to another resource.
	spec := testSpec()
	spec.Target = "evil/../../v1/projects/-/serviceAccounts/other@example.com"

	raw, err := wif.CredentialFile(spec)
	if err != nil {
		t.Fatalf("CredentialFile: %v", err)
	}
	var got credentialDoc
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("unmarshal credential file: %v", err)
	}
	segment := strings.TrimSuffix(strings.TrimPrefix(got.ServiceAccountImpersonationURL, impersonationPrefix), ":generateAccessToken")
	if strings.Contains(segment, "/") {
		t.Fatalf("target escaped its path segment: %q", got.ServiceAccountImpersonationURL)
	}
	if decoded, err := url.PathUnescape(segment); err != nil || decoded != spec.Target {
		t.Fatalf("segment %q decodes to %q (err %v), want %q", segment, decoded, err, spec.Target)
	}
}

func TestCredentialFileRejects(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*wif.CredentialFileSpec)
		want   string
	}{
		{"lifetime below floor", func(s *wif.CredentialFileSpec) { s.LifetimeSeconds = 599 }, "600..3600"},
		{"lifetime above ceiling", func(s *wif.CredentialFileSpec) { s.LifetimeSeconds = 3601 }, "600..3600"},
		{"zero lifetime", func(s *wif.CredentialFileSpec) { s.LifetimeSeconds = 0 }, "600..3600"},
		{"no alias", func(s *wif.CredentialFileSpec) { s.Alias = "" }, "alias and target are required"},
		{"no target", func(s *wif.CredentialFileSpec) { s.Target = "" }, "alias and target are required"},
		{"relative executable", func(s *wif.CredentialFileSpec) { s.Executable = "pivb" }, "must be absolute"},
		{"incomplete provider", func(s *wif.CredentialFileSpec) { s.Provider.PoolID = "" }, "incompletely configured"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			spec := testSpec()
			tc.mutate(&spec)
			raw, err := wif.CredentialFile(spec)
			if raw != nil {
				t.Errorf("expected no output on failure, got:\n%s", raw)
			}
			requireErrorContains(t, err, tc.want)
		})
	}

	t.Run("lifetime bounds are inclusive", func(t *testing.T) {
		for _, seconds := range []int{600, 3600} {
			spec := testSpec()
			spec.LifetimeSeconds = seconds
			if _, err := wif.CredentialFile(spec); err != nil {
				t.Errorf("lifetime %d rejected: %v", seconds, err)
			}
		}
	})
}

func TestValidateExecutablePath(t *testing.T) {
	tests := []struct {
		name string
		path string
		want string // empty means the path must be accepted
	}{
		{"empty", "", "required"},
		{"relative", "relative/pivb", "must be absolute"},
		{"space", "/a b/pivb", "whitespace or control characters"},
		{"tab", "/a\tb", "whitespace or control characters"},
		{"newline", "/a\nb/pivb", "whitespace or control characters"},
		{"control character", "/a\x01b/pivb", "whitespace or control characters"},
		{"delete character", "/a\x7fb/pivb", "whitespace or control characters"},
		{"nix store path", "/nix/store/abc-pivb/bin/pivb", "stable installed path"},
		{"stable path", "/run/current-system/sw/bin/pivb", ""},
		{"home path", "/home/user/.local/bin/pivb", ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := wif.ValidateExecutablePath(tc.path)
			if tc.want == "" {
				if err != nil {
					t.Fatalf("ValidateExecutablePath(%q) = %v, want nil", tc.path, err)
				}
				return
			}
			requireErrorContains(t, err, tc.want)
		})
	}
}

func TestWriteCredentialFile(t *testing.T) {
	data, err := wif.CredentialFile(testSpec())
	if err != nil {
		t.Fatalf("CredentialFile: %v", err)
	}

	t.Run("creates private parents", func(t *testing.T) {
		root := t.TempDir()
		dir := filepath.Join(root, "nested", "deeper")
		path := filepath.Join(dir, "readonly.json")

		if err := wif.WriteCredentialFile(path, data); err != nil {
			t.Fatalf("WriteCredentialFile: %v", err)
		}

		info, err := os.Stat(path)
		if err != nil {
			t.Fatalf("stat credential file: %v", err)
		}
		if perm := info.Mode().Perm(); perm != 0o600 {
			t.Errorf("credential file mode = %04o, want 0600", perm)
		}
		for _, d := range []string{dir, filepath.Join(root, "nested")} {
			di, err := os.Stat(d)
			if err != nil {
				t.Fatalf("stat %s: %v", d, err)
			}
			if perm := di.Mode().Perm(); perm != 0o700 {
				t.Errorf("directory %s mode = %04o, want 0700", d, perm)
			}
		}
		got, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read credential file: %v", err)
		}
		if string(got) != string(data) {
			t.Errorf("written content differs from the rendered credential file")
		}
	})

	t.Run("overwrites in place", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "readonly.json")
		if err := wif.WriteCredentialFile(path, []byte("stale\n")); err != nil {
			t.Fatalf("first write: %v", err)
		}
		if err := wif.WriteCredentialFile(path, data); err != nil {
			t.Fatalf("second write: %v", err)
		}

		got, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read credential file: %v", err)
		}
		if string(got) != string(data) {
			t.Errorf("content was not replaced:\n%s", got)
		}
		info, err := os.Stat(path)
		if err != nil {
			t.Fatalf("stat credential file: %v", err)
		}
		if perm := info.Mode().Perm(); perm != 0o600 {
			t.Errorf("credential file mode = %04o, want 0600", perm)
		}

		// The atomic rename must not leave temporary files behind.
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatalf("read dir: %v", err)
		}
		if len(entries) != 1 || entries[0].Name() != "readonly.json" {
			names := make([]string, 0, len(entries))
			for _, e := range entries {
				names = append(names, e.Name())
			}
			t.Errorf("directory contains %v, want only readonly.json", names)
		}
	})

	t.Run("rejects relative paths", func(t *testing.T) {
		err := wif.WriteCredentialFile(filepath.Join("relative", "readonly.json"), data)
		requireErrorContains(t, err, "must be absolute")
	})
}
