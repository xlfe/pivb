package wif

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

// ExecutableTimeoutMillis bounds one credential-source invocation, covering
// PIN handoff, the touch window, and one scdaemon retry.
const ExecutableTimeoutMillis = 30000

const (
	AgentSandboxRoot       = "/run/pivb-agent"
	AgentSessionSocketPath = AgentSandboxRoot + "/session.sock"
	AgentHelperPath        = AgentSandboxRoot + "/pivb-agent-subject-token"
)

// CredentialFileSpec describes one per-alias external-account credential
// file. All values come from validated configuration; the generator never
// accepts a caller-supplied impersonation URL.
type CredentialFileSpec struct {
	Provider        Provider
	Alias           string
	Target          string
	LifetimeSeconds int
	Executable      string
}

// AgentCredentialFileSpec describes the fixed-alias credential generated for
// one ephemeral agent session. The executable and socket paths are a fixed
// sandbox ABI and neither carries an alias selector.
type AgentCredentialFileSpec struct {
	Provider        Provider
	Target          string
	LifetimeSeconds int
}

type executableSource struct {
	Command       string `json:"command"`
	TimeoutMillis int    `json:"timeout_millis"`
}

type credentialSource struct {
	Executable executableSource `json:"executable"`
}

type impersonation struct {
	TokenLifetimeSeconds int `json:"token_lifetime_seconds"`
}

type credentialFile struct {
	Type                           string           `json:"type"`
	Audience                       string           `json:"audience"`
	SubjectTokenType               string           `json:"subject_token_type"`
	TokenURL                       string           `json:"token_url"`
	ServiceAccountImpersonationURL string           `json:"service_account_impersonation_url"`
	ServiceAccountImpersonation    impersonation    `json:"service_account_impersonation"`
	CredentialSource               credentialSource `json:"credential_source"`
}

// CredentialFile renders the external-account JSON for one alias. The file
// contains no secret material, but its command path controls which executable
// receives credential requests, so callers must still write it privately.
func CredentialFile(spec CredentialFileSpec) ([]byte, error) {
	if spec.Alias == "" || spec.Target == "" {
		return nil, errors.New("credential file alias and target are required")
	}
	// The command string is split on spaces by the auth libraries; config
	// grammar already forbids whitespace in aliases, but this generator must
	// fail closed on its own.
	if strings.ContainsFunc(spec.Alias, func(r rune) bool { return r <= 0x20 || r == 0x7f }) {
		return nil, fmt.Errorf("credential alias %q must not contain whitespace or control characters", spec.Alias)
	}
	if err := ValidateExecutablePath(spec.Executable); err != nil {
		return nil, err
	}
	return credentialFileDocument(spec.Provider, spec.Target, spec.LifetimeSeconds,
		spec.Executable+" subject-token --alias "+spec.Alias)
}

// AgentCredentialFile renders the external-account JSON placed into one
// agent-session directory. The helper can reach only the fixed relay socket;
// alias and source identity never appear in its command line.
func AgentCredentialFile(spec AgentCredentialFileSpec) ([]byte, error) {
	if spec.Target == "" {
		return nil, errors.New("agent credential target is required")
	}
	return credentialFileDocument(spec.Provider, spec.Target, spec.LifetimeSeconds,
		AgentHelperPath+" --socket "+AgentSessionSocketPath)
}

func credentialFileDocument(provider Provider, target string, lifetimeSeconds int, command string) ([]byte, error) {
	if lifetimeSeconds < 600 || lifetimeSeconds > 3600 {
		return nil, fmt.Errorf("credential lifetime %ds is outside the supported 600..3600 range", lifetimeSeconds)
	}
	if provider.ProjectNumber == "" || provider.PoolID == "" || provider.ProviderID == "" {
		return nil, errors.New("wif provider is incompletely configured")
	}
	doc := credentialFile{
		Type:             "external_account",
		Audience:         provider.ExternalAccountAudience(),
		SubjectTokenType: TokenType,
		TokenURL:         "https://sts.googleapis.com/v1/token",
		ServiceAccountImpersonationURL: "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/" +
			url.PathEscape(target) + ":generateAccessToken",
		ServiceAccountImpersonation: impersonation{TokenLifetimeSeconds: lifetimeSeconds},
		CredentialSource: credentialSource{
			Executable: executableSource{
				Command:       command,
				TimeoutMillis: ExecutableTimeoutMillis,
			},
		},
	}
	out, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal credential file: %w", err)
	}
	return append(out, '\n'), nil
}

// ValidateExecutablePath enforces the stable installed command contract: an
// absolute path with no whitespace or control characters (the auth libraries
// split the command string on spaces) and no Nix store hash that would break
// on the next rebuild.
func ValidateExecutablePath(path string) error {
	if path == "" {
		return errors.New("executable path is required")
	}
	if !filepath.IsAbs(path) {
		return fmt.Errorf("executable path %q must be absolute", path)
	}
	if strings.ContainsAny(path, " \t\r\n") || strings.ContainsFunc(path, func(r rune) bool { return r < 0x20 || r == 0x7f }) {
		return fmt.Errorf("executable path %q must not contain whitespace or control characters", path)
	}
	if strings.HasPrefix(path, "/nix/store/") {
		return fmt.Errorf("executable path %q is a hashed Nix store path; use a stable installed path such as /run/current-system/sw/bin/pivb", path)
	}
	return nil
}

// WriteCredentialFile writes the rendered credential JSON atomically with
// 0600 permissions, creating missing parent directories as 0700.
func WriteCredentialFile(path string, data []byte) error {
	if !filepath.IsAbs(path) {
		return fmt.Errorf("output path %q must be absolute", path)
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create credential directory: %w", err)
	}
	tmp, err := os.CreateTemp(dir, ".pivb-credential-*")
	if err != nil {
		return fmt.Errorf("create temporary credential file: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return fmt.Errorf("restrict credential file permissions: %w", err)
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("write credential file: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("sync credential file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close credential file: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("install credential file: %w", err)
	}
	return nil
}
