package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/xlfe/pivb/internal/attachment"
	"github.com/xlfe/pivb/internal/core"
	"github.com/xlfe/pivb/internal/uds"
	"github.com/xlfe/pivb/internal/wif"
	"github.com/xlfe/pivb/internal/wifapi"
)

// Shared fixture values. testKidA and testKidB are the key IDs derived from
// internal/wif/testdata/cert-a.pem and cert-b.pem.
const (
	testSerialA          = 12345678
	testKidA             = "g4tW--9GFcDvwdryp8vTG76EyUg-QhfOEjBo0YQg3Wg"
	testKidB             = "klDBeSjlLGunctWm3FyntSOcV9bk3MZ9pNbuDxn_E-I"
	testTargetRO         = "readonly-sa@example-project-id.iam.gserviceaccount.com"
	testIssuerURI        = "https://auth.example.net/pivb/dep1"
	testProviderResource = "projects/123456789012/locations/global/workloadIdentityPools/pivb/providers/yubikey-piv"
	testAudience         = "//iam.googleapis.com/" + testProviderResource
	testOIDCAudience     = "https://iam.googleapis.com/" + testProviderResource
)

const testConfigTOML = `[wif]
project_number = "123456789012"
pool_id = "pivb"
provider_id = "yubikey-piv"
issuer_uri = "https://auth.example.net/pivb/dep1"

[keys.12345678]
jwk_kid = "g4tW--9GFcDvwdryp8vTG76EyUg-QhfOEjBo0YQg3Wg"

[aliases.ro]
target = "readonly-sa@example-project-id.iam.gserviceaccount.com"
`

// writeConfig writes the standard single-key, single-alias fixture config.
func writeConfig(t *testing.T) string {
	t.Helper()
	return writeConfigText(t, testConfigTOML)
}

func writeConfigText(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// fakeWIFCore stands in for the daemon behind the signing socket.
type fakeWIFCore struct {
	mu       sync.Mutex
	requests []core.SubjectTokenRequest
	result   core.SubjectTokenResult
	err      error
}

func (f *fakeWIFCore) SubjectToken(_ context.Context, req core.SubjectTokenRequest) (core.SubjectTokenResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.requests = append(f.requests, req)
	return f.result, f.err
}

func (f *fakeWIFCore) received() []core.SubjectTokenRequest {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]core.SubjectTokenRequest(nil), f.requests...)
}

// wifHandler builds the real signing API around a fake core, with logging
// discarded so daemon-side warnings do not pollute test output.
func wifHandler(fake *fakeWIFCore) http.Handler {
	api := &wifapi.API{Core: fake, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	return api.Handler()
}

// tripwireHandler fails the test if the daemon is contacted at all.
func tripwireHandler(t *testing.T) http.Handler {
	t.Helper()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("daemon was contacted (%s %s); this request must fail before reaching the socket", r.Method, r.URL.Path)
		http.Error(w, "unexpected request", http.StatusTeapot)
	})
}

// startWIFServer serves handler on a short-lived Unix socket and returns its
// path. The socket is torn down when the test finishes.
func startWIFServer(t *testing.T, handler http.Handler) string {
	t.Helper()
	socket := filepath.Join(t.TempDir(), "wif.sock")
	if len(socket) >= 100 {
		t.Fatalf("socket path %q is %d bytes; sockaddr_un cannot hold it", socket, len(socket))
	}
	ctx, cancel := context.WithCancel(context.Background())
	served := make(chan error, 1)
	go func() { served <- uds.Serve(ctx, socket, handler) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-served:
			if err != nil {
				t.Errorf("uds.Serve(%q) = %v", socket, err)
			}
		case <-time.After(5 * time.Second):
			t.Errorf("uds.Serve(%q) did not return after cancellation", socket)
		}
	})
	deadline := time.Now().Add(5 * time.Second)
	for {
		conn, err := net.DialTimeout("unix", socket, 200*time.Millisecond)
		if err == nil {
			conn.Close()
			return socket
		}
		if time.Now().After(deadline) {
			t.Fatalf("socket %q never accepted a connection: %v", socket, err)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// pythonSubjectTokenEnv is the environment Google Auth Python supplies to the
// source executable while service-account impersonation is active. It omits
// the impersonated email and output file.
func pythonSubjectTokenEnv() map[string]string {
	return map[string]string{
		envTokenType: wif.TokenType,
		envAudience:  testAudience,
	}
}

// emailPresentSubjectTokenEnv represents clients that supply the optional
// impersonated-email tripwire.
func emailPresentSubjectTokenEnv() map[string]string {
	env := pythonSubjectTokenEnv()
	env[envImpersonatedEmail] = testTargetRO
	return env
}

func envWith(mutate func(map[string]string)) map[string]string {
	env := pythonSubjectTokenEnv()
	mutate(env)
	return env
}

// runSubjectToken invokes the command with a fully specified protocol
// environment. Missing map keys are explicitly unset so ambient state cannot
// leak into cases that exercise an omitted variable. t.Setenv registers the
// original value for restoration and prevents use from parallel tests.
func runSubjectToken(t *testing.T, configPath, wifSocket string, args []string, env map[string]string) (string, string, error) {
	t.Helper()
	for _, name := range []string{
		envTokenType, envAudience, envImpersonatedEmail, envOutputFile,
		attachment.EnvMode, attachment.EnvRouteSocket, attachment.EnvProtocol,
	} {
		if value, present := env[name]; present {
			t.Setenv(name, value)
			continue
		}
		t.Setenv(name, "")
		if err := os.Unsetenv(name); err != nil {
			t.Fatalf("unset %s: %v", name, err)
		}
	}
	var stdout, stderr strings.Builder
	err := subjectTokenCommand(configPath, wifSocket, args, &stdout, &stderr)
	return stdout.String(), stderr.String(), err
}

// decodeOneJSON asserts the protocol requirement that stdout carries exactly
// one JSON document, and returns it.
func decodeOneJSON(t *testing.T, stdout string) map[string]any {
	t.Helper()
	dec := json.NewDecoder(strings.NewReader(stdout))
	var doc map[string]any
	if err := dec.Decode(&doc); err != nil {
		t.Fatalf("stdout is not a JSON document: %v (stdout %q)", err, stdout)
	}
	if err := dec.Decode(new(json.RawMessage)); !errors.Is(err, io.EOF) {
		t.Fatalf("stdout must carry exactly one JSON document, got %q", stdout)
	}
	return doc
}

// assertProtocolError checks the shared shape of every failure document.
func assertProtocolError(t *testing.T, stdout string, err error, wantCode string) map[string]any {
	t.Helper()
	if !errors.Is(err, errReported) {
		t.Fatalf("error = %v, want errReported so main exits nonzero without printing more", err)
	}
	doc := decodeOneJSON(t, stdout)
	if doc["version"] != float64(1) {
		t.Errorf("version = %v, want 1", doc["version"])
	}
	if doc["success"] != false {
		t.Errorf("success = %v, want false", doc["success"])
	}
	if doc["code"] != wantCode {
		t.Errorf("code = %v, want %q (document %v)", doc["code"], wantCode, doc)
	}
	if message, ok := doc["message"].(string); !ok || message == "" {
		t.Errorf("message = %v, want a nonempty explanation", doc["message"])
	}
	return doc
}

func TestSubjectTokenSuccess(t *testing.T) {
	tests := []struct {
		name string
		env  map[string]string
	}{
		{name: "email omitted", env: pythonSubjectTokenEnv()},
		{name: "email matches", env: emailPresentSubjectTokenEnv()},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fake := &fakeWIFCore{result: core.SubjectTokenResult{
				IDToken:   "h.p.s",
				ExpiresAt: time.Unix(1785585870, 0),
				Serial:    testSerialA,
				KeyID:     testKidA,
			}}
			socket := startWIFServer(t, wifHandler(fake))

			stdout, stderr, err := runSubjectToken(t, writeConfig(t), socket, []string{"--alias", "ro"}, tt.env)
			if err != nil {
				t.Fatalf("subject-token failed: %v (stderr %q)", err, stderr)
			}
			want := map[string]any{
				"version":         float64(1),
				"success":         true,
				"token_type":      wif.TokenType,
				"id_token":        "h.p.s",
				"expiration_time": float64(1785585870),
			}
			if got := decodeOneJSON(t, stdout); !reflect.DeepEqual(got, want) {
				t.Errorf("success document = %v, want %v", got, want)
			}
			if stderr != "" {
				t.Errorf("stderr = %q, want nothing on success", stderr)
			}

			got := fake.received()
			if len(got) != 1 {
				t.Fatalf("daemon received %d requests, want 1", len(got))
			}
			wantReq := core.SubjectTokenRequest{
				Alias:                   "ro",
				ExternalAccountAudience: testAudience,
				ImpersonatedEmail:       testTargetRO,
				Attachment:              attachment.LocalAllowed(),
			}
			if !reflect.DeepEqual(got[0], wantReq) {
				t.Errorf("daemon received %+v, want configured target %+v", got[0], wantReq)
			}
		})
	}
}

func TestSubjectTokenProtocolOnePreservesRouteRequiredPolicy(t *testing.T) {
	fake := &fakeWIFCore{result: core.SubjectTokenResult{
		IDToken: "h.p.s", ExpiresAt: time.Unix(1785585870, 0), Serial: testSerialA, KeyID: testKidA,
	}}
	socket := startWIFServer(t, wifHandler(fake))
	env := pythonSubjectTokenEnv()
	env[attachment.EnvMode] = attachment.ModeRouteRequired
	env[attachment.EnvProtocol] = "1"
	env[attachment.EnvRouteSocket] = "/run/user/1000/zka/pivb/workspace.sock"

	stdout, stderr, err := runSubjectToken(t, writeConfig(t), socket, []string{"--alias", "ro"}, env)
	if err != nil || stderr != "" || decodeOneJSON(t, stdout)["success"] != true {
		t.Fatalf("protocol-1 subject-token = err=%v stderr=%q stdout=%q", err, stderr, stdout)
	}
	got := fake.received()
	if len(got) != 1 || !got[0].Attachment.RouteRequired() || got[0].Attachment.Protocol != attachment.ProtocolEnvironment ||
		got[0].Attachment.RouteSocket != env[attachment.EnvRouteSocket] {
		t.Fatalf("trusted WIF request lost attachment policy: %#v", got)
	}
}

func TestSubjectTokenManagedPolicyFailsBeforeLocalWIF(t *testing.T) {
	configPath := writeConfig(t)
	tests := []struct {
		name string
		env  map[string]string
		code string
	}{
		{
			name: "partial protocol one",
			env: envWith(func(env map[string]string) {
				env[attachment.EnvMode] = attachment.ModeRouteRequired
				env[attachment.EnvProtocol] = "1"
			}),
			code: wifapi.CodeRouteRequired,
		},
		{
			name: "unsupported protocol two",
			env: envWith(func(env map[string]string) {
				env[attachment.EnvMode] = attachment.ModeRouteRequired
				env[attachment.EnvProtocol] = "2"
				env[attachment.EnvRouteSocket] = "/run/pivb-route-does-not-exist.sock"
			}),
			code: wifapi.CodeRouteRequired,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			stdout, _, err := runSubjectToken(t, configPath, "/run/local-wif-must-not-be-used.sock", []string{"--alias", "ro"}, test.env)
			assertProtocolError(t, stdout, err, test.code)
		})
	}
}

// TestSubjectTokenEnvRejections covers every invocation that must be refused
// before the daemon is contacted. The tripwire handler fails the test if any
// case reaches the socket.
func TestSubjectTokenEnvRejections(t *testing.T) {
	socket := startWIFServer(t, tripwireHandler(t))
	configPath := writeConfig(t)

	tests := []struct {
		name       string
		args       []string
		env        map[string]string
		socket     string
		wantStderr string
	}{
		{
			name:       "no alias",
			args:       nil,
			env:        pythonSubjectTokenEnv(),
			wantStderr: "--alias is required",
		},
		{
			name:       "positional arg",
			args:       []string{"--alias", "ro", "extra"},
			env:        pythonSubjectTokenEnv(),
			wantStderr: "no positional arguments",
		},
		{
			name:       "unknown flag",
			args:       []string{"--alias", "ro", "--bogus"},
			env:        pythonSubjectTokenEnv(),
			wantStderr: "not defined",
		},
		{
			name:       "token type unset",
			args:       []string{"--alias", "ro"},
			env:        envWith(func(env map[string]string) { delete(env, envTokenType) }),
			wantStderr: envTokenType,
		},
		{
			name:       "token type jwt",
			args:       []string{"--alias", "ro"},
			env:        envWith(func(env map[string]string) { env[envTokenType] = "urn:ietf:params:oauth:token-type:jwt" }),
			wantStderr: "only issues",
		},
		{
			name: "audience mismatch",
			args: []string{"--alias", "ro"},
			env: envWith(func(env map[string]string) {
				env[envAudience] = "//iam.googleapis.com/projects/999/locations/global/workloadIdentityPools/other/providers/other"
			}),
			wantStderr: "pivb wif credentials",
		},
		{
			name: "impersonation present empty",
			args: []string{"--alias", "ro"},
			env: envWith(func(env map[string]string) {
				env[envImpersonatedEmail] = ""
			}),
			wantStderr: "pivb wif credentials",
		},
		{
			name: "impersonation mismatch",
			args: []string{"--alias", "ro"},
			env: envWith(func(env map[string]string) {
				env[envImpersonatedEmail] = "attacker-sa@example-project-id.iam.gserviceaccount.com"
			}),
			wantStderr: "pivb wif credentials",
		},
		{
			name:       "output file set",
			args:       []string{"--alias", "ro"},
			env:        envWith(func(env map[string]string) { env[envOutputFile] = "/tmp/pivb-cached-token.json" }),
			wantStderr: "remove output_file",
		},
		{
			name:       "output file present empty",
			args:       []string{"--alias", "ro"},
			env:        envWith(func(env map[string]string) { env[envOutputFile] = "" }),
			wantStderr: "remove output_file",
		},
		{
			name:       "no socket",
			args:       []string{"--alias", "ro"},
			env:        pythonSubjectTokenEnv(),
			socket:     "-",
			wantStderr: "XDG_RUNTIME_DIR",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// "-" selects the empty socket parameter; the zero value means
			// "use the tripwire socket".
			useSocket := socket
			if tt.socket == "-" {
				useSocket = ""
			}
			stdout, stderr, err := runSubjectToken(t, configPath, useSocket, tt.args, tt.env)
			assertProtocolError(t, stdout, err, wifapi.CodeEnv)
			if !strings.Contains(stderr, tt.wantStderr) {
				t.Errorf("stderr = %q, want it to mention %q", stderr, tt.wantStderr)
			}
		})
	}
}

func TestSubjectTokenConfigErrors(t *testing.T) {
	socket := startWIFServer(t, tripwireHandler(t))

	t.Run("no config", func(t *testing.T) {
		missing := filepath.Join(t.TempDir(), "absent.toml")
		stdout, _, err := runSubjectToken(t, missing, socket, []string{"--alias", "ro"}, pythonSubjectTokenEnv())
		assertProtocolError(t, stdout, err, wifapi.CodeConfig)
	})

	t.Run("unknown alias", func(t *testing.T) {
		stdout, _, err := runSubjectToken(t, writeConfig(t), socket, []string{"--alias", "nosuch"}, pythonSubjectTokenEnv())
		doc := assertProtocolError(t, stdout, err, wifapi.CodeConfig)
		if message, _ := doc["message"].(string); !strings.Contains(message, `"nosuch"`) {
			t.Errorf("message = %q, want it to name the missing alias", message)
		}
	})
}

func TestSubjectTokenDaemonUnavailable(t *testing.T) {
	socket := filepath.Join(t.TempDir(), "absent.sock")
	stdout, stderr, err := runSubjectToken(t, writeConfig(t), socket, []string{"--alias", "ro"}, pythonSubjectTokenEnv())
	assertProtocolError(t, stdout, err, wifapi.CodeUnavailable)
	if !strings.Contains(stderr, "systemctl --user start pivb") {
		t.Errorf("stderr = %q, want the daemon start remedy", stderr)
	}
}

func TestSubjectTokenDaemonErrorPassthrough(t *testing.T) {
	fake := &fakeWIFCore{err: core.ErrLocked}
	socket := startWIFServer(t, wifHandler(fake))

	stdout, stderr, err := runSubjectToken(t, writeConfig(t), socket, []string{"--alias", "ro"}, pythonSubjectTokenEnv())
	doc := assertProtocolError(t, stdout, err, wifapi.CodeLocked)
	if message, _ := doc["message"].(string); !strings.Contains(message, "unlock") {
		t.Errorf("message = %q, want it to point at `pivb unlock`", message)
	}
	if !strings.Contains(stderr, "remedy: run `pivb unlock` on the trusted host") {
		t.Errorf("stderr = %q, want the daemon remedy", stderr)
	}
}

func TestSubjectTokenMalformedDaemonToken(t *testing.T) {
	fake := &fakeWIFCore{result: core.SubjectTokenResult{
		IDToken:   "no-dots-here",
		ExpiresAt: time.Unix(1785585870, 0),
	}}
	socket := startWIFServer(t, wifHandler(fake))

	stdout, _, err := runSubjectToken(t, writeConfig(t), socket, []string{"--alias", "ro"}, pythonSubjectTokenEnv())
	assertProtocolError(t, stdout, err, wifapi.CodeInternal)
}
