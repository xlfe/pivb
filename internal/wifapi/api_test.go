package wifapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/xlfe/pivb/internal/attachment"
	"github.com/xlfe/pivb/internal/core"
	"github.com/xlfe/pivb/internal/pivsigner"
	"github.com/xlfe/pivb/internal/tokenapi"
	"github.com/xlfe/pivb/internal/uds"
)

const (
	testToken  = "h.p.s"
	testExpiry = int64(1785585870)
)

// fakeCore is the daemon seam under full test control. It records the request
// it was handed so tests can assert the API forwards it verbatim.
type fakeCore struct {
	subjectToken func(context.Context, core.SubjectTokenRequest) (core.SubjectTokenResult, error)
	got          core.SubjectTokenRequest
	calls        int
}

func (f *fakeCore) SubjectToken(ctx context.Context, req core.SubjectTokenRequest) (core.SubjectTokenResult, error) {
	f.calls++
	f.got = req
	if f.subjectToken == nil {
		return core.SubjectTokenResult{}, errors.New("fakeCore.subjectToken was not set")
	}
	return f.subjectToken(ctx, req)
}

func successResult() core.SubjectTokenResult {
	return core.SubjectTokenResult{
		IDToken:   testToken,
		ExpiresAt: time.Unix(testExpiry, 0),
		Serial:    12345678,
		KeyID:     "kid",
	}
}

func okCore() *fakeCore {
	return &fakeCore{subjectToken: func(context.Context, core.SubjectTokenRequest) (core.SubjectTokenResult, error) {
		return successResult(), nil
	}}
}

func failingCore(err error) *fakeCore {
	return &fakeCore{subjectToken: func(context.Context, core.SubjectTokenRequest) (core.SubjectTokenResult, error) {
		return core.SubjectTokenResult{}, err
	}}
}

// quietAPI keeps expected-failure tests from spamming the default logger.
func quietAPI(c Core) *API {
	return &API{Core: c, Logger: slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil))}
}

func validRequestBody() string {
	return `{"alias":"ro","external_account_audience":"//iam.googleapis.com/projects/123456789012/locations/global/workloadIdentityPools/pivb-pool/providers/pivb-provider","impersonated_email":"readonly-sa@example-project-id.iam.gserviceaccount.com"}`
}

func post(t *testing.T, h http.Handler, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/v1/subject-token", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// TestSubjectTokenSuccess pins the response shape: the token, its expiry, and
// nothing else. An extra field here would be a credential-surface regression.
func TestSubjectTokenSuccess(t *testing.T) {
	api := quietAPI(okCore())
	rec := post(t, api.Handler(), validRequestBody())

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body %q)", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("Content-Type"); got != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", got)
	}

	dec := json.NewDecoder(bytes.NewReader(rec.Body.Bytes()))
	dec.UseNumber()
	var body map[string]any
	if err := dec.Decode(&body); err != nil {
		t.Fatalf("decode %q: %v", rec.Body.String(), err)
	}
	if len(body) != 2 {
		t.Fatalf("response has %d fields (%v), want exactly id_token and expiration_time", len(body), body)
	}
	if body["id_token"] != testToken {
		t.Errorf("id_token = %v, want %q", body["id_token"], testToken)
	}
	exp, ok := body["expiration_time"].(json.Number)
	if !ok {
		t.Fatalf("expiration_time = %T, want a JSON number", body["expiration_time"])
	}
	if exp.String() != "1785585870" {
		t.Errorf("expiration_time = %s, want 1785585870", exp)
	}
}

func TestSubjectTokenForwardsRequestVerbatim(t *testing.T) {
	fake := okCore()
	rec := post(t, quietAPI(fake).Handler(), validRequestBody())
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body %q)", rec.Code, rec.Body.String())
	}
	if fake.calls != 1 {
		t.Fatalf("Core.SubjectToken called %d times, want 1", fake.calls)
	}
	want := core.SubjectTokenRequest{
		Alias:                   "ro",
		ExternalAccountAudience: "//iam.googleapis.com/projects/123456789012/locations/global/workloadIdentityPools/pivb-pool/providers/pivb-provider",
		ImpersonatedEmail:       "readonly-sa@example-project-id.iam.gserviceaccount.com",
		Attachment:              attachment.LocalAllowed(),
	}
	if !reflect.DeepEqual(fake.got, want) {
		t.Errorf("core request = %+v, want %+v", fake.got, want)
	}
}

func TestSubjectTokenRejectsRelativeTrustedRoute(t *testing.T) {
	fake := okCore()
	body := strings.TrimSuffix(validRequestBody(), "}") + `,"route_socket":"relative.sock","route_required":true}`
	rec := post(t, quietAPI(fake).Handler(), body)
	if rec.Code != http.StatusBadRequest || fake.calls != 0 || !strings.Contains(rec.Body.String(), "absolute") {
		t.Fatalf("relative route response = %d %q, calls=%d", rec.Code, rec.Body.String(), fake.calls)
	}
}

func TestSubjectTokenPreservesRouteRequiredPolicy(t *testing.T) {
	fake := okCore()
	body := strings.TrimSuffix(validRequestBody(), "}") + `,"route_socket":"/run/user/1000/zka/pivb/workspace.sock","route_required":true}`
	rec := post(t, quietAPI(fake).Handler(), body)
	if rec.Code != http.StatusOK || fake.calls != 1 {
		t.Fatalf("route-required response = %d %q, calls=%d", rec.Code, rec.Body.String(), fake.calls)
	}
	if !fake.got.Attachment.RouteRequired() || fake.got.Attachment.Protocol != attachment.ProtocolEnvironment ||
		fake.got.Attachment.RouteSocket != "/run/user/1000/zka/pivb/workspace.sock" {
		t.Fatalf("core request lost route-required policy: %#v", fake.got)
	}
}

func TestSubjectTokenRejectsRouteWithoutRequiredMarker(t *testing.T) {
	fake := okCore()
	body := strings.TrimSuffix(validRequestBody(), "}") + `,"route_socket":"/run/user/1000/zka/pivb/workspace.sock"}`
	rec := post(t, quietAPI(fake).Handler(), body)
	if rec.Code != http.StatusBadRequest || fake.calls != 0 || !strings.Contains(rec.Body.String(), CodeRouteRequired) {
		t.Fatalf("unmarked route response = %d %q, calls=%d", rec.Code, rec.Body.String(), fake.calls)
	}
}

func TestSubjectTokenForwardsAgentSourceContext(t *testing.T) {
	fake := okCore()
	body := `{"alias":"ro","external_account_audience":"//iam.googleapis.com/projects/123456789012/locations/global/workloadIdentityPools/pivb-pool/providers/pivb-provider","impersonated_email":"readonly-sa@example-project-id.iam.gserviceaccount.com","request_source":{"kind":"agent-session","label":"codex:agentic/ro","session_id":"0123456789abcdef0123456789abcdef"}}`
	rec := post(t, quietAPI(fake).Handler(), body)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body %q", rec.Code, rec.Body.String())
	}
	if fake.got.RequestSource.Kind != "agent-session" || fake.got.RequestSource.Label != "codex:agentic/ro" || fake.got.RequestSource.SessionID == "" {
		t.Fatalf("core source = %+v", fake.got.RequestSource)
	}
}

func TestSubjectTokenErrorMapping(t *testing.T) {
	tests := []struct {
		name       string
		err        error
		wantStatus int
		wantCode   string
		wantRemedy string
	}{
		{
			name:       "locked",
			err:        core.ErrLocked,
			wantStatus: http.StatusConflict,
			wantCode:   CodeLocked,
		},
		{
			name:       "wrapped locked",
			err:        fmt.Errorf("mint subject token: %w", core.ErrLocked),
			wantStatus: http.StatusConflict,
			wantCode:   CodeLocked,
		},
		{
			name:       "locked lookalike is not unwrapped by text",
			err:        errors.New("mint: " + core.ErrLocked.Error()),
			wantStatus: http.StatusBadGateway,
			wantCode:   CodeSign,
		},
		{
			name:       "unknown alias",
			err:        &core.UnknownAliasError{Alias: "x"},
			wantStatus: http.StatusBadRequest,
			wantCode:   CodeConfig,
		},
		{
			name:       "request mismatch",
			err:        &core.RequestMismatchError{Field: "external_account_audience", Got: "bad", Want: "good"},
			wantStatus: http.StatusForbidden,
			wantCode:   CodeConfig,
		},
		{
			name:       "invalid request source",
			err:        &core.RequestSourceError{Err: errors.New("unsafe label")},
			wantStatus: http.StatusBadRequest,
			wantCode:   CodeConfig,
		},
		{
			name:       "PIN failure",
			err:        &pivsigner.PINError{Retries: 2, Err: errors.New("wrong"), Remedy: "run pivb unlock"},
			wantStatus: http.StatusConflict,
			wantCode:   CodePIN,
			wantRemedy: "run pivb unlock",
		},
		{
			name:       "PIN failure without remedy",
			err:        &pivsigner.PINError{Retries: 2, Err: errors.New("wrong")},
			wantStatus: http.StatusConflict,
			wantCode:   CodePIN,
		},
		{
			name:       "signing failure",
			err:        errors.New("touch timeout"),
			wantStatus: http.StatusBadGateway,
			wantCode:   CodeSign,
		},
		{
			name:       "smart card contention",
			err:        errors.New("open smart card: SCARD_E_SHARING_VIOLATION 0x8010000b"),
			wantStatus: http.StatusServiceUnavailable,
			wantCode:   CodeSign,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rec := post(t, quietAPI(failingCore(tc.err)).Handler(), validRequestBody())
			if rec.Code != tc.wantStatus {
				t.Errorf("status = %d, want %d (body %q)", rec.Code, tc.wantStatus, rec.Body.String())
			}
			if got := rec.Header().Get("Content-Type"); got != "application/json" {
				t.Errorf("Content-Type = %q, want application/json", got)
			}
			var body errorResponse
			if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
				t.Fatalf("decode %q: %v", rec.Body.String(), err)
			}
			if body.Code != tc.wantCode {
				t.Errorf("code = %q, want %q", body.Code, tc.wantCode)
			}
			if body.Error == "" {
				t.Error("error field is empty")
			}
			if body.Remedy == "" {
				t.Error("remedy field is empty; every rejection must tell the caller what to do")
			}
			if tc.wantRemedy != "" && body.Remedy != tc.wantRemedy {
				t.Errorf("remedy = %q, want the error's own remedy %q", body.Remedy, tc.wantRemedy)
			}
		})
	}
}

func TestSecurityRelevantForwardingFailureIsLoggedAsError(t *testing.T) {
	var journal bytes.Buffer
	api := &API{
		Core: failingCore(&tokenapi.APIError{
			Status: http.StatusBadGateway, Code: tokenapi.CodeConfig,
			Message: "forwarded assertion signature is invalid", Remedy: "inspect the route", SecurityRelevant: true,
		}),
		Logger: slog.New(slog.NewTextHandler(&journal, nil)),
	}
	rec := post(t, api.Handler(), validRequestBody())
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusBadGateway)
	}
	logged := journal.String()
	if !strings.Contains(logged, "level=ERROR") || !strings.Contains(logged, "failed a security check") {
		t.Fatalf("security rejection log = %q", logged)
	}
}

func TestSubjectTokenMalformedRequests(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{"empty body", ""},
		{"invalid JSON", `{"alias":`},
		{"unknown field", `{"alias":"ro","extra":1}`},
		{"two JSON documents", `{"alias":"ro"}{}`},
		{"wrong field type", `{"alias":42}`},
		{"array body", `[{"alias":"ro"}]`},
		{"oversized body", `{"alias":"` + strings.Repeat("a", 5000) + `"}`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			fake := okCore()
			rec := post(t, quietAPI(fake).Handler(), tc.body)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400 (body %q)", rec.Code, rec.Body.String())
			}
			var body errorResponse
			if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
				t.Fatalf("decode %q: %v", rec.Body.String(), err)
			}
			if body.Code != CodeConfig {
				t.Errorf("code = %q, want %q", body.Code, CodeConfig)
			}
			if body.Error == "" {
				t.Error("error field is empty")
			}
			if fake.calls != 0 {
				t.Errorf("Core.SubjectToken called %d times, want 0: a malformed request must never reach the card", fake.calls)
			}
		})
	}
}

func TestSubjectTokenRejectsOtherMethods(t *testing.T) {
	for _, method := range []string{http.MethodGet, http.MethodPut, http.MethodDelete, http.MethodPatch} {
		t.Run(method, func(t *testing.T) {
			fake := okCore()
			req := httptest.NewRequest(method, "/v1/subject-token", nil)
			rec := httptest.NewRecorder()
			quietAPI(fake).Handler().ServeHTTP(rec, req)
			if rec.Code != http.StatusMethodNotAllowed {
				t.Errorf("status = %d, want 405", rec.Code)
			}
			if fake.calls != 0 {
				t.Errorf("Core.SubjectToken called %d times, want 0", fake.calls)
			}
		})
	}
}

func TestUnknownRouteOnSigningSocket(t *testing.T) {
	for _, path := range []string{"/v1/status", "/v1/unlock", "/"} {
		t.Run(path, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, path, strings.NewReader("{}"))
			rec := httptest.NewRecorder()
			quietAPI(okCore()).Handler().ServeHTTP(rec, req)
			if rec.Code != http.StatusNotFound {
				t.Errorf("status = %d, want 404: the signing socket exposes one route", rec.Code)
			}
		})
	}
}

// TestTokenNeverLogged is the load-bearing privacy check: the daemon logs
// signing metadata but must never write the minted token anywhere.
func TestTokenNeverLogged(t *testing.T) {
	var buf bytes.Buffer
	api := &API{Core: okCore(), Logger: slog.New(slog.NewTextHandler(&buf, nil))}

	rec := post(t, api.Handler(), validRequestBody())
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body %q)", rec.Code, rec.Body.String())
	}
	logged := buf.String()
	if logged == "" {
		t.Fatal("nothing was logged; the success path should record signing metadata")
	}
	if strings.Contains(logged, testToken) {
		t.Errorf("log contains the minted token %q: %s", testToken, logged)
	}
	for _, want := range []string{"alias=ro", "target=readonly-sa@example-project-id.iam.gserviceaccount.com", "source_kind=local-wif", "serial=12345678", "key_id=kid"} {
		if !strings.Contains(logged, want) {
			t.Errorf("log is missing %q: %s", want, logged)
		}
	}
	if !strings.Contains(rec.Body.String(), testToken) {
		t.Errorf("response body = %q, want it to carry the token", rec.Body.String())
	}
}

func TestAgentSourceLoggedWithoutToken(t *testing.T) {
	var buf bytes.Buffer
	api := &API{Core: okCore(), Logger: slog.New(slog.NewTextHandler(&buf, nil))}
	body := `{"alias":"ro","external_account_audience":"//iam.googleapis.com/projects/123456789012/locations/global/workloadIdentityPools/pivb-pool/providers/pivb-provider","impersonated_email":"readonly-sa@example-project-id.iam.gserviceaccount.com","request_source":{"kind":"agent-session","label":"codex:agentic/ro","session_id":"0123456789abcdef0123456789abcdef"}}`
	rec := post(t, api.Handler(), body)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body %q", rec.Code, rec.Body.String())
	}
	logged := buf.String()
	for _, want := range []string{"source_kind=agent-session", "source_label=codex:agentic/ro", "session_id=0123456789abcdef0123456789abcdef"} {
		if !strings.Contains(logged, want) {
			t.Errorf("log missing %q: %s", want, logged)
		}
	}
	if strings.Contains(logged, testToken) {
		t.Fatalf("agent log contains token: %s", logged)
	}
}

// syncBuffer collects journal lines a handler goroutine writes while the test
// goroutine reads them.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// TestMintLogCarriesPeerPID exercises attribution over a real uds listener, the
// only place SO_PEERCRED exists: whether the mint succeeds or is refused, the
// journal names the process that asked, and still never names the token.
func TestMintLogCarriesPeerPID(t *testing.T) {
	tests := []struct {
		name      string
		core      Core
		wantMsg   string
		wantError bool
	}{
		{name: "success", core: okCore(), wantMsg: "minted WIF subject token"},
		{name: "refusal", core: failingCore(core.ErrLocked), wantMsg: "subject-token request while locked", wantError: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			journal := &syncBuffer{}
			api := &API{Core: tc.core, Logger: slog.New(slog.NewTextHandler(journal, nil))}
			socket := serveOnSocket(t, api.Handler())

			_, err := NewClient(socket).SubjectToken(context.Background(), SubjectTokenRequest{
				Alias:                   "ro",
				ExternalAccountAudience: "//iam.googleapis.com/projects/123456789012/locations/global/workloadIdentityPools/pivb-pool/providers/pivb-provider",
				ImpersonatedEmail:       "readonly-sa@example-project-id.iam.gserviceaccount.com",
			})
			if tc.wantError && err == nil {
				t.Fatal("SubjectToken = nil error, want the core rejection")
			}
			if !tc.wantError && err != nil {
				t.Fatalf("SubjectToken: %v", err)
			}

			logged := journal.String()
			if !strings.Contains(logged, tc.wantMsg) {
				t.Fatalf("journal is missing %q: %s", tc.wantMsg, logged)
			}
			if want := fmt.Sprintf("peer_pid=%d", os.Getpid()); !strings.Contains(logged, want) {
				t.Errorf("journal is missing %q: %s", want, logged)
			}
			if !strings.Contains(logged, "peer_chain=") {
				t.Errorf("journal is missing peer_chain: %s", logged)
			}
			if want := fmt.Sprintf("%d(", os.Getpid()); !strings.Contains(logged, want) {
				t.Errorf("peer chain does not start at this process (%q): %s", want, logged)
			}
			if strings.Contains(logged, testToken) {
				t.Errorf("journal contains the minted token %q: %s", testToken, logged)
			}
		})
	}
}

// TestLoggedAliasIsEscaped stops a caller-supplied alias from forging journal
// lines: the error path logs the alias verbatim, so slog must quote control
// characters rather than emit them raw.
func TestLoggedAliasIsEscaped(t *testing.T) {
	var buf bytes.Buffer
	api := &API{
		Core:   failingCore(&core.UnknownAliasError{Alias: "injected"}),
		Logger: slog.New(slog.NewTextHandler(&buf, nil)),
	}
	rec := post(t, api.Handler(), `{"alias":"ro\nlevel=ERROR msg=forged","external_account_audience":"","impersonated_email":""}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 (body %q)", rec.Code, rec.Body.String())
	}
	logged := strings.TrimSuffix(buf.String(), "\n")
	if logged == "" {
		t.Fatal("nothing was logged; the error path should record the rejected alias")
	}
	if strings.Contains(logged, "\n") {
		t.Errorf("a caller-supplied alias produced a raw newline in the log: %q", buf.String())
	}
}

func serveOnSocket(t *testing.T, handler http.Handler) string {
	t.Helper()
	socket := filepath.Join(t.TempDir(), "s.sock")
	ctx, cancel := context.WithCancel(context.Background())
	served := make(chan error, 1)
	go func() { served <- uds.Serve(ctx, socket, handler) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-served:
			if err != nil {
				t.Errorf("uds.Serve = %v, want nil", err)
			}
		case <-time.After(5 * time.Second):
			t.Error("uds.Serve did not return after cancellation")
		}
	})
	waitReady(t, socket)
	return socket
}

func waitReady(t *testing.T, socket string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("unix", socket, 100*time.Millisecond)
		if err == nil {
			conn.Close()
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("socket %q never became ready", socket)
}

func TestClientSuccess(t *testing.T) {
	fake := okCore()
	socket := serveOnSocket(t, quietAPI(fake).Handler())

	req := SubjectTokenRequest{
		Alias:                   "ro",
		ExternalAccountAudience: "//iam.googleapis.com/projects/123456789012/locations/global/workloadIdentityPools/pivb-pool/providers/pivb-provider",
		ImpersonatedEmail:       "readonly-sa@example-project-id.iam.gserviceaccount.com",
	}
	resp, err := NewClient(socket).SubjectToken(context.Background(), req)
	if err != nil {
		t.Fatalf("SubjectToken: %v", err)
	}
	if resp.IDToken != testToken {
		t.Errorf("IDToken = %q, want %q", resp.IDToken, testToken)
	}
	if resp.ExpirationTime != testExpiry {
		t.Errorf("ExpirationTime = %d, want %d", resp.ExpirationTime, testExpiry)
	}
	if got := (core.SubjectTokenRequest{Alias: req.Alias, ExternalAccountAudience: req.ExternalAccountAudience, ImpersonatedEmail: req.ImpersonatedEmail, Attachment: attachment.LocalAllowed()}); !reflect.DeepEqual(fake.got, got) {
		t.Errorf("core request = %+v, want %+v", fake.got, got)
	}
}

func TestClientAPIError(t *testing.T) {
	socket := serveOnSocket(t, quietAPI(failingCore(core.ErrLocked)).Handler())

	_, err := NewClient(socket).SubjectToken(context.Background(), SubjectTokenRequest{Alias: "ro"})
	if err == nil {
		t.Fatal("SubjectToken = nil error, want a rejection")
	}
	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("error = %T (%v), want *APIError", err, err)
	}
	if apiErr.Code != CodeLocked {
		t.Errorf("Code = %q, want %q", apiErr.Code, CodeLocked)
	}
	if apiErr.Status != http.StatusConflict {
		t.Errorf("Status = %d, want 409", apiErr.Status)
	}
	if apiErr.Message == "" {
		t.Error("Message is empty")
	}
	if !strings.Contains(apiErr.Error(), CodeLocked) {
		t.Errorf("Error() = %q, want it to mention the code", apiErr.Error())
	}
	if !strings.Contains(apiErr.Error(), apiErr.Remedy) {
		t.Errorf("Error() = %q, want it to mention the remedy %q", apiErr.Error(), apiErr.Remedy)
	}
}

// TestClientRejectsIncompleteResponse guards the credential-source contract: a
// 200 that carries no usable token must fail loudly rather than hand the Google
// auth library an empty assertion.
func TestClientRejectsIncompleteResponse(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{"empty object", `{}`},
		{"missing token", `{"expiration_time":1785585870}`},
		{"missing expiry", `{"id_token":"h.p.s"}`},
		{"zero expiry", `{"id_token":"h.p.s","expiration_time":0}`},
		{"negative expiry", `{"id_token":"h.p.s","expiration_time":-1}`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			socket := serveOnSocket(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(tc.body))
			}))
			resp, err := NewClient(socket).SubjectToken(context.Background(), SubjectTokenRequest{Alias: "ro"})
			if err == nil {
				t.Fatalf("SubjectToken = %+v, nil error; want an incomplete-response error", resp)
			}
			if !strings.Contains(err.Error(), "incomplete") {
				t.Errorf("error = %v, want it to mention %q", err, "incomplete")
			}
			if resp.IDToken != "" {
				t.Errorf("IDToken = %q on failure, want it zeroed", resp.IDToken)
			}
		})
	}
}

func TestClientNonJSONError(t *testing.T) {
	socket := serveOnSocket(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("  boom  "))
	}))
	_, err := NewClient(socket).SubjectToken(context.Background(), SubjectTokenRequest{Alias: "ro"})
	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("error = %T (%v), want *APIError", err, err)
	}
	if apiErr.Code != CodeInternal {
		t.Errorf("Code = %q, want %q for a body with no code", apiErr.Code, CodeInternal)
	}
	if apiErr.Message != "boom" {
		t.Errorf("Message = %q, want the trimmed body %q", apiErr.Message, "boom")
	}
}

func TestClientUnreachableSocket(t *testing.T) {
	client := NewClient(filepath.Join(t.TempDir(), "s.sock"))
	_, err := client.SubjectToken(context.Background(), SubjectTokenRequest{Alias: "ro"})
	if err == nil {
		t.Fatal("SubjectToken against a missing socket = nil error, want a dial failure")
	}
	if !strings.Contains(err.Error(), "signing socket") {
		t.Errorf("error = %v, want it to name the signing socket", err)
	}
}

func TestClientContextCancellation(t *testing.T) {
	release := make(chan struct{})
	socket := serveOnSocket(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		<-release
		w.WriteHeader(http.StatusOK)
	}))
	// Registered after serveOnSocket so cleanup unblocks the handler before the
	// server is asked to shut down.
	t.Cleanup(func() { close(release) })

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if _, err := NewClient(socket).SubjectToken(ctx, SubjectTokenRequest{Alias: "ro"}); err == nil {
		t.Fatal("SubjectToken = nil error, want the cancelled context to surface")
	}
}
