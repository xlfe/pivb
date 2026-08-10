package agentapi

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/xlfe/pivb/internal/config"
	"github.com/xlfe/pivb/internal/core"
	"github.com/xlfe/pivb/internal/pivsigner"
	"github.com/xlfe/pivb/internal/uds"
)

const (
	testPIN    = "123456"
	testSerial = uint32(12345678)
)

// fakeSigner accepts exactly one PIN. Sign panics: the control API has no
// route that reaches hardware, and this proves it.
type fakeSigner struct{}

func (fakeSigner) VerifyPIN(_ context.Context, pin string) (uint32, int, error) {
	if pin == testPIN {
		return testSerial, 3, nil
	}
	return 0, 2, &pivsigner.PINError{Retries: 2, Err: errors.New("wrong PIN")}
}

func (fakeSigner) Sign(context.Context, string, string, func(uint32, *x509.Certificate) ([]byte, error)) ([]byte, uint32, error) {
	panic("control API must never reach the signer")
}

type busySigner struct{ fakeSigner }

func (busySigner) VerifyPIN(context.Context, string) (uint32, int, error) {
	return 0, -1, errors.New("open smart card: SCARD_E_SHARING_VIOLATION 0x8010000b")
}

func testConfig() *config.Config {
	return &config.Config{
		PIVSlot:  "9c",
		PINCache: "session",
		WIF: config.WIF{
			ProjectNumber: "123456789012",
			PoolID:        "pivb-pool",
			ProviderID:    "pivb-provider",
			IssuerURI:     "https://pivb.example.com",
		},
		Keys: map[string]config.Key{
			"12345678": {JWKKid: "g4tW--9GFcDvwdryp8vTG76EyUg-QhfOEjBo0YQg3Wg"},
		},
		Aliases: map[string]config.Alias{
			"ro": {Cloud: "gcp", Target: "readonly-sa@example-project-id.iam.gserviceaccount.com", LifetimeS: 3600},
		},
	}
}

func newTestAPI(t *testing.T) *API {
	t.Helper()
	if err := testConfig().Validate(); err != nil {
		t.Fatalf("test config is invalid, fix the fixture: %v", err)
	}
	return &API{Core: core.New(testConfig(), fakeSigner{}, "test-version")}
}

func do(t *testing.T, h http.Handler, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	var req *http.Request
	if body == "" {
		req = httptest.NewRequest(method, path, nil)
	} else {
		req = httptest.NewRequest(method, path, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// TestRemovedRoutesAreGone pins the post-WIF surface: the control socket must
// expose no route that can return credential material.
func TestRemovedRoutesAreGone(t *testing.T) {
	h := newTestAPI(t).Handler()
	tests := []struct {
		method, path string
		want         int
	}{
		{http.MethodGet, "/v1/token", http.StatusNotFound},
		{http.MethodPost, "/v1/use", http.StatusNotFound},
		{http.MethodPost, "/v1/renew", http.StatusNotFound},
		{http.MethodGet, "/v1/identity", http.StatusNotFound},
		{http.MethodPost, "/v1/subject-token", http.StatusNotFound},
		{http.MethodGet, "/", http.StatusNotFound},
		// Surviving routes stay method-scoped.
		{http.MethodGet, "/v1/unlock", http.StatusMethodNotAllowed},
		{http.MethodPost, "/v1/status", http.StatusMethodNotAllowed},
	}
	for _, tc := range tests {
		t.Run(tc.method+" "+tc.path, func(t *testing.T) {
			if rec := do(t, h, tc.method, tc.path, ""); rec.Code != tc.want {
				t.Errorf("status = %d, want %d (body %q)", rec.Code, tc.want, rec.Body.String())
			}
		})
	}
}

func TestHealth(t *testing.T) {
	rec := do(t, newTestAPI(t).Handler(), http.MethodGet, "/v1/health", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if got := rec.Header().Get("Content-Type"); got != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", got)
	}
	var body map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode %q: %v", rec.Body.String(), err)
	}
	if body["status"] != "ok" {
		t.Errorf("status field = %q, want ok", body["status"])
	}
}

func TestStatus(t *testing.T) {
	rec := do(t, newTestAPI(t).Handler(), http.MethodGet, "/v1/status", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	var status core.Status
	if err := json.Unmarshal(rec.Body.Bytes(), &status); err != nil {
		t.Fatalf("decode %q: %v", rec.Body.String(), err)
	}
	if !strings.HasPrefix(status.WIFProvider, "projects/") {
		t.Errorf("WIFProvider = %q, want a projects/... resource name", status.WIFProvider)
	}
	if !strings.Contains(status.WIFProvider, "pivb-pool") || !strings.Contains(status.WIFProvider, "pivb-provider") {
		t.Errorf("WIFProvider = %q, want it to name the configured pool and provider", status.WIFProvider)
	}
	if status.PINCached {
		t.Error("PINCached = true on a fresh core, want false")
	}
	if status.Version != "test-version" {
		t.Errorf("Version = %q, want test-version", status.Version)
	}
}

func TestUnlockThenStatusThenLock(t *testing.T) {
	h := newTestAPI(t).Handler()

	rec := do(t, h, http.MethodPost, "/v1/unlock", `{"pin":"123456"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("unlock status = %d, want 200 (body %q)", rec.Code, rec.Body.String())
	}
	var unlocked struct {
		Unlocked bool `json:"unlocked"`
		Retries  int  `json:"retries"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &unlocked); err != nil {
		t.Fatalf("decode %q: %v", rec.Body.String(), err)
	}
	if !unlocked.Unlocked {
		t.Error("unlocked = false, want true")
	}
	if unlocked.Retries != 3 {
		t.Errorf("retries = %d, want 3", unlocked.Retries)
	}

	status := decodeStatus(t, h)
	if !status.PINCached {
		t.Error("PINCached = false after unlock, want true")
	}
	if status.PINVerifiedSerial != testSerial {
		t.Errorf("PINVerifiedSerial = %d, want %d", status.PINVerifiedSerial, testSerial)
	}

	rec = do(t, h, http.MethodPost, "/v1/lock", `{}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("lock status = %d, want 200 (body %q)", rec.Code, rec.Body.String())
	}
	var locked map[string]bool
	if err := json.Unmarshal(rec.Body.Bytes(), &locked); err != nil {
		t.Fatalf("decode %q: %v", rec.Body.String(), err)
	}
	if !locked["locked"] {
		t.Errorf("locked = %v, want true", locked)
	}

	status = decodeStatus(t, h)
	if status.PINCached {
		t.Error("PINCached = true after lock, want false")
	}
	if status.PINVerifiedSerial != 0 {
		t.Errorf("PINVerifiedSerial = %d after lock, want 0", status.PINVerifiedSerial)
	}
}

func decodeStatus(t *testing.T, h http.Handler) core.Status {
	t.Helper()
	rec := do(t, h, http.MethodGet, "/v1/status", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	var status core.Status
	if err := json.Unmarshal(rec.Body.Bytes(), &status); err != nil {
		t.Fatalf("decode %q: %v", rec.Body.String(), err)
	}
	return status
}

func TestUnlockWrongPIN(t *testing.T) {
	h := newTestAPI(t).Handler()
	rec := do(t, h, http.MethodPost, "/v1/unlock", `{"pin":"000000"}`)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 (body %q)", rec.Code, rec.Body.String())
	}
	var body struct {
		Error   string `json:"error"`
		Remedy  string `json:"remedy"`
		Retries int    `json:"retries"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode %q: %v", rec.Body.String(), err)
	}
	if body.Retries != 2 {
		t.Errorf("retries = %d, want 2", body.Retries)
	}
	if body.Error == "" {
		t.Error("error field is empty")
	}
	if body.Remedy == "" {
		t.Error("remedy field is empty")
	}
	if strings.Contains(body.Error, "000000") {
		t.Errorf("error %q leaks the submitted PIN", body.Error)
	}

	if status := decodeStatus(t, h); status.PINCached {
		t.Error("PINCached = true after a rejected PIN, want false")
	}
}

func TestUnlockContentionHasBusyRemedyAndStableCode(t *testing.T) {
	api := &API{Core: core.New(testConfig(), busySigner{}, "test-version")}
	rec := do(t, api.Handler(), http.MethodPost, "/v1/unlock", `{"pin":"123456"}`)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503 (body %q)", rec.Code, rec.Body.String())
	}
	var body errorResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Code != "PIVB_SIGN" {
		t.Fatalf("code = %q, want PIVB_SIGN", body.Code)
	}
	if strings.Contains(body.Remedy, "insert exactly one") || !strings.Contains(body.Remedy, "competing") {
		t.Fatalf("remedy = %q, want contention guidance instead of card insertion", body.Remedy)
	}
}

func TestUnlockBadRequests(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{"empty body", ""},
		{"invalid JSON", `{"pin":`},
		{"unknown field", `{"pin":"123456","extra":1}`},
		{"two JSON documents", `{"pin":"123456"}{}`},
		{"wrong type", `{"pin":123456}`},
		{"array body", `[]`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rec := do(t, newTestAPI(t).Handler(), http.MethodPost, "/v1/unlock", tc.body)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400 (body %q)", rec.Code, rec.Body.String())
			}
			var body errorResponse
			if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
				t.Fatalf("decode %q: %v", rec.Body.String(), err)
			}
			if body.Error == "" {
				t.Error("error field is empty")
			}
		})
	}
}

// TestUnlockEmptyPIN documents the current behaviour of a well-formed request
// carrying an empty PIN. See the note in the accompanying review: core rejects
// it with a plain error, so the API reports it as an availability problem.
func TestUnlockEmptyPIN(t *testing.T) {
	rec := do(t, newTestAPI(t).Handler(), http.MethodPost, "/v1/unlock", `{"pin":""}`)
	if rec.Code == http.StatusOK {
		t.Fatalf("status = 200 for an empty PIN, want a rejection (body %q)", rec.Body.String())
	}
	var body errorResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode %q: %v", rec.Body.String(), err)
	}
	if body.Error == "" {
		t.Error("error field is empty")
	}
	if rec.Code != http.StatusServiceUnavailable {
		t.Logf("empty PIN now returns %d; it returned 503 when this test was written", rec.Code)
	}
}

func TestUnlockOversizedBody(t *testing.T) {
	body := `{"pin":"` + strings.Repeat("1", 32<<10) + `"}`
	rec := do(t, newTestAPI(t).Handler(), http.MethodPost, "/v1/unlock", body)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 for a body over the 16KiB cap", rec.Code)
	}
}

func TestClientRoundTrip(t *testing.T) {
	socket := filepath.Join(t.TempDir(), "s.sock")
	api := newTestAPI(t)
	ctx, cancel := context.WithCancel(context.Background())
	served := make(chan error, 1)
	go func() { served <- uds.Serve(ctx, socket, api.Handler()) }()
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

	client := NewClient(socket)
	reqCtx := context.Background()

	status, err := client.Status(reqCtx)
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if status.PINCached {
		t.Error("PINCached = true before unlock, want false")
	}
	if !strings.HasPrefix(status.WIFProvider, "projects/") {
		t.Errorf("WIFProvider = %q, want a projects/... resource name", status.WIFProvider)
	}

	retries, err := client.Unlock(reqCtx, testPIN)
	if err != nil {
		t.Fatalf("Unlock: %v", err)
	}
	if retries != 3 {
		t.Errorf("retries = %d, want 3", retries)
	}

	status, err = client.Status(reqCtx)
	if err != nil {
		t.Fatalf("Status after unlock: %v", err)
	}
	if !status.PINCached || status.PINVerifiedSerial != testSerial {
		t.Errorf("status after unlock = %+v, want PINCached true and serial %d", status, testSerial)
	}

	if err := client.Lock(reqCtx); err != nil {
		t.Fatalf("Lock: %v", err)
	}
	status, err = client.Status(reqCtx)
	if err != nil {
		t.Fatalf("Status after lock: %v", err)
	}
	if status.PINCached {
		t.Error("PINCached = true after Lock, want false")
	}

	_, err = client.Unlock(reqCtx, "000000")
	if err == nil {
		t.Fatal("Unlock with a wrong PIN = nil error, want a rejection")
	}
	var httpErr *HTTPError
	if !errors.As(err, &httpErr) {
		t.Fatalf("Unlock error = %T (%v), want *HTTPError", err, err)
	}
	if httpErr.Status != http.StatusForbidden {
		t.Errorf("HTTPError.Status = %d, want 403", httpErr.Status)
	}
	if httpErr.ErrorMessage == "" {
		t.Error("HTTPError.ErrorMessage is empty")
	}
	if httpErr.Remedy == "" {
		t.Error("HTTPError.Remedy is empty")
	}
	if httpErr.Code != "PIVB_PIN" {
		t.Errorf("HTTPError.Code = %q, want PIVB_PIN", httpErr.Code)
	}
	if !strings.Contains(httpErr.Error(), "403") {
		t.Errorf("HTTPError.Error() = %q, want it to mention the status", httpErr.Error())
	}
	if !strings.Contains(httpErr.Error(), "PIVB_PIN") {
		t.Errorf("HTTPError.Error() = %q, want it to mention the stable code", httpErr.Error())
	}
}

func TestClientUnreachableSocket(t *testing.T) {
	client := NewClient(filepath.Join(t.TempDir(), "s.sock"))
	if _, err := client.Status(context.Background()); err == nil {
		t.Fatal("Status against a missing socket = nil error, want a dial failure")
	} else if !strings.Contains(err.Error(), "control socket") {
		t.Errorf("error = %v, want it to name the control socket", err)
	}
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
