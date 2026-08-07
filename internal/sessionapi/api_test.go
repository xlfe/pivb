package sessionapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/xlfe/pivb/internal/agentsource"
	"github.com/xlfe/pivb/internal/tokenapi"
	"github.com/xlfe/pivb/internal/uds"
)

const (
	testAudience = "//iam.googleapis.com/projects/123/locations/global/workloadIdentityPools/pool/providers/provider"
	testTarget   = "readonly-sa@example-project.iam.gserviceaccount.com"
	testID       = "0123456789abcdef0123456789abcdef"
)

type fakeUpstream struct {
	requests []UpstreamRequest
	result   tokenapi.SubjectTokenResponse
	err      error
}

func (f *fakeUpstream) SubjectToken(_ context.Context, req UpstreamRequest) (tokenapi.SubjectTokenResponse, error) {
	f.requests = append(f.requests, req)
	return f.result, f.err
}

func testAPI(upstream *fakeUpstream) *API {
	return &API{Session: Session{
		Alias: "ro", Target: testTarget, ExternalAccountAudience: testAudience,
		Source: agentsource.Agent("codex:agentic/ro", testID),
	}, Upstream: upstream}
}

func post(h http.Handler, body string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/subject-token", strings.NewReader(body))
	h.ServeHTTP(rec, req)
	return rec
}

func TestRelayInjectsFixedSessionValues(t *testing.T) {
	for _, body := range []string{
		`{"external_account_audience":"` + testAudience + `"}`,
		`{"external_account_audience":"` + testAudience + `","impersonated_email":"` + testTarget + `"}`,
	} {
		upstream := &fakeUpstream{result: tokenapi.SubjectTokenResponse{IDToken: "h.p.s", ExpirationTime: 1785585870}}
		rec := post(testAPI(upstream).Handler(), body)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, body %q", rec.Code, rec.Body.String())
		}
		if len(upstream.requests) != 1 {
			t.Fatalf("upstream calls = %d", len(upstream.requests))
		}
		got := upstream.requests[0]
		if got.Alias != "ro" || got.ImpersonatedEmail != testTarget || got.ExternalAccountAudience != testAudience || got.RequestSource.SessionID != testID {
			t.Fatalf("upstream request = %+v", got)
		}
	}
}

func TestRelayFailsClosedBeforeUpstream(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{"alias field", `{"alias":"deploy","external_account_audience":"` + testAudience + `"}`},
		{"tampered audience", `{"external_account_audience":"tampered"}`},
		{"tampered target", `{"external_account_audience":"` + testAudience + `","impersonated_email":"deploy-sa@example-project.iam.gserviceaccount.com"}`},
		{"null target", `{"external_account_audience":"` + testAudience + `","impersonated_email":null}`},
		{"multiple documents", `{"external_account_audience":"` + testAudience + `"}{}`},
		{"empty body", ``},
		{"invalid JSON", `{"external_account_audience":`},
		{"wrong audience type", `{"external_account_audience":42}`},
		{"array body", `[{"external_account_audience":"` + testAudience + `"}]`},
		{"oversized body", `{"external_account_audience":"` + strings.Repeat("a", maxRequestBody) + `"}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			upstream := &fakeUpstream{}
			rec := post(testAPI(upstream).Handler(), tt.body)
			if rec.Code < 400 || rec.Code >= 500 {
				t.Errorf("body %q status = %d, response %q", tt.body, rec.Code, rec.Body.String())
			}
			if len(upstream.requests) != 0 {
				t.Errorf("body %q reached upstream: %+v", tt.body, upstream.requests)
			}
		})
	}
}

func TestRelayRejectsOtherMethods(t *testing.T) {
	for _, method := range []string{http.MethodGet, http.MethodPut, http.MethodDelete, http.MethodPatch} {
		upstream := &fakeUpstream{}
		rec := httptest.NewRecorder()
		testAPI(upstream).Handler().ServeHTTP(rec, httptest.NewRequest(method, "/v1/subject-token", nil))
		if rec.Code != http.StatusMethodNotAllowed || len(upstream.requests) != 0 {
			t.Errorf("%s status/calls = %d/%d, want 405/0", method, rec.Code, len(upstream.requests))
		}
	}
}

func TestRelayHasNoDiscoveryOrControlRoutes(t *testing.T) {
	for _, route := range []string{"/v1/status", "/v1/unlock", "/v1/lock", "/v1/config"} {
		rec := httptest.NewRecorder()
		testAPI(&fakeUpstream{}).Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, route, nil))
		if rec.Code != http.StatusNotFound {
			t.Errorf("GET %s status = %d, want 404", route, rec.Code)
		}
	}
}

func TestSessionHandlersCannotCrossSelect(t *testing.T) {
	shared := &fakeUpstream{result: tokenapi.SubjectTokenResponse{IDToken: "h.p.s", ExpirationTime: 1785585870}}
	ro := testAPI(shared)
	deploy := &API{Session: Session{
		Alias: "deploy", Target: "deploy-sa@example-project.iam.gserviceaccount.com",
		ExternalAccountAudience: testAudience,
		Source:                  agentsource.Agent("codex:agentic/deploy", "fedcba9876543210fedcba9876543210"),
	}, Upstream: shared}
	for _, api := range []*API{ro, deploy} {
		rec := post(api.Handler(), `{"external_account_audience":"`+testAudience+`"}`)
		if rec.Code != http.StatusOK {
			t.Fatalf("session %q status = %d", api.Session.Alias, rec.Code)
		}
	}
	if len(shared.requests) != 2 || shared.requests[0].Alias != "ro" || shared.requests[1].Alias != "deploy" {
		t.Fatalf("fixed requests = %+v", shared.requests)
	}
	before := len(shared.requests)
	rec := post(ro.Handler(), `{"external_account_audience":"`+testAudience+`","impersonated_email":"deploy-sa@example-project.iam.gserviceaccount.com"}`)
	if rec.Code != http.StatusForbidden || len(shared.requests) != before {
		t.Fatalf("cross-target status/calls = %d/%d", rec.Code, len(shared.requests))
	}
}

func startSessionSocket(t *testing.T, api *API) string {
	t.Helper()
	socket := filepath.Join(t.TempDir(), "session.sock")
	listener, err := uds.Listen(socket)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- uds.ServeListenerCancelRequests(ctx, listener, api.Handler()) }()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Errorf("serve session socket: %v", err)
		}
	})
	return socket
}

func TestConcurrentSessionSocketsRemainIsolated(t *testing.T) {
	roUpstream := &fakeUpstream{result: tokenapi.SubjectTokenResponse{IDToken: "ro.h.s", ExpirationTime: 1785585870}}
	deployUpstream := &fakeUpstream{result: tokenapi.SubjectTokenResponse{IDToken: "deploy.h.s", ExpirationTime: 1785585870}}
	roAPI := testAPI(roUpstream)
	deployTarget := "deploy-sa@example-project.iam.gserviceaccount.com"
	deployAPI := &API{Session: Session{
		Alias: "deploy", Target: deployTarget, ExternalAccountAudience: testAudience,
		Source: agentsource.Agent("codex:agentic/deploy", "fedcba9876543210fedcba9876543210"),
	}, Upstream: deployUpstream}

	type result struct {
		alias string
		token string
		err   error
	}
	results := make(chan result, 2)
	for _, session := range []struct {
		alias  string
		socket string
	}{
		{"ro", startSessionSocket(t, roAPI)},
		{"deploy", startSessionSocket(t, deployAPI)},
	} {
		go func() {
			client := NewClient(session.socket)
			defer client.HTTP.CloseIdleConnections()
			resp, err := client.SubjectToken(context.Background(), Request{ExternalAccountAudience: testAudience})
			results <- result{alias: session.alias, token: resp.IDToken, err: err}
		}()
	}
	got := make(map[string]string)
	for range 2 {
		result := <-results
		if result.err != nil {
			t.Fatalf("%s socket request: %v", result.alias, result.err)
		}
		got[result.alias] = result.token
	}
	if got["ro"] != "ro.h.s" || got["deploy"] != "deploy.h.s" {
		t.Fatalf("socket tokens = %#v", got)
	}
	if len(roUpstream.requests) != 1 || roUpstream.requests[0].Alias != "ro" || len(deployUpstream.requests) != 1 || deployUpstream.requests[0].Alias != "deploy" {
		t.Fatalf("socket upstreams = ro:%+v deploy:%+v", roUpstream.requests, deployUpstream.requests)
	}

	client := NewClient(startSessionSocket(t, deployAPI))
	defer client.HTTP.CloseIdleConnections()
	roEmail := testTarget
	if _, err := client.SubjectToken(context.Background(), Request{ExternalAccountAudience: testAudience, ImpersonatedEmail: &roEmail}); err == nil {
		t.Fatal("ro credential context crossed into deploy session socket")
	}
	if len(deployUpstream.requests) != 1 {
		t.Fatalf("cross-session request reached deploy upstream: %+v", deployUpstream.requests)
	}
}

func TestRelayPropagatesStructuredUpstreamError(t *testing.T) {
	upstream := &fakeUpstream{err: &tokenapi.APIError{Status: http.StatusConflict, Code: tokenapi.CodeLocked, Message: "locked", Remedy: "unlock on host"}}
	rec := post(testAPI(upstream).Handler(), `{"external_account_audience":"`+testAudience+`"}`)
	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d", rec.Code)
	}
	var body tokenapi.ErrorResponse
	if err := json.NewDecoder(bytes.NewReader(rec.Body.Bytes())).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if body.Code != tokenapi.CodeLocked || body.Remedy != "unlock on host" {
		t.Fatalf("error body = %+v", body)
	}

	upstream.err = errors.New("dial failed")
	rec = post(testAPI(upstream).Handler(), `{"external_account_audience":"`+testAudience+`"}`)
	if rec.Code != http.StatusServiceUnavailable || !strings.Contains(rec.Body.String(), tokenapi.CodeUnavailable) {
		t.Fatalf("unavailable status/body = %d/%q", rec.Code, rec.Body.String())
	}
}
