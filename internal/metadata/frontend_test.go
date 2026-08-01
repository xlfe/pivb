package metadata

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/xlfe/pivb/internal/agentapi"
	"github.com/xlfe/pivb/internal/core"
)

type fakeAgent struct {
	status   core.Status
	token    core.Token
	tokenErr error
	id       core.Identity
}

func (a *fakeAgent) Status(context.Context) (core.Status, error) { return a.status, nil }
func (a *fakeAgent) Token(context.Context) (core.Token, error)   { return a.token, a.tokenErr }
func (a *fakeAgent) Identity(_ context.Context, audience string) (core.Identity, error) {
	if audience == "" {
		return core.Identity{}, errors.New("missing audience")
	}
	return a.id, nil
}

func TestMetadataConformance(t *testing.T) {
	now := time.Unix(1_900_000_000, 0)
	email := "ro@example.test"
	agent := &fakeAgent{
		status: core.Status{Cloud: "gcp", ActiveAlias: "ro", TargetEmail: email, ProjectID: "project-1", NumericProject: "12345"},
		token:  core.Token{AccessToken: "secret", ExpiresAt: now.Add(10 * time.Minute), TargetEmail: email},
		id:     core.Identity{Token: "header.payload.sig", ExpiresAt: now.Add(time.Hour)},
	}
	handler := (&Frontend{Agent: agent, Now: func() time.Time { return now }}).Handler()
	tests := []struct {
		name, path, contentType, body string
		status                        int
		header                        bool
	}{
		{"root detection", "/", "", "", 200, false},
		{"accounts", prefix + "instance/service-accounts/", "text/plain", "default/\n" + email + "/\n", 200, true},
		{"default directory", prefix + "instance/service-accounts/default/", "text/plain", "aliases\nemail\nidentity\nscopes\ntoken\n", 200, true},
		{"email directory", prefix + "instance/service-accounts/" + email + "/", "text/plain", "aliases\nemail\nidentity\nscopes\ntoken\n", 200, true},
		{"email", prefix + "instance/service-accounts/default/email", "text/plain", email, 200, true},
		{"scopes", prefix + "instance/service-accounts/default/scopes", "text/plain", cloudScope + "\n", 200, true},
		{"aliases", prefix + "instance/service-accounts/default/aliases", "text/plain", "default\n", 200, true},
		{"identity", prefix + "instance/service-accounts/default/identity?audience=https%3A%2F%2Fservice.test", "text/plain", "header.payload.sig", 200, true},
		{"project", prefix + "project/project-id", "text/plain", "project-1", 200, true},
		{"numeric project", prefix + "project/numeric-project-id", "text/plain", "12345", 200, true},
		{"universe", prefix + "universe/universe-domain", "text/plain", "googleapis.com", 200, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, tc.path, nil)
			if tc.header {
				req.Header.Set("Metadata-Flavor", "Google")
			}
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)
			if w.Code != tc.status || w.Body.String() != tc.body {
				t.Fatalf("response = %d %q, want %d %q", w.Code, w.Body.String(), tc.status, tc.body)
			}
			if got := w.Header().Get("Metadata-Flavor"); got != "Google" {
				t.Fatalf("Metadata-Flavor response = %q", got)
			}
			if tc.contentType != "" && w.Header().Get("Content-Type") != tc.contentType {
				t.Fatalf("Content-Type = %q", w.Header().Get("Content-Type"))
			}
		})
	}
}

func TestMetadataTokenExpiryArithmeticAndNotificationWindow(t *testing.T) {
	now := time.Unix(1_900_000_000, 0)
	agent := &fakeAgent{
		status: core.Status{ActiveAlias: "ro", TargetEmail: "ro@example.test"},
		token:  core.Token{AccessToken: "secret", ExpiresAt: now.Add(239 * time.Second)},
	}
	f := &Frontend{Agent: agent, Now: func() time.Time { return now }, Notify: []string{"true"}}
	for range 2 {
		req := httptest.NewRequest(http.MethodGet, prefix+"instance/service-accounts/default/token", nil)
		req.Header.Set("Metadata-Flavor", "Google")
		w := httptest.NewRecorder()
		f.Handler().ServeHTTP(w, req)
		if w.Code != 200 {
			t.Fatalf("status = %d: %s", w.Code, w.Body.String())
		}
		var got struct {
			AccessToken string `json:"access_token"`
			ExpiresIn   int64  `json:"expires_in"`
			TokenType   string `json:"token_type"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
			t.Fatal(err)
		}
		if got.AccessToken != "secret" || got.ExpiresIn != 239 || got.TokenType != "Bearer" {
			t.Fatalf("token response = %#v", got)
		}
	}
	if !f.notifiedExpiry.Equal(agent.token.ExpiresAt) {
		t.Fatal("expiry notification window was not recorded")
	}
}

func TestMetadataTokenLogsIgnoredScopes(t *testing.T) {
	now := time.Unix(1_900_000_000, 0)
	agent := &fakeAgent{
		status: core.Status{ActiveAlias: "ro", TargetEmail: "ro@example.test"},
		token:  core.Token{AccessToken: "secret", ExpiresAt: now.Add(time.Hour)},
	}
	var logs bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	handler := (&Frontend{Agent: agent, Logger: logger, Now: func() time.Time { return now }}).Handler()
	req := httptest.NewRequest(http.MethodGet, prefix+"instance/service-accounts/default/token?scopes=scope-a,scope-b", nil)
	req.Header.Set("Metadata-Flavor", "Google")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", w.Code, w.Body.String())
	}
	if got := logs.String(); !strings.Contains(got, "metadata token scopes query parameter ignored") || !strings.Contains(got, "scope-a,scope-b") {
		t.Fatalf("ignored scopes were not logged at debug: %q", got)
	}
}

func TestMetadataFailuresAreLoud(t *testing.T) {
	now := time.Unix(1_900_000_000, 0)
	agent := &fakeAgent{status: core.Status{ActiveAlias: "ro", TargetEmail: "ro@example.test", ProjectID: "p"}}
	handler := (&Frontend{Agent: agent, Now: func() time.Time { return now }}).Handler()

	t.Run("missing flavor", func(t *testing.T) {
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, httptest.NewRequest(http.MethodGet, prefix+"project/project-id", nil))
		if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "Metadata-Flavor") {
			t.Fatalf("response = %d %s", w.Code, w.Body.String())
		}
	})
	t.Run("missing numeric project", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, prefix+"project/numeric-project-id", nil)
		req.Header.Set("Metadata-Flavor", "Google")
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		if w.Code != http.StatusNotFound || !strings.Contains(w.Body.String(), "numeric_project_id") {
			t.Fatalf("response = %d %s", w.Code, w.Body.String())
		}
	})
	t.Run("absent token", func(t *testing.T) {
		agent.tokenErr = &agentapi.HTTPError{Status: 503, ErrorMessage: "no valid access token", Remedy: "run `pivb renew`"}
		req := httptest.NewRequest(http.MethodGet, prefix+"instance/service-accounts/default/token", nil)
		req.Header.Set("Metadata-Flavor", "Google")
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		if w.Code != http.StatusServiceUnavailable || !strings.Contains(w.Body.String(), "pivb renew") || !strings.Contains(w.Body.String(), "no valid access token") {
			t.Fatalf("response = %d %s", w.Code, w.Body.String())
		}
	})
}
