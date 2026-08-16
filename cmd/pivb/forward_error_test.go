package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/xlfe/pivb/internal/agentsource"
	"github.com/xlfe/pivb/internal/config"
	"github.com/xlfe/pivb/internal/core"
	"github.com/xlfe/pivb/internal/forwardapi"
	"github.com/xlfe/pivb/internal/tokenapi"
)

func TestForwardContentionUsesSharedHardwareClassifier(t *testing.T) {
	mapped := mapForwardError(errors.New("open smart card: SCARD_E_SHARING_VIOLATION 0x8010000b"))
	if mapped.Status != http.StatusServiceUnavailable || mapped.Code != tokenapi.CodeSign {
		t.Fatalf("mapped = %+v, want 503/%s", mapped, tokenapi.CodeSign)
	}
}

func testForwardBackend(t *testing.T) forwardBackend {
	t.Helper()
	return forwardBackend{
		core:   core.New(&config.Config{}, nil, "test"),
		logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
}

func testForwardMintRequest() forwardapi.MintRequest {
	return forwardapi.MintRequest{
		Version: forwardapi.ProtocolVersion, Alias: "ro",
		ExternalAccountAudience: "//iam.googleapis.com/projects/1/locations/global/workloadIdentityPools/pivb/providers/yubikey",
		ImpersonatedEmail:       "ro@example.iam.gserviceaccount.com",
		RequestSource:           &agentsource.Source{Kind: agentsource.KindAgentSession, Label: "codex:proj/ro", SessionID: strings.Repeat("1", 32)},
		ExpectedCard:            forwardapi.CardIdentity{Serial: 12345678, KeyID: "kid", SPKIDER: []byte("spki")},
		ForwardContext: forwardapi.ForwardContext{
			OriginNodeID: strings.Repeat("a", 32), WorkspaceID: strings.Repeat("b", 32), Bundle: "work",
			ClaimGeneration: 7, ProviderNodeID: strings.Repeat("c", 32), OperationID: strings.Repeat("e", 32),
		},
	}
}

// Protocol 3 can carry a requested authorisation window, but nothing enforces
// one yet. Until it does, a mint asking for window coverage is refused rather
// than served without the coverage it asked for. The backend holds a live core
// here so a refusal moved after the hardware call would fail loudly.
func TestForwardMintRefusesRequestedWindowsUntilTheProviderGrantsThem(t *testing.T) {
	backend := testForwardBackend(t)
	req := testForwardMintRequest()
	req.ForwardContext.WindowSeconds = 900
	req.ForwardContext.WindowDeadline = 1785586770

	_, apiErr := backend.Mint(context.Background(), req)
	if apiErr == nil {
		t.Fatal("a mint requesting a grant window was accepted")
	}
	if apiErr.Status != http.StatusForbidden || apiErr.Code != tokenapi.CodeWindowNotAllowed ||
		apiErr.Message != "a grant window was requested but this provider does not allow windows" ||
		apiErr.Remedy != "enable grant windows in the provider pivb configuration or re-claim without a window" {
		t.Fatalf("window refusal = %+v", apiErr)
	}
}

// The two error mappers between the provider and the agent pass a structured
// rejection through untouched, so a new code needs no mapper change to reach
// the caller. This proves that for the window refusal end to end.
func TestWindowRefusalReachesTheWIFCallerUnchanged(t *testing.T) {
	refusal := &tokenapi.APIError{
		Status: http.StatusForbidden, Code: tokenapi.CodeWindowNotAllowed,
		Message: "a grant window was requested but this provider does not allow windows",
		Remedy:  "enable grant windows in the provider pivb configuration or re-claim without a window",
	}
	if mapped := mapForwardError(fmt.Errorf("forwarded mint: %w", refusal)); mapped != refusal {
		t.Fatalf("forward mapper rewrote the refusal: %+v", mapped)
	}

	handler := wifHandler(&fakeWIFCore{err: refusal})
	request := httptest.NewRequest("POST", "/v1/subject-token", strings.NewReader(`{"alias":"ro","external_account_audience":"aud","impersonated_email":"ro@example"}`))
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	var body tokenapi.ErrorResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if recorder.Code != http.StatusForbidden || body.Code != tokenapi.CodeWindowNotAllowed ||
		body.Error != refusal.Message || body.Remedy != refusal.Remedy {
		t.Fatalf("WIF response = %d %+v", recorder.Code, body)
	}
}

// Invalidation is the release path, so generation zero — "every generation of
// this workspace" — is legal here even though a mint requires a real one.
func TestForwardInvalidateAcceptsWholeWorkspaceReleases(t *testing.T) {
	backend := testForwardBackend(t)
	workspace := strings.Repeat("b", 32)

	result, apiErr := backend.Invalidate(context.Background(), forwardapi.InvalidateRequest{
		Version: forwardapi.ProtocolVersion, WorkspaceID: workspace,
	})
	if apiErr != nil {
		t.Fatalf("release invalidation = %+v", apiErr)
	}
	if result.Version != forwardapi.ProtocolVersion || result.Purged != 0 {
		t.Fatalf("release invalidation result = %+v", result)
	}

	if _, apiErr := backend.Invalidate(context.Background(), forwardapi.InvalidateRequest{
		Version: forwardapi.ProtocolVersion, WorkspaceID: workspace, ClaimGeneration: 7,
	}); apiErr != nil {
		t.Fatalf("bounded invalidation = %+v", apiErr)
	}

	for _, workspaceID := range []string{"", strings.Repeat("b", 24), strings.Repeat("B", 32), strings.Repeat("z", 32)} {
		_, apiErr := backend.Invalidate(context.Background(), forwardapi.InvalidateRequest{
			Version: forwardapi.ProtocolVersion, WorkspaceID: workspaceID,
		})
		if apiErr == nil || apiErr.Status != http.StatusBadRequest || apiErr.Code != tokenapi.CodeConfig {
			t.Fatalf("invalidation for workspace %q = %+v", workspaceID, apiErr)
		}
	}
}
