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
	"time"

	"github.com/xlfe/pivb/internal/agentsource"
	"github.com/xlfe/pivb/internal/config"
	"github.com/xlfe/pivb/internal/core"
	"github.com/xlfe/pivb/internal/forwardapi"
	"github.com/xlfe/pivb/internal/pivsigner"
	"github.com/xlfe/pivb/internal/tokenapi"
)

func TestForwardContentionUsesSharedHardwareClassifier(t *testing.T) {
	mapped := mapForwardError(errors.New("open smart card: SCARD_E_SHARING_VIOLATION 0x8010000b"))
	if mapped.Status != http.StatusServiceUnavailable || mapped.Code != tokenapi.CodeSign {
		t.Fatalf("mapped = %+v, want 503/%s", mapped, tokenapi.CodeSign)
	}
}

// testForwardBackend runs the real core over a configuration that binds exactly
// the alias testForwardMintRequest asks for, so a refusal is a refusal on the
// merits rather than an unresolved alias. Its signer is nil: a request that got
// as far as the card would panic instead of passing quietly.
func testForwardBackend(t *testing.T, maxGrantWindowS int) forwardBackend {
	t.Helper()
	cfg := &config.Config{
		PIVSlot: "9c", PINCache: "session", MaxGrantWindowS: maxGrantWindowS,
		WIF: config.WIF{ProjectNumber: "1", PoolID: "pivb", ProviderID: "yubikey", IssuerURI: "https://auth.example.net/pivb/dep1"},
		Aliases: map[string]config.Alias{
			"ro": {Cloud: "gcp", Target: "ro@example.iam.gserviceaccount.com", LifetimeS: 3600},
		},
	}
	return forwardBackend{
		core:   core.New(cfg, nil, "test"),
		logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
}

// stubForwardCore answers the forwarding socket without a card, so a test can
// pin what the backend does with a result rather than how one is produced.
type stubForwardCore struct {
	result core.SubjectTokenResult
	req    core.SubjectTokenRequest
}

func (s *stubForwardCore) SubjectToken(_ context.Context, req core.SubjectTokenRequest) (core.SubjectTokenResult, error) {
	s.req = req
	return s.result, nil
}

func (s *stubForwardCore) ForwardPolicy() forwardapi.Policy { return forwardapi.Policy{} }

func (s *stubForwardCore) DescribeForwardProvider(context.Context) (forwardapi.Description, error) {
	return forwardapi.Description{}, nil
}

func (s *stubForwardCore) InvalidateWorkspace(string, uint64) int { return 0 }

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

// A provider whose operator grants no windows refuses a claim that asks to be
// covered by one rather than serving it without the coverage it asked for. The
// backend holds a live core here, so a refusal that arrived only after the PIN
// or the card would report a locked daemon instead of this.
func TestForwardMintRefusesWindowsTheProviderDoesNotGrant(t *testing.T) {
	backend := testForwardBackend(t, 0)
	req := testForwardMintRequest()
	req.ForwardContext.WindowSeconds = 900
	req.ForwardContext.WindowDeadline = 1785586770

	_, apiErr := backend.Mint(context.Background(), req)
	if apiErr == nil {
		t.Fatal("a mint requesting a grant window was accepted")
	}
	if apiErr.Status != http.StatusForbidden || apiErr.Code != tokenapi.CodeWindowNotAllowed ||
		apiErr.Message != "the mint asked to be covered by a 900-second authorisation window but this provider's max_grant_window_s is 0" ||
		apiErr.Remedy != core.WindowNotAllowedRemedy {
		t.Fatalf("window refusal = %+v", apiErr)
	}

	// The refusal is about the window this claim asked for, not about windows
	// being disabled: the same request without one walks past it into the
	// ordinary mint path and stops where an unlocked daemon would carry on.
	if _, apiErr := backend.Mint(context.Background(), testForwardMintRequest()); apiErr == nil || apiErr.Code != tokenapi.CodeLocked {
		t.Fatalf("windowless mint on a provider that grants no windows = %+v", apiErr)
	}
}

// A card-free origin keeps serving the two forwarding operations zkad uses on
// it — policy and invalidation — and answers the two provider-only ones with
// the card-free code, so a misrouted mint reports "the card is on another
// host" rather than a hardware fault or a locked daemon.
func TestForwardBackendOnCardFreeOrigin(t *testing.T) {
	cfg := &config.Config{
		PIVSlot: "9c", PINCache: "session", Card: config.CardNone,
		WIF:  config.WIF{ProjectNumber: "1", PoolID: "pivb", ProviderID: "yubikey", IssuerURI: "https://auth.example.net/pivb/dep1"},
		Keys: map[string]config.Key{"12345678": {JWKKid: strings.Repeat("k", 43)}},
		Aliases: map[string]config.Alias{
			"ro": {Cloud: "gcp", Target: "ro@example.iam.gserviceaccount.com", LifetimeS: 3600},
		},
	}
	backend := forwardBackend{
		core:   core.New(cfg, pivsigner.CardFree{}, "test"),
		logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}

	if _, apiErr := backend.Mint(context.Background(), testForwardMintRequest()); apiErr == nil ||
		apiErr.Status != http.StatusForbidden || apiErr.Code != tokenapi.CodeCardFree {
		t.Fatalf("card-free mint = %+v, want 403/%s", apiErr, tokenapi.CodeCardFree)
	}
	if _, apiErr := backend.Describe(context.Background()); apiErr == nil ||
		apiErr.Status != http.StatusForbidden || apiErr.Code != tokenapi.CodeCardFree {
		t.Fatalf("card-free describe = %+v, want 403/%s", apiErr, tokenapi.CodeCardFree)
	}

	policy, apiErr := backend.Policy(context.Background())
	if apiErr != nil {
		t.Fatalf("card-free policy = %+v", apiErr)
	}
	if len(policy.EnrolledKeys) != 1 || policy.Aliases["ro"].Target != "ro@example.iam.gserviceaccount.com" {
		t.Fatalf("card-free policy dropped shared configuration: %#v", policy)
	}
	if _, apiErr := backend.Invalidate(context.Background(), forwardapi.InvalidateRequest{
		Version: forwardapi.ProtocolVersion, WorkspaceID: strings.Repeat("b", 32),
	}); apiErr != nil {
		t.Fatalf("card-free invalidation = %+v", apiErr)
	}
}

// What the provider granted has to reach the origin, so the claim can be told
// how much of what it asked for it actually got.
func TestForwardMintReportsTheGrantedWindow(t *testing.T) {
	stub := &stubForwardCore{result: core.SubjectTokenResult{
		IDToken: "h.p.s", ExpiresAt: time.Unix(1785586770, 0), Serial: 12345678, KeyID: "kid",
		GrantedWindowSeconds: 900, GrantedWindowDeadline: 1785587000,
	}}
	backend := forwardBackend{core: stub, logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	req := testForwardMintRequest()
	req.ForwardContext.WindowSeconds = 1800
	req.ForwardContext.WindowDeadline = 1785587900

	response, apiErr := backend.Mint(context.Background(), req)
	if apiErr != nil {
		t.Fatalf("mint = %+v", apiErr)
	}
	if response.GrantedWindowSeconds != 900 || response.GrantedWindowDeadline != 1785587000 {
		t.Errorf("response grant = %ds until %d, want the 900s the provider granted",
			response.GrantedWindowSeconds, response.GrantedWindowDeadline)
	}
	// The request reaches core with the window the claim asked for intact; the
	// clamping is core's, not this backend's.
	if stub.req.ForwardContext.WindowSeconds != 1800 || stub.req.ForwardContext.WindowDeadline != 1785587900 {
		t.Errorf("core saw window %+v, want the claim's own", stub.req.ForwardContext)
	}

	// A mint covered by no window says nothing about one, so the fields stay
	// absent on the wire.
	stub.result.GrantedWindowSeconds, stub.result.GrantedWindowDeadline = 0, 0
	windowless, apiErr := backend.Mint(context.Background(), testForwardMintRequest())
	if apiErr != nil {
		t.Fatalf("windowless mint = %+v", apiErr)
	}
	if windowless.GrantedWindowSeconds != 0 || windowless.GrantedWindowDeadline != 0 {
		t.Errorf("windowless response grant = %ds until %d, want zero",
			windowless.GrantedWindowSeconds, windowless.GrantedWindowDeadline)
	}
}

// The refusal has to survive both hops between the card's operator and the
// agent that caused it: the forwarding socket turns the typed core error into
// the protocol's own code, and the WIF socket relays what the provider said
// rather than restating it as a generic failure.
func TestWindowRefusalReachesTheWIFCallerUnchanged(t *testing.T) {
	refused := &core.WindowNotAllowedError{Requested: 900}
	refusal := mapForwardError(fmt.Errorf("forwarded mint: %w", refused))
	if refusal.Status != http.StatusForbidden || refusal.Code != tokenapi.CodeWindowNotAllowed ||
		!strings.Contains(refusal.Message, refused.Error()) || refusal.Remedy != core.WindowNotAllowedRemedy {
		t.Fatalf("forward mapper = %+v", refusal)
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
	backend := testForwardBackend(t, 0)
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
