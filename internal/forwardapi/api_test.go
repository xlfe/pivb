package forwardapi

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/xlfe/pivb/internal/tokenapi"
)

type fakeBackend struct {
	mint       MintRequest
	invalidate InvalidateRequest
	purged     int
}

// The fixture is byte-identical to ZKA's copy at
// internal/zka/testdata/pivb_forward_v3.json. Both repos assert that their own
// wire structs re-marshal to exactly these bytes, so the two ends of the
// forward protocol cannot drift apart without one of the two suites failing.
func TestProtocolV3GoldenFixture(t *testing.T) {
	raw, err := os.ReadFile("testdata/pivb_forward_v3.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		MintRequest        json.RawMessage `json:"mint_request"`
		MintResponse       json.RawMessage `json:"mint_response"`
		Policy             json.RawMessage `json:"policy"`
		Description        json.RawMessage `json:"description"`
		InvalidateRequest  json.RawMessage `json:"invalidate_request"`
		InvalidateResponse json.RawMessage `json:"invalidate_response"`
	}
	decodeForwardFixture(t, raw, &fixture)

	var request MintRequest
	assertForwardGoldenValue(t, fixture.MintRequest, &request)
	var response MintResponse
	assertForwardGoldenValue(t, fixture.MintResponse, &response)
	var policy Policy
	assertForwardGoldenValue(t, fixture.Policy, &policy)
	var description Description
	assertForwardGoldenValue(t, fixture.Description, &description)
	var invalidateRequest InvalidateRequest
	assertForwardGoldenValue(t, fixture.InvalidateRequest, &invalidateRequest)
	var invalidateResponse InvalidateResponse
	assertForwardGoldenValue(t, fixture.InvalidateResponse, &invalidateResponse)

	for name, version := range map[string]int{
		"mint request": request.Version, "mint response": response.Version,
		"policy": policy.Version, "description": description.Version,
		"invalidate request": invalidateRequest.Version, "invalidate response": invalidateResponse.Version,
	} {
		if version != ProtocolVersion {
			t.Errorf("golden %s version = %d, want %d", name, version, ProtocolVersion)
		}
	}
	// Every protocol 3 addition is omitempty, so only non-zero fixture values
	// prove the fields reach the wire at all.
	if request.ForwardContext.WindowSeconds == 0 || request.ForwardContext.WindowDeadline == 0 ||
		response.GrantedWindowSeconds == 0 || response.GrantedWindowDeadline == 0 ||
		policy.MaxGrantWindowS == 0 || description.MaxGrantWindowS == 0 ||
		policy.Aliases["deploy"].AssertionLifetimeS == 0 || description.Aliases["deploy"].AssertionLifetimeS == 0 {
		t.Fatal("golden fixture does not pin the protocol 3 window and assertion-lifetime fields")
	}
}

func assertForwardGoldenValue(t *testing.T, raw json.RawMessage, value any) {
	t.Helper()
	decodeForwardFixture(t, raw, value)
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	var compact bytes.Buffer
	if err := json.Compact(&compact, raw); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(encoded, compact.Bytes()) {
		t.Fatalf("wire encoding changed\n got: %s\nwant: %s", encoded, compact.Bytes())
	}
}

func decodeForwardFixture(t *testing.T, raw []byte, value any) {
	t.Helper()
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		t.Fatal(err)
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		t.Fatalf("fixture contains multiple JSON values: %v", err)
	}
}

func (f *fakeBackend) Policy(context.Context) (Policy, *tokenapi.APIError) {
	return Policy{ProviderResource: "projects/1/provider", IssuerURI: "https://issuer.example", Aliases: map[string]AliasBinding{"ro": {Target: "ro@example"}}, EnrolledKeys: []EnrolledKey{{Serial: 1, KeyID: "kid"}}}, nil
}

func (f *fakeBackend) Describe(context.Context) (Description, *tokenapi.APIError) {
	return Description{ProviderResource: "projects/1/provider", IssuerURI: "https://issuer.example", Aliases: map[string]AliasBinding{"ro": {Target: "ro@example"}}, Card: CardIdentity{Serial: 1, KeyID: "kid", SPKIDER: []byte("spki")}}, nil
}

func (f *fakeBackend) Mint(_ context.Context, req MintRequest) (MintResponse, *tokenapi.APIError) {
	f.mint = req
	return MintResponse{
		IDToken: "h.p.s", ExpirationTime: 123, Card: req.ExpectedCard,
		ExpectedCard: req.ExpectedCard, ForwardContext: req.ForwardContext,
	}, nil
}

func (f *fakeBackend) Invalidate(_ context.Context, req InvalidateRequest) (InvalidateResponse, *tokenapi.APIError) {
	f.invalidate = req
	return InvalidateResponse{Purged: f.purged}, nil
}

func TestMintProtocolIsStrictAndVersioned(t *testing.T) {
	backend := &fakeBackend{}
	handler := (&API{Backend: backend}).Handler()
	policyRequest := httptest.NewRequest("GET", "/v1/policy", nil)
	policyResponse := httptest.NewRecorder()
	handler.ServeHTTP(policyResponse, policyRequest)
	if policyResponse.Code != 200 || !strings.Contains(policyResponse.Body.String(), `"version":3`) || !strings.Contains(policyResponse.Body.String(), `"enrolled_keys"`) {
		t.Fatalf("policy response = %d %s", policyResponse.Code, policyResponse.Body.String())
	}
	unknown := httptest.NewRequest("POST", "/v1/mint", strings.NewReader(`{"version":3,"alias":"ro","unknown":true}`))
	unknown.Header.Set("Content-Type", "application/json")
	unknownResponse := httptest.NewRecorder()
	handler.ServeHTTP(unknownResponse, unknown)
	if unknownResponse.Code != 400 || backend.mint.Alias != "" {
		t.Fatalf("unknown-field response = %d %s", unknownResponse.Code, unknownResponse.Body.String())
	}

	// A complete request from a protocol 2 peer: it decodes cleanly against
	// these structs, and only the version says it must be refused.
	wrongVersion := httptest.NewRequest("POST", "/v1/mint", strings.NewReader(`{"version":2,"alias":"ro","external_account_audience":"aud","impersonated_email":"ro@example","expected_card":{"serial":1,"jwk_kid":"kid","spki_der":"c3BraQ=="},"forward_context":{"origin_node_id":"origin","workspace_id":"workspace","bundle":"work","claim_generation":1,"provider_node_id":"provider","operation_id":"op"}}`))
	wrongVersion.Header.Set("Content-Type", "application/json")
	versionResponse := httptest.NewRecorder()
	handler.ServeHTTP(versionResponse, wrongVersion)
	if versionResponse.Code != 400 || !strings.Contains(versionResponse.Body.String(), "unsupported") || backend.mint.Alias != "" {
		t.Fatalf("version response = %d %s", versionResponse.Code, versionResponse.Body.String())
	}
}

// A peer one protocol behind sends a body this build cannot strictly decode.
// Answering that with "send the fixed request shape" points the operator at
// the request instead of at the skew, so the version is read first.
func TestVersionSkewIsReportedAsAnUpgradeNotAMalformedRequest(t *testing.T) {
	backend := &fakeBackend{}
	handler := (&API{Backend: backend}).Handler()
	for _, path := range []string{"/v1/mint", "/v1/invalidate"} {
		t.Run(path, func(t *testing.T) {
			request := httptest.NewRequest("POST", path, strings.NewReader(`{"version":2,"alias":"ro","workspace_id":"workspace","retired_v2_field":true}`))
			request.Header.Set("Content-Type", "application/json")
			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, request)
			var body tokenapi.ErrorResponse
			if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
				t.Fatal(err)
			}
			if recorder.Code != 400 || body.Code != tokenapi.CodeConfig ||
				!strings.Contains(body.Error, "unsupported PIVB forwarding protocol 2") ||
				body.Remedy != "upgrade PIVB and ZKA together" {
				t.Fatalf("skewed request = %d %+v", recorder.Code, body)
			}
		})
	}
	if backend.mint.Alias != "" || backend.invalidate.WorkspaceID != "" {
		t.Fatalf("a skewed request reached the backend: %+v %+v", backend.mint, backend.invalidate)
	}
}

func TestInvalidateIsStrictVersionedAndReportsPurgeCount(t *testing.T) {
	backend := &fakeBackend{purged: 3}
	handler := (&API{Backend: backend}).Handler()
	workspace := strings.Repeat("b", 32)
	request := httptest.NewRequest("POST", "/v1/invalidate", strings.NewReader(`{"version":3,"workspace_id":"`+workspace+`","claim_generation":7}`))
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	var response InvalidateResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if recorder.Code != 200 || response.Version != ProtocolVersion || response.Purged != 3 {
		t.Fatalf("invalidate response = %d %+v", recorder.Code, response)
	}
	if backend.invalidate.WorkspaceID != workspace || backend.invalidate.ClaimGeneration != 7 {
		t.Fatalf("backend received %+v", backend.invalidate)
	}

	backend.invalidate = InvalidateRequest{}
	unknown := httptest.NewRequest("POST", "/v1/invalidate", strings.NewReader(`{"version":3,"workspace_id":"`+workspace+`","max_generation":7}`))
	unknown.Header.Set("Content-Type", "application/json")
	unknownRecorder := httptest.NewRecorder()
	handler.ServeHTTP(unknownRecorder, unknown)
	if unknownRecorder.Code != 400 || backend.invalidate.WorkspaceID != "" {
		t.Fatalf("unknown-field invalidate = %d %s", unknownRecorder.Code, unknownRecorder.Body.String())
	}
}
