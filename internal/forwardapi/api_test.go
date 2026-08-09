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
	mint MintRequest
}

func TestProtocolV2GoldenFixture(t *testing.T) {
	raw, err := os.ReadFile("testdata/pivb_forward_v2.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		MintRequest  json.RawMessage `json:"mint_request"`
		MintResponse json.RawMessage `json:"mint_response"`
	}
	decodeForwardFixture(t, raw, &fixture)

	var request MintRequest
	assertForwardGoldenValue(t, fixture.MintRequest, &request)
	if request.Version != ProtocolVersion {
		t.Fatalf("golden request version = %d, want %d", request.Version, ProtocolVersion)
	}
	var response MintResponse
	assertForwardGoldenValue(t, fixture.MintResponse, &response)
	if response.Version != ProtocolVersion {
		t.Fatalf("golden response version = %d, want %d", response.Version, ProtocolVersion)
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

func TestMintProtocolIsStrictAndVersioned(t *testing.T) {
	backend := &fakeBackend{}
	handler := (&API{Backend: backend}).Handler()
	policyRequest := httptest.NewRequest("GET", "/v1/policy", nil)
	policyResponse := httptest.NewRecorder()
	handler.ServeHTTP(policyResponse, policyRequest)
	if policyResponse.Code != 200 || !strings.Contains(policyResponse.Body.String(), `"version":2`) || !strings.Contains(policyResponse.Body.String(), `"enrolled_keys"`) {
		t.Fatalf("policy response = %d %s", policyResponse.Code, policyResponse.Body.String())
	}
	unknown := httptest.NewRequest("POST", "/v1/mint", strings.NewReader(`{"version":2,"alias":"ro","unknown":true}`))
	unknown.Header.Set("Content-Type", "application/json")
	unknownResponse := httptest.NewRecorder()
	handler.ServeHTTP(unknownResponse, unknown)
	if unknownResponse.Code != 400 || backend.mint.Alias != "" {
		t.Fatalf("unknown-field response = %d %s", unknownResponse.Code, unknownResponse.Body.String())
	}

	wrongVersion := httptest.NewRequest("POST", "/v1/mint", strings.NewReader(`{"version":1,"alias":"ro","external_account_audience":"aud","impersonated_email":"ro@example","expected_card":{"serial":1,"jwk_kid":"kid","spki_der":"c3BraQ=="},"forward_context":{"origin_node_id":"origin","workspace_id":"workspace","bundle":"work","claim_generation":1,"provider_node_id":"provider","operation_id":"op"}}`))
	wrongVersion.Header.Set("Content-Type", "application/json")
	versionResponse := httptest.NewRecorder()
	handler.ServeHTTP(versionResponse, wrongVersion)
	if versionResponse.Code != 400 || !strings.Contains(versionResponse.Body.String(), "unsupported") {
		t.Fatalf("version response = %d %s", versionResponse.Code, versionResponse.Body.String())
	}
}
