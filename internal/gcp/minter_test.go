package gcp

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/xlfe/pivb/internal/config"
)

type recordingSigner struct {
	digest []byte
	sig    []byte
	key    *rsa.PrivateKey
	serial uint32
	signs  int
}

func (s *recordingSigner) VerifyPIN(context.Context, string) (uint32, int, error) {
	return 42, 3, nil
}

func (s *recordingSigner) Sign(_ context.Context, alias, pin string, digestFor func(uint32) ([]byte, error)) ([]byte, uint32, error) {
	if alias == "" || pin == "" {
		return nil, 0, fmt.Errorf("missing signing context")
	}
	serial := s.serial
	if serial == 0 {
		serial = 42
	}
	digest, err := digestFor(serial)
	if err != nil {
		return nil, serial, err
	}
	s.signs++
	s.digest = append([]byte(nil), digest...)
	if s.key != nil {
		sig, err := rsa.SignPKCS1v15(rand.Reader, s.key, crypto.SHA256, digest)
		return sig, serial, err
	}
	return append([]byte(nil), s.sig...), serial, nil
}

func TestJWSGolden(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	signer := &recordingSigner{sig: []byte{1, 2, 3}, serial: 23456789}
	var assertion string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/token":
			if err := r.ParseForm(); err != nil {
				t.Error(err)
			}
			assertion = r.Form.Get("assertion")
			fmt.Fprint(w, `{"access_token":"broker-token"}`)
		case strings.HasSuffix(r.URL.Path, ":generateAccessToken"):
			fmt.Fprintf(w, `{"accessToken":"target-token","expireTime":%q}`, now.Add(time.Hour).Format(time.RFC3339))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	m := &Minter{Signer: signer, BrokerSA: "broker@example.test", KeyIDs: map[uint32]string{12345678: "kid-1", 23456789: "kid-2"}, OAuthURL: server.URL + "/token", IAMURL: server.URL, Now: func() time.Time { return now }}
	_, err := m.MintAccess(context.Background(), "ro", config.Alias{Target: "ro@example.test", LifetimeS: 3600}, "123456")
	if err != nil {
		t.Fatal(err)
	}
	header := `{"alg":"RS256","typ":"JWT","kid":"kid-2"}`
	claims := `{"iss":"broker@example.test","sub":"broker@example.test","aud":"https://oauth2.googleapis.com/token","scope":"https://www.googleapis.com/auth/cloud-platform","iat":1700000000,"exp":1700000600}`
	input := base64.RawURLEncoding.EncodeToString([]byte(header)) + "." + base64.RawURLEncoding.EncodeToString([]byte(claims))
	wantAssertion := input + "." + base64.RawURLEncoding.EncodeToString([]byte{1, 2, 3})
	if assertion != wantAssertion {
		t.Fatalf("assertion mismatch\n got: %s\nwant: %s", assertion, wantAssertion)
	}
	wantDigest := sha256.Sum256([]byte(input))
	if string(signer.digest) != string(wantDigest[:]) {
		t.Fatalf("signer digest mismatch: %x != %x", signer.digest, wantDigest)
	}
}

func TestMintAccessIntegrationAndBrokerTokenWipe(t *testing.T) {
	private, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_800_000_000, 0).UTC()
	signer := &recordingSigner{key: private}
	wipeCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/token":
			if r.Header.Get("Content-Type") != "application/x-www-form-urlencoded" {
				t.Errorf("oauth content type = %q", r.Header.Get("Content-Type"))
			}
			if err := r.ParseForm(); err != nil {
				t.Error(err)
			}
			verifyAssertion(t, r.Form, &private.PublicKey, now)
			fmt.Fprint(w, `{"access_token":"ephemeral-broker"}`)
		case strings.HasSuffix(r.URL.Path, ":generateAccessToken"):
			if got := r.Header.Get("Authorization"); got != "Bearer ephemeral-broker" {
				t.Errorf("Authorization = %q", got)
			}
			var body struct {
				Scope    []string `json:"scope"`
				Lifetime string   `json:"lifetime"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Error(err)
			}
			if body.Lifetime != "7200s" || len(body.Scope) != 1 || body.Scope[0] != cloudScope {
				t.Errorf("IAM body = %#v", body)
			}
			fmt.Fprintf(w, `{"accessToken":"target-access","expireTime":%q}`, now.Add(2*time.Hour).Format(time.RFC3339))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	m := &Minter{
		Signer: signer, BrokerSA: "broker@example.test", KeyIDs: map[uint32]string{42: "key-id"},
		OAuthURL: server.URL + "/token", IAMURL: server.URL, Now: func() time.Time { return now },
		TokenWiped: func(b []byte) {
			wipeCount++
			for i, value := range b {
				if value != 0 {
					t.Errorf("broker secret byte %d not wiped", i)
				}
			}
		},
	}
	token, err := m.MintAccess(context.Background(), "deploy", config.Alias{Target: "target@example.test", LifetimeS: 7200}, "654321")
	if err != nil {
		t.Fatal(err)
	}
	if token.Value != "target-access" || !token.ExpiresAt.Equal(now.Add(2*time.Hour)) || token.Serial != 42 {
		t.Fatalf("token = %#v", token)
	}
	if wipeCount != 2 {
		t.Fatalf("broker secret wipe hook called %d times, want response body and extracted token", wipeCount)
	}
}

func TestMintIdentityParsesExpiry(t *testing.T) {
	now := time.Unix(1_800_000_000, 0).UTC()
	payload, _ := json.Marshal(map[string]int64{"exp": now.Add(time.Hour).Unix()})
	idJWT := "e30." + base64.RawURLEncoding.EncodeToString(payload) + ".sig"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/token":
			fmt.Fprint(w, `{"access_token":"broker"}`)
		case strings.HasSuffix(r.URL.Path, ":generateIdToken"):
			var body map[string]any
			_ = json.NewDecoder(r.Body).Decode(&body)
			if body["audience"] != "https://service.test" || body["includeEmail"] != true {
				t.Errorf("identity body = %#v", body)
			}
			_ = json.NewEncoder(w).Encode(map[string]string{"token": idJWT})
		}
	}))
	defer server.Close()
	m := &Minter{Signer: &recordingSigner{sig: []byte{1}}, BrokerSA: "b", KeyIDs: map[uint32]string{42: "k"}, OAuthURL: server.URL + "/token", IAMURL: server.URL, Now: func() time.Time { return now }}
	token, err := m.MintIdentity(context.Background(), "ro", config.Alias{Target: "t"}, "https://service.test", "1")
	if err != nil {
		t.Fatal(err)
	}
	if token.Value != idJWT || !token.ExpiresAt.Equal(now.Add(time.Hour)) {
		t.Fatalf("ID token = %#v", token)
	}
}

func TestProviderErrorHasStatusAndBoundedBody(t *testing.T) {
	large := strings.Repeat("x", maxErrorBody+100)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprint(w, large)
	}))
	defer server.Close()
	m := &Minter{Signer: &recordingSigner{sig: []byte{1}}, BrokerSA: "b", KeyIDs: map[uint32]string{42: "k"}, OAuthURL: server.URL}
	_, err := m.MintAccess(context.Background(), "ro", config.Alias{Target: "t", LifetimeS: 1}, "1")
	if err == nil || !strings.Contains(err.Error(), "HTTP 400 Bad Request") || !strings.Contains(err.Error(), "truncated") {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(err.Error()) > maxErrorBody+1000 {
		t.Fatalf("provider error was not bounded: %d bytes", len(err.Error()))
	}
}

func TestUnknownSignerSerialFailsBeforeSignatureOrProviderCall(t *testing.T) {
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		requests++
	}))
	defer server.Close()
	signer := &recordingSigner{sig: []byte{1}, serial: 99}
	m := &Minter{
		Signer: signer, BrokerSA: "broker@example.test", KeyIDs: map[uint32]string{42: "known-key"},
		OAuthURL: server.URL, IAMURL: server.URL,
	}
	_, err := m.MintAccess(context.Background(), "ro", config.Alias{Target: "ro@example.test", LifetimeS: 3600}, "123456")
	if err == nil || !strings.Contains(err.Error(), "no configured key_id for YubiKey 99") {
		t.Fatalf("unexpected error: %v", err)
	}
	if signer.signs != 0 || requests != 0 {
		t.Fatalf("unknown serial performed %d signatures and %d provider requests", signer.signs, requests)
	}
}

func verifyAssertion(t *testing.T, form url.Values, public *rsa.PublicKey, now time.Time) {
	t.Helper()
	if form.Get("grant_type") != "urn:ietf:params:oauth:grant-type:jwt-bearer" {
		t.Errorf("grant_type = %q", form.Get("grant_type"))
	}
	parts := strings.Split(form.Get("assertion"), ".")
	if len(parts) != 3 {
		t.Fatalf("assertion has %d parts", len(parts))
	}
	headerBytes, _ := base64.RawURLEncoding.DecodeString(parts[0])
	claimsBytes, _ := base64.RawURLEncoding.DecodeString(parts[1])
	var header map[string]any
	var claims map[string]any
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(claimsBytes, &claims); err != nil {
		t.Fatal(err)
	}
	if header["alg"] != "RS256" || header["kid"] != "key-id" || claims["iss"] != "broker@example.test" {
		t.Errorf("header=%v claims=%v", header, claims)
	}
	if int64(claims["iat"].(float64)) != now.Unix() || int64(claims["exp"].(float64)) != now.Add(10*time.Minute).Unix() {
		t.Errorf("assertion times = %v", claims)
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		t.Fatal(err)
	}
	if err := rsa.VerifyPKCS1v15(public, crypto.SHA256, digest[:], sig); err != nil {
		t.Fatalf("verify assertion: %v", err)
	}
}
