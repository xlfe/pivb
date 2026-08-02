package wif_test

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"strings"
	"testing"
	"time"

	"github.com/xlfe/pivb/internal/wif"
)

// The pinned deployment used across the wif goldens.
var testProvider = wif.Provider{
	ProjectNumber: "123456789012",
	PoolID:        "pivb",
	ProviderID:    "yubikey-piv",
	IssuerURI:     "https://auth.example.net/pivb/dep1",
}

const (
	testIssuer      = "https://auth.example.net/pivb/dep1"
	testResource    = "projects/123456789012/locations/global/workloadIdentityPools/pivb/providers/yubikey-piv"
	testExternalAud = "//iam.googleapis.com/projects/123456789012/locations/global/workloadIdentityPools/pivb/providers/yubikey-piv"
	testOIDCAud     = "https://iam.googleapis.com/projects/123456789012/locations/global/workloadIdentityPools/pivb/providers/yubikey-piv"
	testTarget      = "readonly-sa@example-project-id.iam.gserviceaccount.com"
	testJTI         = "MDEyMzQ1Njc4OWFiY2RlZg"
)

// Pinned signing instant: iat is backdated by ClockSkew, exp is iat+Lifetime.
const (
	testNowUnix = int64(1785585600)
	testIat     = int64(1785585570)
	testExp     = int64(1785585870)
)

func loadKey(t *testing.T, name string) *rsa.PrivateKey {
	t.Helper()
	block, _ := pem.Decode(readFixture(t, name))
	if block == nil || block.Type != "RSA PRIVATE KEY" {
		t.Fatalf("fixture %s is not a PKCS#1 RSA private key", name)
	}
	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		t.Fatalf("parse fixture %s: %v", name, err)
	}
	return key
}

func TestProviderDerivations(t *testing.T) {
	if got := testProvider.Resource(); got != testResource {
		t.Errorf("Resource() = %q, want %q", got, testResource)
	}
	if got := testProvider.ExternalAccountAudience(); got != testExternalAud {
		t.Errorf("ExternalAccountAudience() = %q, want %q", got, testExternalAud)
	}
	if got := testProvider.OIDCAudience(); got != testOIDCAud {
		t.Errorf("OIDCAudience() = %q, want %q", got, testOIDCAud)
	}
}

func TestNewJTI(t *testing.T) {
	t.Run("fixed stream", func(t *testing.T) {
		seed := []byte("0123456789abcdef")
		got, err := wif.NewJTI(bytes.NewReader(seed))
		if err != nil {
			t.Fatalf("NewJTI: %v", err)
		}
		if want := base64.RawURLEncoding.EncodeToString(seed); got != want {
			t.Fatalf("NewJTI = %q, want %q", got, want)
		}
		if got != testJTI {
			t.Fatalf("NewJTI = %q, want pinned %q", got, testJTI)
		}
		if strings.Contains(got, "=") {
			t.Errorf("jti %q contains base64 padding", got)
		}
	})

	t.Run("short reader", func(t *testing.T) {
		got, err := wif.NewJTI(bytes.NewReader([]byte("012345678901234")))
		if got != "" {
			t.Errorf("NewJTI = %q, want empty on failure", got)
		}
		requireErrorContains(t, err, "jti")
	})

	t.Run("consumes exactly 128 bits", func(t *testing.T) {
		// A second call must draw fresh bytes rather than reuse the first.
		r := bytes.NewReader([]byte("0123456789abcdefFEDCBA9876543210"))
		first, err := wif.NewJTI(r)
		if err != nil {
			t.Fatalf("first NewJTI: %v", err)
		}
		second, err := wif.NewJTI(r)
		if err != nil {
			t.Fatalf("second NewJTI: %v", err)
		}
		if first == second {
			t.Fatalf("both calls returned %q", first)
		}
		if want := base64.RawURLEncoding.EncodeToString([]byte("FEDCBA9876543210")); second != want {
			t.Fatalf("second NewJTI = %q, want %q", second, want)
		}
	})
}

func TestNewClaimsGolden(t *testing.T) {
	now := time.Unix(testNowUnix, 0).UTC()
	claims, err := wif.NewClaims(testProvider, "ro", testTarget, serialA, kidA, testJTI, now)
	if err != nil {
		t.Fatalf("NewClaims: %v", err)
	}

	want := wif.Claims{
		Iss:    testIssuer,
		Sub:    "pivb-key:" + kidA,
		Aud:    testOIDCAud,
		Iat:    testIat,
		Exp:    testExp,
		Jti:    testJTI,
		Alias:  "ro",
		Target: testTarget,
		Serial: "12345678",
		KeyID:  kidA,
	}
	if claims != want {
		t.Fatalf("NewClaims =\n %+v\nwant\n %+v", claims, want)
	}
	if claims.Exp-claims.Iat != int64(wif.Lifetime/time.Second) {
		t.Errorf("exp-iat = %d, want %d", claims.Exp-claims.Iat, int64(wif.Lifetime/time.Second))
	}
	if claims.Iat != now.Add(-wif.ClockSkew).Unix() {
		t.Errorf("iat = %d, want now-ClockSkew = %d", claims.Iat, now.Add(-wif.ClockSkew).Unix())
	}
	if got, want := claims.ExpiresAt(), time.Unix(testExp, 0).UTC(); !got.Equal(want) {
		t.Errorf("ExpiresAt() = %v, want %v", got, want)
	}
	if !strings.HasPrefix(claims.Sub, wif.SubjectPrefix) {
		t.Errorf("sub %q is not namespaced with %q", claims.Sub, wif.SubjectPrefix)
	}
}

func TestNewClaimsFailsClosed(t *testing.T) {
	type args struct {
		p      wif.Provider
		alias  string
		target string
		serial uint32
		keyID  string
		jti    string
		now    time.Time
	}
	base := args{
		p:      testProvider,
		alias:  "ro",
		target: testTarget,
		serial: serialA,
		keyID:  kidA,
		jti:    testJTI,
		now:    time.Unix(testNowUnix, 0).UTC(),
	}

	tests := []struct {
		name   string
		mutate func(*args)
		want   string
	}{
		{"no project number", func(a *args) { a.p.ProjectNumber = "" }, "incompletely configured"},
		{"no pool id", func(a *args) { a.p.PoolID = "" }, "incompletely configured"},
		{"no provider id", func(a *args) { a.p.ProviderID = "" }, "incompletely configured"},
		{"no issuer uri", func(a *args) { a.p.IssuerURI = "" }, "issuer_uri"},
		{"no alias", func(a *args) { a.alias = "" }, "alias and target"},
		{"no target", func(a *args) { a.target = "" }, "alias and target"},
		{"zero serial", func(a *args) { a.serial = 0 }, "serial must be nonzero"},
		{"no key id", func(a *args) { a.keyID = "" }, "key ID is required"},
		{"no jti", func(a *args) { a.jti = "" }, "jti is required"},
		{"zero time", func(a *args) { a.now = time.Time{} }, "signing time is required"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			a := base
			tc.mutate(&a)
			claims, err := wif.NewClaims(a.p, a.alias, a.target, a.serial, a.keyID, a.jti, a.now)
			if claims != (wif.Claims{}) {
				t.Fatalf("expected zero claims on failure, got %+v", claims)
			}
			requireErrorContains(t, err, tc.want)
		})
	}
}

func TestSigningInputGolden(t *testing.T) {
	claims := wif.Claims{
		Iss:    testIssuer,
		Sub:    "pivb-key:" + kidA,
		Aud:    testOIDCAud,
		Iat:    testIat,
		Exp:    testExp,
		Jti:    testJTI,
		Alias:  "ro",
		Target: testTarget,
		Serial: "12345678",
		KeyID:  kidA,
	}

	input, err := wif.SigningInput(claims)
	if err != nil {
		t.Fatalf("SigningInput: %v", err)
	}
	parts := strings.Split(input, ".")
	if len(parts) != 2 {
		t.Fatalf("signing input has %d segments, want 2: %q", len(parts), input)
	}
	for i, part := range parts {
		if strings.Contains(part, "=") {
			t.Errorf("segment %d contains base64 padding: %q", i, part)
		}
		if _, err := base64.RawURLEncoding.DecodeString(part); err != nil {
			t.Errorf("segment %d is not unpadded base64url: %v", i, err)
		}
	}

	// Wire format is pinned field by field, in order: Google verifies these
	// bytes and the attribute condition reads these exact claim names.
	wantHeader := `{"alg":"RS256","typ":"JWT","kid":"` + kidA + `"}`
	wantPayload := `{"iss":"` + testIssuer +
		`","sub":"pivb-key:` + kidA +
		`","aud":"` + testOIDCAud +
		`","iat":1785585570,"exp":1785585870,"jti":"` + testJTI +
		`","alias":"ro","target":"` + testTarget +
		`","serial":"12345678","key_id":"` + kidA + `"}`

	gotHeader, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatalf("decode header: %v", err)
	}
	if string(gotHeader) != wantHeader {
		t.Errorf("header =\n %s\nwant\n %s", gotHeader, wantHeader)
	}
	gotPayload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	if string(gotPayload) != wantPayload {
		t.Errorf("payload =\n %s\nwant\n %s", gotPayload, wantPayload)
	}
}

func TestSigningInputRequiresKeyID(t *testing.T) {
	input, err := wif.SigningInput(wif.Claims{Iss: testIssuer, Sub: "pivb-key:x"})
	if input != "" {
		t.Errorf("SigningInput = %q, want empty on failure", input)
	}
	requireErrorContains(t, err, "no key ID")
}

func TestSignAndVerifyEndToEnd(t *testing.T) {
	cert := loadCert(t, "cert-a.pem")
	key := loadKey(t, "key-a.pem")
	pub, err := wif.RSAPublicKey(cert)
	if err != nil {
		t.Fatalf("RSAPublicKey: %v", err)
	}

	claims, err := wif.NewClaims(testProvider, "ro", testTarget, serialA, kidA, testJTI, time.Unix(testNowUnix, 0).UTC())
	if err != nil {
		t.Fatalf("NewClaims: %v", err)
	}
	input, err := wif.SigningInput(claims)
	if err != nil {
		t.Fatalf("SigningInput: %v", err)
	}

	digest := wif.SigningDigest(input)
	if sum := sha256.Sum256([]byte(input)); !bytes.Equal(digest, sum[:]) {
		t.Fatalf("SigningDigest is not SHA-256 of the signing input")
	}
	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	jws, err := wif.Assemble(input, signature)
	if err != nil {
		t.Fatalf("Assemble: %v", err)
	}
	parts := strings.Split(jws, ".")
	if len(parts) != 3 {
		t.Fatalf("compact JWS has %d segments, want 3: %q", len(parts), jws)
	}
	if !strings.HasPrefix(jws, input+".") {
		t.Fatalf("compact JWS does not begin with the signed input")
	}

	verify := func(signingInput string) error {
		sum := sha256.Sum256([]byte(signingInput))
		raw, err := base64.RawURLEncoding.DecodeString(parts[2])
		if err != nil {
			t.Fatalf("decode signature: %v", err)
		}
		return rsa.VerifyPKCS1v15(pub, crypto.SHA256, sum[:], raw)
	}

	if err := verify(parts[0] + "." + parts[1]); err != nil {
		t.Fatalf("verify a well-formed token: %v", err)
	}

	tampered := []byte(parts[1])
	if tampered[0] == 'A' {
		tampered[0] = 'B'
	} else {
		tampered[0] = 'A'
	}
	if err := verify(parts[0] + "." + string(tampered)); err == nil {
		t.Fatalf("verification accepted a tampered payload")
	}
}

func TestAssemble(t *testing.T) {
	t.Run("joins input and signature", func(t *testing.T) {
		signature := []byte{0x01, 0x02, 0x03}
		got, err := wif.Assemble("aGVhZGVy.cGF5bG9hZA", signature)
		if err != nil {
			t.Fatalf("Assemble: %v", err)
		}
		want := "aGVhZGVy.cGF5bG9hZA." + base64.RawURLEncoding.EncodeToString(signature)
		if got != want {
			t.Fatalf("Assemble = %q, want %q", got, want)
		}
	})

	tests := []struct {
		name      string
		input     string
		signature []byte
		want      string
	}{
		{"empty input", "", []byte{0x01}, "empty JWS signing input"},
		{"nil signature", "aGVhZGVy.cGF5bG9hZA", nil, "empty RS256 signature"},
		{"zero length signature", "aGVhZGVy.cGF5bG9hZA", []byte{}, "empty RS256 signature"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := wif.Assemble(tc.input, tc.signature)
			if got != "" {
				t.Errorf("Assemble = %q, want empty on failure", got)
			}
			requireErrorContains(t, err, tc.want)
		})
	}
}
