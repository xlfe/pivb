package core

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/xlfe/pivb/internal/config"
	"github.com/xlfe/pivb/internal/pivsigner"
)

const (
	// Key identifiers of the shared fixtures in ../wif/testdata, derived from
	// the SubjectPublicKeyInfo digest the daemon recomputes at signing time.
	kidA = "g4tW--9GFcDvwdryp8vTG76EyUg-QhfOEjBo0YQg3Wg"
	kidB = "klDBeSjlLGunctWm3FyntSOcV9bk3MZ9pNbuDxn_E-I"

	roTarget     = "readonly-sa@example-project-id.iam.gserviceaccount.com"
	deployTarget = "deployment-sa@example-project-id.iam.gserviceaccount.com"

	testIssuer           = "https://auth.example.net/pivb/dep1"
	testResource         = "projects/123456789012/locations/global/workloadIdentityPools/pivb/providers/yubikey-piv"
	testExternalAudience = "//iam.googleapis.com/" + testResource
	testOIDCAudience     = "https://iam.googleapis.com/" + testResource

	pinA = "123456"
	pinB = "654321"

	testVersion = "test"

	// testJTISeed is drained 16 bytes at a time by wif.NewJTI; testJTI is the
	// base64url encoding of the first block.
	testJTISeed = "0123456789abcdef"
	testJTI     = "MDEyMzQ1Njc4OWFiY2RlZg"

	// The fixed signing instant, and the iat/exp it must produce: iat is
	// backdated by wif.ClockSkew and exp is iat plus wif.Lifetime.
	testNowUnix = 1785585600
	testIatUnix = 1785585570
	testExpUnix = 1785585870
)

const (
	serialA uint32 = 12345678
	serialB uint32 = 23456789
	// serialUnknown is a card that no configuration enrolls.
	serialUnknown uint32 = 99999
)

// fixtureKey is one enrolled card's certificate and the matching private key,
// standing in for the RSA-2048 key material in PIV slot 9c.
type fixtureKey struct {
	cert *x509.Certificate
	key  *rsa.PrivateKey
}

func loadFixture(t *testing.T, name string) fixtureKey {
	t.Helper()
	cert := fixtureKey{}
	certPEM, err := os.ReadFile("../wif/testdata/cert-" + name + ".pem")
	if err != nil {
		t.Fatalf("read certificate fixture %s: %v", name, err)
	}
	block, _ := pem.Decode(certPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		t.Fatalf("certificate fixture %s is not a single CERTIFICATE PEM block", name)
	}
	if cert.cert, err = x509.ParseCertificate(block.Bytes); err != nil {
		t.Fatalf("parse certificate fixture %s: %v", name, err)
	}
	keyPEM, err := os.ReadFile("../wif/testdata/key-" + name + ".pem")
	if err != nil {
		t.Fatalf("read key fixture %s: %v", name, err)
	}
	block, _ = pem.Decode(keyPEM)
	if block == nil || block.Type != "RSA PRIVATE KEY" {
		t.Fatalf("key fixture %s is not a single RSA PRIVATE KEY PEM block", name)
	}
	if cert.key, err = x509.ParsePKCS1PrivateKey(block.Bytes); err != nil {
		t.Fatalf("parse key fixture %s: %v", name, err)
	}
	return cert
}

func (f fixtureKey) public(t *testing.T) *rsa.PublicKey {
	t.Helper()
	pub, ok := f.cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		t.Fatalf("fixture certificate holds a %T, not an RSA public key", f.cert.PublicKey)
	}
	return pub
}

// signerCounts records how much card work a test provoked. It is comparable so
// a test can assert that an operation touched no hardware at all.
type signerCounts struct {
	verifies       int
	swapVerifies   int
	signatures     int
	digestRequests int
}

// fakeSigner reproduces the observable contract of pivsigner.Hardware: it reads
// the live certificate of whichever card is currently inserted, offers it to
// digestFor before any PIN is spent, applies the fleet swap rules, and only
// then signs with that card's key.
type fakeSigner struct {
	// current is the inserted card; verified is the card the cached PIN has
	// already been checked against in an earlier session.
	current  uint32
	verified uint32

	cards   map[uint32]fixtureKey
	pins    map[uint32]string
	retries map[uint32]int

	labels []string
	counts signerCounts
}

func (s *fakeSigner) VerifyPIN(_ context.Context, pin string) (uint32, int, error) {
	s.counts.verifies++
	retries := s.retries[s.current]
	if pin != s.pins[s.current] {
		return s.current, retries - 1, &pivsigner.PINError{Retries: retries - 1, Err: errors.New("wrong PIN")}
	}
	s.verified = s.current
	return s.current, retries, nil
}

func (s *fakeSigner) Sign(_ context.Context, label, pin string, digestFor func(uint32, *x509.Certificate) ([]byte, error)) ([]byte, uint32, error) {
	serial := s.current
	s.labels = append(s.labels, label)
	card, present := s.cards[serial]
	if !present {
		return nil, 0, fmt.Errorf("read certificate from PIV slot 9c on YubiKey %d: no card registered in the fake", serial)
	}

	// Hardware builds the digest before spending any PIN attempt, and reports
	// no serial when that fails: a nonzero serial is the signal that the cached
	// PIN was verified against the card during this operation.
	s.counts.digestRequests++
	digest, err := digestFor(serial, card.cert)
	if err != nil {
		return nil, 0, fmt.Errorf("build signing digest for YubiKey %d: %w", serial, err)
	}

	// Both swap failures below report the serial. pivsigner.Hardware reports
	// zero there instead, because the cached PIN was not in fact verified
	// against the card. Core discards the serial for any *PINError, so the two
	// behave alike, but an assertion that depends on the difference is only
	// testing this fake.
	if serial != s.verified {
		retries := s.retries[serial]
		if retries <= 1 {
			return nil, serial, &pivsigner.PINError{
				Retries: retries,
				Err:     fmt.Errorf("refusing to try the cached PIN on swapped YubiKey %d and spend the final PIN attempt", serial),
				Remedy:  "run `pivb unlock` with this key inserted after checking or resetting its PIV PIN",
			}
		}
		s.counts.swapVerifies++
		if pin != s.pins[serial] {
			s.verified = 0
			return nil, serial, &pivsigner.PINError{
				Retries:        retries - 1,
				Err:            fmt.Errorf("cached PIN was rejected by swapped YubiKey %d; fleet keys may have different PINs", serial),
				Remedy:         "run `pivb unlock` with this key inserted",
				ClearCachedPIN: true,
			}
		}
		s.verified = serial
	}

	sig, err := rsa.SignPKCS1v15(rand.Reader, card.key, crypto.SHA256, digest)
	if err != nil {
		return nil, serial, fmt.Errorf("sign with PIV slot 9c on YubiKey %d: %w", serial, err)
	}
	s.counts.signatures++
	return sig, serial, nil
}

func testConfig(mode string) *config.Config {
	return &config.Config{
		PIVSlot:  "9c",
		PINCache: mode,
		WIF: config.WIF{
			ProjectNumber: "123456789012",
			PoolID:        "pivb",
			ProviderID:    "yubikey-piv",
			IssuerURI:     testIssuer,
		},
		Keys: map[string]config.Key{
			"12345678": {JWKKid: kidA},
			"23456789": {JWKKid: kidB},
		},
		Aliases: map[string]config.Alias{
			"ro":     {Cloud: "gcp", Target: roTarget, LifetimeS: 3600},
			"deploy": {Cloud: "gcp", Target: deployTarget, LifetimeS: 3600},
		},
	}
}

// newTestCore builds a core over a two-key fleet that shares one PIN, with
// `inserted` presented as the card in the reader.
func newTestCore(t *testing.T, cfg *config.Config, inserted uint32) (*Core, *fakeSigner) {
	t.Helper()
	signer := &fakeSigner{
		current: inserted,
		cards:   map[uint32]fixtureKey{serialA: loadFixture(t, "a"), serialB: loadFixture(t, "b")},
		pins:    map[uint32]string{serialA: pinA, serialB: pinA},
		retries: map[uint32]int{serialA: 3, serialB: 3},
	}
	return New(cfg, signer, testVersion), signer
}

// fixClock pins the signing instant and the jti stream so a minted token is
// byte-for-byte predictable.
func fixClock(c *Core) time.Time {
	now := time.Unix(testNowUnix, 0).UTC()
	c.SetNowForTest(func() time.Time { return now })
	c.SetRandomForTest(strings.NewReader(strings.Repeat(testJTISeed, 8)))
	return now
}

func roRequest() SubjectTokenRequest {
	return SubjectTokenRequest{
		Alias:                   "ro",
		ExternalAccountAudience: testExternalAudience,
		ImpersonatedEmail:       roTarget,
	}
}

func deployRequest() SubjectTokenRequest {
	return SubjectTokenRequest{
		Alias:                   "deploy",
		ExternalAccountAudience: testExternalAudience,
		ImpersonatedEmail:       deployTarget,
	}
}

func unlockOK(t *testing.T, c *Core, pin string) {
	t.Helper()
	if _, err := c.Unlock(context.Background(), pin); err != nil {
		t.Fatalf("Unlock: %v", err)
	}
}

func mintOK(t *testing.T, c *Core, req SubjectTokenRequest) SubjectTokenResult {
	t.Helper()
	result, err := c.SubjectToken(context.Background(), req)
	if err != nil {
		t.Fatalf("SubjectToken(%s): %v", req.Alias, err)
	}
	return result
}

// decodedToken is a parsed compact JWS, kept in wire form so assertions check
// what a verifier actually receives rather than what the daemon meant to send.
type decodedToken struct {
	header    string
	claims    map[string]any
	signature []byte
	input     string
}

func parseToken(t *testing.T, token string) decodedToken {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("token has %d segments, want 3: %q", len(parts), token)
	}
	enc := base64.RawURLEncoding
	head, err := enc.DecodeString(parts[0])
	if err != nil {
		t.Fatalf("decode JWS header: %v", err)
	}
	body, err := enc.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decode JWT claims: %v", err)
	}
	sig, err := enc.DecodeString(parts[2])
	if err != nil {
		t.Fatalf("decode RS256 signature: %v", err)
	}
	claims := map[string]any{}
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	if err := dec.Decode(&claims); err != nil {
		t.Fatalf("unmarshal JWT claims: %v", err)
	}
	return decodedToken{header: string(head), claims: claims, signature: sig, input: parts[0] + "." + parts[1]}
}

func (d decodedToken) verify(t *testing.T, pub *rsa.PublicKey) {
	t.Helper()
	digest := sha256.Sum256([]byte(d.input))
	if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest[:], d.signature); err != nil {
		t.Fatalf("RS256 signature does not verify against the expected card key: %v", err)
	}
}

func TestLockedCoreMintsNothingAndNeverCachesARejectedPIN(t *testing.T) {
	c, signer := newTestCore(t, testConfig("session"), serialA)

	if _, err := c.SubjectToken(context.Background(), roRequest()); !errors.Is(err, ErrLocked) {
		t.Fatalf("SubjectToken before Unlock error = %v, want ErrLocked", err)
	}

	if retries, err := c.Unlock(context.Background(), ""); err == nil || retries != -1 {
		t.Errorf("Unlock with an empty PIN = (%d, %v), want (-1, non-nil)", retries, err)
	}

	retries, err := c.Unlock(context.Background(), "999999")
	var pinErr *pivsigner.PINError
	if !errors.As(err, &pinErr) {
		t.Fatalf("Unlock with the wrong PIN error = %v, want *pivsigner.PINError", err)
	}
	if pinErr.Retries != 2 || retries != 2 {
		t.Errorf("wrong-PIN retries = %d (Unlock returned %d), want 2", pinErr.Retries, retries)
	}

	if status := c.Status(); status.PINCached || status.PINVerifiedSerial != 0 {
		t.Errorf("a rejected PIN was cached: %#v", status)
	}
	if _, err := c.SubjectToken(context.Background(), roRequest()); !errors.Is(err, ErrLocked) {
		t.Fatalf("SubjectToken after a failed Unlock error = %v, want ErrLocked", err)
	}
	if signer.counts.signatures != 0 || signer.counts.digestRequests != 0 {
		t.Errorf("a locked core reached the card: %+v", signer.counts)
	}
}

func TestSubjectTokenMintsAnAssertionBoundToTheLiveKey(t *testing.T) {
	c, signer := newTestCore(t, testConfig("session"), serialA)
	now := fixClock(c)
	unlockOK(t, c, pinA)

	result := mintOK(t, c, roRequest())
	token := parseToken(t, result.IDToken)
	token.verify(t, signer.cards[serialA].public(t))

	wantHeader := `{"alg":"RS256","typ":"JWT","kid":"` + kidA + `"}`
	if token.header != wantHeader {
		t.Errorf("JWS header = %s, want %s", token.header, wantHeader)
	}

	wantClaims := []struct {
		name string
		want any
	}{
		{"iss", testIssuer},
		{"sub", "pivb-key:" + kidA},
		{"aud", testOIDCAudience},
		{"iat", json.Number("1785585570")},
		{"exp", json.Number("1785585870")},
		{"jti", testJTI},
		{"alias", "ro"},
		{"target", roTarget},
		{"serial", "12345678"},
		{"key_id", kidA},
	}
	for _, claim := range wantClaims {
		if got := token.claims[claim.name]; got != claim.want {
			t.Errorf("claim %q = %#v, want %#v", claim.name, got, claim.want)
		}
	}
	if len(token.claims) != len(wantClaims) {
		t.Errorf("payload carries %d claims, want exactly %d: %v", len(token.claims), len(wantClaims), token.claims)
	}

	if want := time.Unix(testExpUnix, 0).UTC(); !result.ExpiresAt.Equal(want) {
		t.Errorf("result.ExpiresAt = %s, want %s", result.ExpiresAt, want)
	}
	if result.Serial != serialA || result.KeyID != kidA {
		t.Errorf("result serial/key = %d/%s, want %d/%s", result.Serial, result.KeyID, serialA, kidA)
	}

	status := c.Status()
	switch {
	case !status.PINCached:
		t.Error("session mode dropped the cached PIN after minting")
	case status.PINVerifiedSerial != serialA:
		t.Errorf("status.PINVerifiedSerial = %d, want %d", status.PINVerifiedSerial, serialA)
	case status.LastSignAlias != "ro" || status.LastSignTarget != roTarget:
		t.Errorf("status last-sign alias/target = %q/%q, want %q/%q", status.LastSignAlias, status.LastSignTarget, "ro", roTarget)
	case status.LastSignSerial != serialA || status.LastSignKeyID != kidA:
		t.Errorf("status last-sign serial/key = %d/%s, want %d/%s", status.LastSignSerial, status.LastSignKeyID, serialA, kidA)
	case !status.LastSignAt.Equal(now):
		t.Errorf("status.LastSignAt = %s, want %s", status.LastSignAt, now)
	case status.WIFProvider != testResource:
		t.Errorf("status.WIFProvider = %q, want %q", status.WIFProvider, testResource)
	case status.Version != testVersion:
		t.Errorf("status.Version = %q, want %q", status.Version, testVersion)
	}

	wantLabel := "ro → " + roTarget + " (local-wif)"
	if len(signer.labels) != 1 || signer.labels[0] != wantLabel {
		t.Errorf("touch prompt labels = %q, want exactly [%q]", signer.labels, wantLabel)
	}
	if signer.counts.signatures != 1 || signer.counts.swapVerifies != 0 {
		t.Errorf("card work = %+v, want a single non-swap signature", signer.counts)
	}
}

func TestSubjectTokenRejectsRequestsConfigurationDoesNotBind(t *testing.T) {
	c, signer := newTestCore(t, testConfig("session"), serialA)
	fixClock(c)
	unlockOK(t, c, pinA)
	// Every rejection below must beat the card, not merely the PIN cache, so
	// the counters are frozen after a successful unlock rather than at zero.
	before := signer.counts

	mismatch := func(field, want string) func(*testing.T, error) {
		return func(t *testing.T, err error) {
			t.Helper()
			var mismatchErr *RequestMismatchError
			if !errors.As(err, &mismatchErr) {
				t.Fatalf("error = %v, want *RequestMismatchError", err)
			}
			if mismatchErr.Field != field {
				t.Errorf("mismatch field = %q, want %q", mismatchErr.Field, field)
			}
			if mismatchErr.Want != want {
				t.Errorf("mismatch want = %q, want %q", mismatchErr.Want, want)
			}
		}
	}

	tests := []struct {
		name  string
		req   SubjectTokenRequest
		check func(*testing.T, error)
	}{
		{
			name: "unknown alias",
			req:  SubjectTokenRequest{Alias: "staging", ExternalAccountAudience: testExternalAudience, ImpersonatedEmail: roTarget},
			check: func(t *testing.T, err error) {
				t.Helper()
				var aliasErr *UnknownAliasError
				if !errors.As(err, &aliasErr) {
					t.Fatalf("error = %v, want *UnknownAliasError", err)
				}
				if aliasErr.Alias != "staging" {
					t.Errorf("unknown alias = %q, want %q", aliasErr.Alias, "staging")
				}
			},
		},
		{
			name: "audience of another pool",
			req: SubjectTokenRequest{
				Alias:                   "ro",
				ExternalAccountAudience: "//iam.googleapis.com/projects/210987654321/locations/global/workloadIdentityPools/other/providers/other",
				ImpersonatedEmail:       roTarget,
			},
			check: mismatch("external_account_audience", testExternalAudience),
		},
		{
			name: "OIDC audience in place of the external-account audience",
			req: SubjectTokenRequest{
				Alias:                   "ro",
				ExternalAccountAudience: testOIDCAudience,
				ImpersonatedEmail:       roTarget,
			},
			check: mismatch("external_account_audience", testExternalAudience),
		},
		{
			name: "target of another alias",
			req: SubjectTokenRequest{
				Alias:                   "ro",
				ExternalAccountAudience: testExternalAudience,
				ImpersonatedEmail:       deployTarget,
			},
			check: mismatch("impersonated_email", roTarget),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result, err := c.SubjectToken(context.Background(), test.req)
			if err == nil {
				t.Fatalf("SubjectToken succeeded: %#v", result)
			}
			if result.IDToken != "" {
				t.Errorf("rejected request still returned a token: %q", result.IDToken)
			}
			test.check(t, err)
		})
	}

	if signer.counts != before {
		t.Errorf("request validation reached the card: %+v, want %+v", signer.counts, before)
	}
	if status := c.Status(); status.LastSignAlias != "" || !status.LastSignAt.IsZero() {
		t.Errorf("rejected requests recorded a signature: %#v", status)
	}
}

func TestSubjectTokenRefusesAnUnenrolledCard(t *testing.T) {
	c, signer := newTestCore(t, testConfig("session"), serialUnknown)
	fixClock(c)
	// The unknown card is a working YubiKey with the same PIN; only the
	// configuration is missing.
	signer.cards[serialUnknown] = signer.cards[serialA]
	signer.pins[serialUnknown] = pinA
	signer.retries[serialUnknown] = 3
	unlockOK(t, c, pinA)

	_, err := c.SubjectToken(context.Background(), roRequest())
	if err == nil {
		t.Fatal("SubjectToken minted a token for an unenrolled card")
	}
	if !strings.Contains(err.Error(), "not enrolled") {
		t.Errorf("error = %v, want it to name the missing enrollment", err)
	}
	if signer.counts.digestRequests != 1 {
		t.Errorf("digest requests = %d, want the digest builder to have run once", signer.counts.digestRequests)
	}
	if signer.counts.signatures != 0 {
		t.Errorf("an unenrolled card produced %d signatures", signer.counts.signatures)
	}
	if status := c.Status(); status.LastSignAlias != "" {
		t.Errorf("a failed mint recorded a signature: %#v", status)
	}
}

func TestSubjectTokenRefusesAReplacedSlotKey(t *testing.T) {
	cfg := testConfig("session")
	// Serial 12345678 is enrolled with key B's identifier, but card A is in the
	// reader: slot 9c was regenerated behind the configuration's back.
	cfg.Keys = map[string]config.Key{"12345678": {JWKKid: kidB}}
	c, signer := newTestCore(t, cfg, serialA)
	fixClock(c)
	unlockOK(t, c, pinA)

	_, err := c.SubjectToken(context.Background(), roRequest())
	if err == nil {
		t.Fatal("SubjectToken signed with a key the configuration does not enroll")
	}
	if !strings.Contains(err.Error(), "re-enrolled") {
		t.Errorf("error = %v, want it to demand deliberate re-enrollment", err)
	}
	if !strings.Contains(err.Error(), kidA) || !strings.Contains(err.Error(), kidB) {
		t.Errorf("error = %v, want it to name both the live and configured key IDs", err)
	}
	if signer.counts.signatures != 0 {
		t.Errorf("a mismatched key produced %d signatures", signer.counts.signatures)
	}
	if status := c.Status(); status.LastSignAlias != "" || status.LastSignSerial != 0 || !status.LastSignAt.IsZero() {
		t.Errorf("a refused mint recorded a signature: %#v", status)
	}
}

func TestNeverModeSpendsTheCachedPINOnOneToken(t *testing.T) {
	c, signer := newTestCore(t, testConfig("never"), serialA)
	fixClock(c)
	unlockOK(t, c, pinA)

	result := mintOK(t, c, roRequest())
	parseToken(t, result.IDToken).verify(t, signer.cards[serialA].public(t))

	status := c.Status()
	if status.PINCached || status.PINVerifiedSerial != 0 {
		t.Errorf("never mode retained the PIN after minting: %#v", status)
	}
	if status.LastSignSerial != serialA {
		t.Errorf("status.LastSignSerial = %d, want %d", status.LastSignSerial, serialA)
	}
	if _, err := c.SubjectToken(context.Background(), roRequest()); !errors.Is(err, ErrLocked) {
		t.Fatalf("second SubjectToken error = %v, want ErrLocked", err)
	}
	if signer.counts.signatures != 1 {
		t.Errorf("signatures = %d, want exactly one", signer.counts.signatures)
	}
}

func TestFleetKeySwapPINHandling(t *testing.T) {
	newSwapCore := func(t *testing.T, pinForB string, retriesForB int) (*Core, *fakeSigner) {
		t.Helper()
		c, signer := newTestCore(t, testConfig("session"), serialA)
		signer.pins[serialB] = pinForB
		signer.retries[serialB] = retriesForB
		fixClock(c)
		unlockOK(t, c, pinA)
		if status := c.Status(); status.PINVerifiedSerial != serialA {
			t.Fatalf("status after unlock = %#v", status)
		}
		signer.current = serialB
		return c, signer
	}

	t.Run("a shared PIN re-verifies against the swapped key", func(t *testing.T) {
		c, signer := newSwapCore(t, pinA, 3)

		result := mintOK(t, c, deployRequest())
		token := parseToken(t, result.IDToken)
		token.verify(t, signer.cards[serialB].public(t))
		if got := token.claims["serial"]; got != "23456789" {
			t.Errorf("serial claim = %#v, want the swapped card", got)
		}
		if got := token.claims["key_id"]; got != kidB {
			t.Errorf("key_id claim = %#v, want %q", got, kidB)
		}
		if result.Serial != serialB || result.KeyID != kidB {
			t.Errorf("result serial/key = %d/%s, want %d/%s", result.Serial, result.KeyID, serialB, kidB)
		}
		if signer.counts.swapVerifies != 1 || signer.counts.signatures != 1 {
			t.Errorf("card work = %+v, want one swap verification and one signature", signer.counts)
		}
		status := c.Status()
		if !status.PINCached || status.PINVerifiedSerial != serialB || status.LastSignSerial != serialB {
			t.Errorf("status after the swap = %#v", status)
		}
	})

	t.Run("a different PIN drops the cache and names the remedy", func(t *testing.T) {
		c, signer := newSwapCore(t, pinB, 3)

		_, err := c.SubjectToken(context.Background(), deployRequest())
		var pinErr *pivsigner.PINError
		if !errors.As(err, &pinErr) {
			t.Fatalf("swap error = %v, want *pivsigner.PINError", err)
		}
		if !pinErr.ClearCachedPIN {
			t.Error("a rejected cached PIN did not ask for the cache to be cleared")
		}
		if !strings.Contains(pinErr.Remedy, "pivb unlock") {
			t.Errorf("remedy = %q, want it to point at `pivb unlock`", pinErr.Remedy)
		}
		if signer.counts.swapVerifies != 1 || signer.counts.signatures != 0 {
			t.Errorf("card work = %+v, want one rejected swap verification and no signature", signer.counts)
		}
		if status := c.Status(); status.PINCached || status.PINVerifiedSerial != 0 {
			t.Errorf("status after the rejected swap = %#v", status)
		}
		if _, err := c.SubjectToken(context.Background(), deployRequest()); !errors.Is(err, ErrLocked) {
			t.Fatalf("SubjectToken after the rejected swap error = %v, want ErrLocked", err)
		}
	})

	t.Run("the final PIN attempt is never spent", func(t *testing.T) {
		c, signer := newSwapCore(t, pinA, 1)

		_, err := c.SubjectToken(context.Background(), deployRequest())
		var pinErr *pivsigner.PINError
		if !errors.As(err, &pinErr) {
			t.Fatalf("swap error = %v, want *pivsigner.PINError", err)
		}
		if pinErr.Retries != 1 {
			t.Errorf("reported retries = %d, want 1", pinErr.Retries)
		}
		if pinErr.ClearCachedPIN {
			t.Error("the guarded swap cleared a PIN that was never tried")
		}
		if signer.counts.swapVerifies != 0 || signer.counts.signatures != 0 {
			t.Errorf("card work = %+v, want the swap to have been refused before any PIN attempt", signer.counts)
		}
		status := c.Status()
		if !status.PINCached || status.PINVerifiedSerial != serialA {
			t.Errorf("status after the guarded swap = %#v, want the PIN still bound to %d", status, serialA)
		}
	})
}

func TestLockClearsThePINAndTheSignMetadata(t *testing.T) {
	c, _ := newTestCore(t, testConfig("session"), serialA)
	fixClock(c)
	unlockOK(t, c, pinA)
	mintOK(t, c, roRequest())

	if status := c.Status(); status.LastSignAlias != "ro" {
		t.Fatalf("status before Lock = %#v", status)
	}

	c.Lock()

	status := c.Status()
	switch {
	case status.PINCached:
		t.Error("Lock left the PIN cached")
	case status.PINVerifiedSerial != 0:
		t.Errorf("Lock left PINVerifiedSerial = %d", status.PINVerifiedSerial)
	case status.LastSignAlias != "" || status.LastSignTarget != "" || status.LastSignKeyID != "":
		t.Errorf("Lock left signing metadata behind: %#v", status)
	case status.LastSignSerial != 0 || !status.LastSignAt.IsZero():
		t.Errorf("Lock left signing metadata behind: %#v", status)
	case status.WIFProvider != testResource:
		t.Errorf("Lock disturbed the reported provider: %q", status.WIFProvider)
	}
	if _, err := c.SubjectToken(context.Background(), roRequest()); !errors.Is(err, ErrLocked) {
		t.Fatalf("SubjectToken after Lock error = %v, want ErrLocked", err)
	}
}

func TestStatusIsCardFree(t *testing.T) {
	c, signer := newTestCore(t, testConfig("session"), serialA)
	for range 3 {
		status := c.Status()
		if status.PINCached || status.PINVerifiedSerial != 0 || status.LastSignSerial != 0 {
			t.Fatalf("a fresh status claimed card state: %#v", status)
		}
		if status.WIFProvider != testResource || status.Version != testVersion {
			t.Fatalf("status provider/version = %q/%q", status.WIFProvider, status.Version)
		}
	}
	if signer.counts != (signerCounts{}) {
		t.Errorf("Status did card work: %+v", signer.counts)
	}
}

func TestJTIIsUniquePerToken(t *testing.T) {
	c, _ := newTestCore(t, testConfig("session"), serialA)
	// The clock is fixed but the jti stream is not: identical claim sets must
	// still produce distinct token identifiers.
	now := time.Unix(testNowUnix, 0).UTC()
	c.SetNowForTest(func() time.Time { return now })
	unlockOK(t, c, pinA)

	first := parseToken(t, mintOK(t, c, roRequest()).IDToken)
	second := parseToken(t, mintOK(t, c, roRequest()).IDToken)

	firstJTI, _ := first.claims["jti"].(string)
	secondJTI, _ := second.claims["jti"].(string)
	if firstJTI == "" || secondJTI == "" {
		t.Fatalf("missing jti claims: %v and %v", first.claims, second.claims)
	}
	if firstJTI == secondJTI {
		t.Errorf("both tokens carry jti %q", firstJTI)
	}
	if first.input == second.input {
		t.Error("two mints produced byte-identical signing inputs")
	}
}

// retryingSigner emulates the one path where pivsigner.Hardware invokes
// digestFor more than once: a confirmed PC/SC sharing violation, which kills
// scdaemon and retries the whole attempt. The operator may swap cards between
// the two attempts, so the retry re-reads the certificate and rebuilds the
// digest. Whatever the second attempt signs is what the caller must assemble.
type retryingSigner struct {
	*fakeSigner
	retryWith uint32
}

func (s *retryingSigner) Sign(ctx context.Context, label, pin string, digestFor func(uint32, *x509.Certificate) ([]byte, error)) ([]byte, uint32, error) {
	first := s.cards[s.current]
	s.counts.digestRequests++
	if _, err := digestFor(s.current, first.cert); err != nil {
		return nil, 0, fmt.Errorf("build signing digest for YubiKey %d: %w", s.current, err)
	}
	// The first attempt died on the sharing violation before signing; the
	// second sees whichever card is now inserted.
	s.current = s.retryWith
	return s.fakeSigner.Sign(ctx, label, pin, digestFor)
}

func TestSharingViolationRetrySignsTheCardItRebuiltTheDigestFor(t *testing.T) {
	base := &fakeSigner{
		current: serialA,
		cards:   map[uint32]fixtureKey{serialA: loadFixture(t, "a"), serialB: loadFixture(t, "b")},
		pins:    map[uint32]string{serialA: pinA, serialB: pinA},
		retries: map[uint32]int{serialA: 3, serialB: 3},
	}
	signer := &retryingSigner{fakeSigner: base, retryWith: serialB}
	c := New(testConfig("session"), signer, testVersion)
	now := fixClock(c)
	unlockOK(t, c, pinA)

	result := mintOK(t, c, roRequest())
	token := parseToken(t, result.IDToken)

	// The assembled token must verify against the card that actually signed,
	// not the one the abandoned first attempt described.
	token.verify(t, base.cards[serialB].public(t))
	if base.counts.digestRequests != 2 {
		t.Errorf("digest built %d times, want 2 (one per attempt)", base.counts.digestRequests)
	}
	if base.counts.signatures != 1 {
		t.Errorf("card signed %d times, want 1", base.counts.signatures)
	}

	for _, claim := range []struct{ name, want string }{
		{"key_id", kidB},
		{"serial", "23456789"},
		{"sub", "pivb-key:" + kidB},
	} {
		if got, _ := token.claims[claim.name].(string); got != claim.want {
			t.Errorf("claim %q = %q, want %q", claim.name, got, claim.want)
		}
	}
	if want := `{"alg":"RS256","typ":"JWT","kid":"` + kidB + `"}`; token.header != want {
		t.Errorf("JWS header = %s, want %s", token.header, want)
	}
	if result.Serial != serialB || result.KeyID != kidB {
		t.Errorf("result serial/key = %d/%s, want %d/%s", result.Serial, result.KeyID, serialB, kidB)
	}

	// The retry must not advance the clock or draw a second jti: iat, exp, and
	// jti are fixed when the request starts, not per attempt.
	if got, _ := token.claims["jti"].(string); got != testJTI {
		t.Errorf("jti = %q, want the single value drawn for this request (%q)", got, testJTI)
	}
	if got, _ := token.claims["iat"].(json.Number); got.String() != "1785585570" {
		t.Errorf("iat = %v, want 1785585570", got)
	}

	status := c.Status()
	if status.LastSignSerial != serialB || status.LastSignKeyID != kidB || !status.LastSignAt.Equal(now) {
		t.Errorf("status last-sign = %d/%s at %s, want %d/%s at %s",
			status.LastSignSerial, status.LastSignKeyID, status.LastSignAt, serialB, kidB, now)
	}
}
