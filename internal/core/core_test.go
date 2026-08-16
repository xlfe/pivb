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
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xlfe/pivb/internal/agentsource"
	"github.com/xlfe/pivb/internal/attachment"
	"github.com/xlfe/pivb/internal/config"
	"github.com/xlfe/pivb/internal/forwardapi"
	"github.com/xlfe/pivb/internal/pivsigner"
	"github.com/xlfe/pivb/internal/tokenapi"
	"github.com/xlfe/pivb/internal/wif"
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
//
// Its mutable state is guarded, because the coalescing tests drive it from many
// goroutines at once. signGate holds a signature open the way a real touch
// does, so a test can decide exactly which requests were queued behind it.
type fakeSigner struct {
	mu sync.Mutex

	// current is the inserted card; verified is the card the cached PIN has
	// already been checked against in an earlier session.
	current  uint32
	verified uint32

	cards   map[uint32]fixtureKey
	pins    map[uint32]string
	retries map[uint32]int

	labels []string
	counts signerCounts

	// signGate blocks inside Sign until a test closes it. readerNames is what
	// ListReaderNames reports, and listErr fails the enumeration outright.
	signGate    chan struct{}
	readerNames []string
	listErr     error
}

func (s *fakeSigner) snapshotCounts() signerCounts {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.counts
}

func (s *fakeSigner) snapshotLabels() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.labels...)
}

func (s *fakeSigner) setSignGate(gate chan struct{}) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.signGate = gate
}

func (s *fakeSigner) setCurrent(serial uint32) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.current = serial
}

func (s *fakeSigner) setReaders(names []string, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.readerNames, s.listErr = names, err
}

// ListReaderNames makes the fake a card-presence seam. A signer that does not
// implement it disables the probe, so the default here — one reader, no error
// — keeps every existing test on the probing path.
func (s *fakeSigner) ListReaderNames() ([]string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.listErr != nil {
		return nil, s.listErr
	}
	return append([]string(nil), s.readerNames...), nil
}

func (s *fakeSigner) Describe(_ context.Context) (uint32, *x509.Certificate, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	card, ok := s.cards[s.current]
	if !ok {
		return 0, nil, errors.New("no card")
	}
	return s.current, card.cert, nil
}

func (s *fakeSigner) VerifyPIN(_ context.Context, pin string) (uint32, int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.counts.verifies++
	retries := s.retries[s.current]
	if pin != s.pins[s.current] {
		return s.current, retries - 1, &pivsigner.PINError{Retries: retries - 1, Err: errors.New("wrong PIN")}
	}
	s.verified = s.current
	return s.current, retries, nil
}

func (s *fakeSigner) Sign(_ context.Context, label, pin string, digestFor func(uint32, *x509.Certificate) ([]byte, error)) ([]byte, uint32, error) {
	s.mu.Lock()
	serial := s.current
	s.labels = append(s.labels, label)
	card, present := s.cards[serial]
	gate := s.signGate
	s.mu.Unlock()
	if !present {
		return nil, 0, fmt.Errorf("read certificate from PIV slot 9c on YubiKey %d: no card registered in the fake", serial)
	}
	// A real touch takes seconds. Waiting here is what lets the requests that
	// will share this signature queue up behind it.
	if gate != nil {
		<-gate
	}

	// Hardware builds the digest before spending any PIN attempt, and reports
	// no serial when that fails: a nonzero serial is the signal that the cached
	// PIN was verified against the card during this operation.
	s.mu.Lock()
	s.counts.digestRequests++
	s.mu.Unlock()
	digest, err := digestFor(serial, card.cert)
	if err != nil {
		return nil, 0, fmt.Errorf("build signing digest for YubiKey %d: %w", serial, err)
	}

	// Both swap failures below report the serial. pivsigner.Hardware reports
	// zero there instead, because the cached PIN was not in fact verified
	// against the card. Core discards the serial for any *PINError, so the two
	// behave alike, but an assertion that depends on the difference is only
	// testing this fake.
	s.mu.Lock()
	if serial != s.verified {
		retries := s.retries[serial]
		if retries <= 1 {
			s.mu.Unlock()
			return nil, serial, &pivsigner.PINError{
				Retries: retries,
				Err:     fmt.Errorf("refusing to try the cached PIN on swapped YubiKey %d and spend the final PIN attempt", serial),
				Remedy:  "run `pivb unlock` with this key inserted after checking or resetting its PIV PIN",
			}
		}
		s.counts.swapVerifies++
		if pin != s.pins[serial] {
			s.verified = 0
			s.mu.Unlock()
			return nil, serial, &pivsigner.PINError{
				Retries:        retries - 1,
				Err:            fmt.Errorf("cached PIN was rejected by swapped YubiKey %d; fleet keys may have different PINs", serial),
				Remedy:         "run `pivb unlock` with this key inserted",
				ClearCachedPIN: true,
			}
		}
		s.verified = serial
	}
	s.mu.Unlock()

	sig, err := rsa.SignPKCS1v15(rand.Reader, card.key, crypto.SHA256, digest)
	if err != nil {
		return nil, serial, fmt.Errorf("sign with PIV slot 9c on YubiKey %d: %w", serial, err)
	}
	s.mu.Lock()
	s.counts.signatures++
	s.mu.Unlock()
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
		current:     inserted,
		cards:       map[uint32]fixtureKey{serialA: loadFixture(t, "a"), serialB: loadFixture(t, "b")},
		pins:        map[uint32]string{serialA: pinA, serialB: pinA},
		retries:     map[uint32]int{serialA: 3, serialB: 3},
		readerNames: []string{"Yubico YubiKey OTP+FIDO+CCID 00 00"},
	}
	return New(cfg, signer, testVersion), signer
}

// fixClock pins the signing instant and the jti stream so a minted token is
// byte-for-byte predictable. A frozen clock makes sequential mints
// indistinguishable from concurrent ones, so a test that mints the same
// request twice wants tickClock instead.
func fixClock(c *Core) time.Time {
	now := time.Unix(testNowUnix, 0).UTC()
	c.SetNowForTest(func() time.Time { return now })
	c.SetRandomForTest(strings.NewReader(strings.Repeat(testJTISeed, 8)))
	return now
}

// tickClock is the honest counterpart to fixClock: waiting for a touch takes
// real time, so every read of the clock advances it. Requests minted under it
// are strictly sequential, which is what a default-configuration daemon must
// never coalesce. It is safe to read from many goroutines at once.
type tickClock struct {
	mu      sync.Mutex
	instant time.Time
}

func startTickClock(c *Core) *tickClock {
	clock := &tickClock{instant: time.Unix(testNowUnix, 0).UTC()}
	c.SetNowForTest(clock.now)
	c.SetRandomForTest(rand.Reader)
	return clock
}

func (t *tickClock) now() time.Time {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.instant = t.instant.Add(time.Second)
	return t.instant
}

// advance jumps the clock, so a test can sit inside or past a reuse window
// without spending thousands of reads to get there.
func (t *tickClock) advance(d time.Duration) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.instant = t.instant.Add(d)
}

// mintRace runs n identical requests concurrently and holds the signature open
// until every one of them has recorded its arrival, so the whole group is
// provably queued behind one touch rather than merely likely to be.
func mintRace(t *testing.T, c *Core, signer *fakeSigner, req SubjectTokenRequest, n int) []SubjectTokenResult {
	t.Helper()
	gate := make(chan struct{})
	signer.setSignGate(gate)
	defer signer.setSignGate(nil)

	var pending atomic.Int32
	pending.Store(int32(n))
	c.SetMintArrivalHookForTest(func() {
		if pending.Add(-1) == 0 {
			close(gate)
		}
	})
	defer c.SetMintArrivalHookForTest(nil)

	results := make([]SubjectTokenResult, n)
	errs := make([]error, n)
	var running sync.WaitGroup
	running.Add(n)
	for i := range n {
		go func() {
			defer running.Done()
			results[i], errs[i] = c.SubjectToken(context.Background(), req)
		}()
	}
	running.Wait()
	for i, err := range errs {
		if err != nil {
			t.Fatalf("concurrent SubjectToken %d: %v", i, err)
		}
	}
	return results
}

// reuseConfig is testConfig with a touch-free window on every alias.
func reuseConfig(mode string, reuse int) *config.Config {
	cfg := testConfig(mode)
	for name, alias := range cfg.Aliases {
		alias.AssertionReuseS = reuse
		cfg.Aliases[name] = alias
	}
	return cfg
}

// onlyEntry returns the single cached assertion, failing when the cache does
// not hold exactly one.
func onlyEntry(t *testing.T, c *Core) (reuseKey, *cacheEntry) {
	t.Helper()
	c.mu.RLock()
	defer c.mu.RUnlock()
	if len(c.cache) != 1 {
		t.Fatalf("cache holds %d assertions, want exactly 1", len(c.cache))
	}
	for key, entry := range c.cache {
		return key, entry
	}
	return reuseKey{}, nil
}

func roRequest() SubjectTokenRequest {
	return SubjectTokenRequest{
		Alias:                   "ro",
		ExternalAccountAudience: testExternalAudience,
		ImpersonatedEmail:       roTarget,
		Attachment:              attachment.LocalAllowed(),
	}
}

func deployRequest() SubjectTokenRequest {
	return SubjectTokenRequest{
		Alias:                   "deploy",
		ExternalAccountAudience: testExternalAudience,
		ImpersonatedEmail:       deployTarget,
		Attachment:              attachment.LocalAllowed(),
	}
}

func TestSubjectTokenRequiresExplicitAttachmentPolicy(t *testing.T) {
	c, signer := newTestCore(t, testConfig("session"), serialA)
	_, err := c.SubjectToken(context.Background(), SubjectTokenRequest{
		Alias: "ro", ExternalAccountAudience: testExternalAudience, ImpersonatedEmail: roTarget,
	})
	if err == nil || !strings.Contains(err.Error(), "attachment policy is required") {
		t.Fatalf("SubjectToken error = %v, want required attachment policy", err)
	}
	if signer.counts != (signerCounts{}) {
		t.Fatalf("omitted attachment policy reached hardware: %+v", signer.counts)
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
			req:  SubjectTokenRequest{Alias: "staging", ExternalAccountAudience: testExternalAudience, ImpersonatedEmail: roTarget, Attachment: attachment.LocalAllowed()},
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
				Attachment:              attachment.LocalAllowed(),
			},
			check: mismatch("external_account_audience", testExternalAudience),
		},
		{
			name: "OIDC audience in place of the external-account audience",
			req: SubjectTokenRequest{
				Alias:                   "ro",
				ExternalAccountAudience: testOIDCAudience,
				ImpersonatedEmail:       roTarget,
				Attachment:              attachment.LocalAllowed(),
			},
			check: mismatch("external_account_audience", testExternalAudience),
		},
		{
			name: "target of another alias",
			req: SubjectTokenRequest{
				Alias:                   "ro",
				ExternalAccountAudience: testExternalAudience,
				ImpersonatedEmail:       deployTarget,
				Attachment:              attachment.LocalAllowed(),
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

func TestSubjectTokenValidatesAgentSourceBeforeHardware(t *testing.T) {
	c, signer := newTestCore(t, testConfig("session"), serialA)
	fixClock(c)
	unlockOK(t, c, pinA)
	before := signer.counts

	bad := roRequest()
	bad.RequestSource = agentsource.Agent("codex:agentic/deploy", "0123456789abcdef0123456789abcdef")
	if _, err := c.SubjectToken(context.Background(), bad); err == nil {
		t.Fatal("mismatched source role succeeded")
	} else {
		var sourceErr *RequestSourceError
		if !errors.As(err, &sourceErr) {
			t.Fatalf("error = %T %v, want RequestSourceError", err, err)
		}
	}
	if signer.counts != before {
		t.Fatalf("invalid source reached hardware: %+v != %+v", signer.counts, before)
	}

	good := roRequest()
	good.RequestSource = agentsource.Agent("codex:agentic/ro", "0123456789abcdef0123456789abcdef")
	mintOK(t, c, good)
	want := "agent codex · project agentic · role ro\nsession 0123456789ab\ntarget " + roTarget
	if got := signer.labels[len(signer.labels)-1]; got != want {
		t.Fatalf("agent signing label = %q, want %q", got, want)
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

func TestForwardDescriptionAndExpectedCardAreBoundToLiveSession(t *testing.T) {
	c, signer := newTestCore(t, testConfig("session"), serialA)
	description, err := c.DescribeForwardProvider(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if description.Card.Serial != serialA || description.Card.KeyID != kidA || description.Aliases["ro"].Target != roTarget {
		t.Fatalf("description = %#v", description)
	}
	unlockOK(t, c, pinA)
	req := roRequest()
	req.ExpectedCard = forwardapi.CardIdentity{Serial: serialB, KeyID: kidB, SPKIDER: signer.cards[serialB].cert.RawSubjectPublicKeyInfo}
	if _, err := c.SubjectToken(context.Background(), req); err == nil || !strings.Contains(err.Error(), "does not match claimed identity") {
		t.Fatalf("mismatched claimed card error = %v", err)
	}
	if signer.counts.signatures != 0 {
		t.Fatal("mismatched claimed card was allowed to sign")
	}
}

func TestNeverModeSpendsTheCachedPINOnOneToken(t *testing.T) {
	c, signer := newTestCore(t, testConfig("never"), serialA)
	// The two requests below are sequential, not concurrent, so the clock has
	// to move between them: a frozen clock would make the second look like a
	// request that had been queued behind the first one's touch.
	fixClock(c)
	startTickClock(c)
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
	if status := c.Status(); status.Mints != nil {
		t.Errorf("a fresh status reported mint counters %+v, want none", status.Mints)
	}
}

// movingClock is the counterpart to fixClock: the rolling mint window only
// means anything if a test can place mints at different instants.
type movingClock struct{ at time.Time }

func (c *movingClock) now() time.Time          { return c.at }
func (c *movingClock) advance(d time.Duration) { c.at = c.at.Add(d) }

func startClock(c *Core) *movingClock {
	clock := &movingClock{at: time.Unix(testNowUnix, 0).UTC()}
	c.SetNowForTest(clock.now)
	return clock
}

// agentRequest attaches the trusted-host session context that makes a mint
// attributable to one agent session.
func agentRequest(req SubjectTokenRequest, label, sessionID string) SubjectTokenRequest {
	req.RequestSource = agentsource.Agent(label, sessionID)
	return req
}

func TestStatusMintCounters(t *testing.T) {
	sessionA := strings.Repeat("a", agentsource.SessionIDLength)
	sessionB := strings.Repeat("b", agentsource.SessionIDLength)
	c, signer := newTestCore(t, testConfig("session"), serialA)
	clock := startClock(c)
	unlockOK(t, c, pinA)

	mintOK(t, c, agentRequest(roRequest(), "codex:proj/ro", sessionA))
	clock.advance(2 * time.Minute)
	mintOK(t, c, agentRequest(deployRequest(), "codex:proj/deploy", sessionB))
	clock.advance(20 * time.Minute)
	mintOK(t, c, agentRequest(roRequest(), "codex:proj/ro", sessionA))

	counters := c.Status().Mints
	if counters == nil {
		t.Fatal("Status reported no mint counters after three mints")
	}
	if counters.Total1m != 1 || counters.Total5m != 1 || counters.Total60m != 3 {
		t.Errorf("totals = %d/1m %d/5m %d/60m, want 1/1 1/5 3/60", counters.Total1m, counters.Total5m, counters.Total60m)
	}
	// Nothing is reused yet, so every mint in the window spent a touch.
	if counters.Signatures60m != 3 {
		t.Errorf("Signatures60m = %d, want 3", counters.Signatures60m)
	}
	if want := map[string]int{"ro": 2, "deploy": 1}; !reflect.DeepEqual(counters.PerAlias60m, want) {
		t.Errorf("PerAlias60m = %v, want %v", counters.PerAlias60m, want)
	}
	if want := map[string]int{sessionA: 2, sessionB: 1}; !reflect.DeepEqual(counters.PerSession60m, want) {
		t.Errorf("PerSession60m = %v, want %v", counters.PerSession60m, want)
	}
	if signer.counts.signatures != 3 {
		t.Errorf("signer signed %d times, want 3", signer.counts.signatures)
	}

	// The window is pruned when a mint appends, so the two oldest entries and
	// the alias and session only they carried drop out of the next report.
	clock.advance(45 * time.Minute)
	mintOK(t, c, agentRequest(roRequest(), "codex:proj/ro", sessionA))

	counters = c.Status().Mints
	if counters == nil {
		t.Fatal("Status reported no mint counters after the pruning mint")
	}
	if counters.Total60m != 2 || counters.Total1m != 1 {
		t.Errorf("totals after pruning = %d/1m %d/60m, want 1/1m 2/60m", counters.Total1m, counters.Total60m)
	}
	if want := map[string]int{"ro": 2}; !reflect.DeepEqual(counters.PerAlias60m, want) {
		t.Errorf("PerAlias60m after pruning = %v, want %v", counters.PerAlias60m, want)
	}
	if want := map[string]int{sessionA: 2}; !reflect.DeepEqual(counters.PerSession60m, want) {
		t.Errorf("PerSession60m after pruning = %v, want %v", counters.PerSession60m, want)
	}
}

// TestLocalMintCountersOmitSession pins what a plain local-wif mint reports: a
// total, an alias, and no session it never had.
func TestLocalMintCountersOmitSession(t *testing.T) {
	c, _ := newTestCore(t, testConfig("session"), serialA)
	startClock(c)
	unlockOK(t, c, pinA)
	mintOK(t, c, roRequest())

	counters := c.Status().Mints
	if counters == nil {
		t.Fatal("Status reported no mint counters after a local mint")
	}
	if counters.Total1m != 1 || counters.Total60m != 1 {
		t.Errorf("totals = %d/1m %d/60m, want 1/1m 1/60m", counters.Total1m, counters.Total60m)
	}
	if want := map[string]int{"ro": 1}; !reflect.DeepEqual(counters.PerAlias60m, want) {
		t.Errorf("PerAlias60m = %v, want %v", counters.PerAlias60m, want)
	}
	if counters.PerSession60m != nil {
		t.Errorf("PerSession60m = %v, want nothing for a local-wif mint", counters.PerSession60m)
	}
}

// TestMintRateWarnFiresOncePerWindow keeps the threshold warning honest in both
// directions: a busy session is reported once, not once per mint, and a session
// that stays busy into the next window is reported again.
func TestMintRateWarnFiresOncePerWindow(t *testing.T) {
	const warning = "session mint rate exceeds threshold"
	session := strings.Repeat("a", agentsource.SessionIDLength)
	c, _ := newTestCore(t, testConfig("session"), serialA)
	clock := startClock(c)
	var journal bytes.Buffer
	c.SetLogger(slog.New(slog.NewTextHandler(&journal, nil)))
	unlockOK(t, c, pinA)

	req := agentRequest(roRequest(), "codex:proj/ro", session)
	burst := func() {
		t.Helper()
		for range mintWarnThreshold {
			clock.advance(time.Second)
			mintOK(t, c, req)
		}
	}

	burst()
	if got := strings.Count(journal.String(), warning); got != 1 {
		t.Fatalf("%d mints produced %d warnings, want exactly 1:\n%s", mintWarnThreshold, got, journal.String())
	}
	logged := journal.String()
	for _, want := range []string{"level=WARN", "session_id=" + session, "alias=ro", "mints_5m=" + strconv.Itoa(mintWarnThreshold)} {
		if !strings.Contains(logged, want) {
			t.Errorf("warning is missing %q: %s", want, logged)
		}
	}

	// Still inside the same window: the session stays over the threshold and
	// stays quiet.
	burst()
	if got := strings.Count(journal.String(), warning); got != 1 {
		t.Fatalf("a continuing burst produced %d warnings, want the first one only:\n%s", got, journal.String())
	}

	// Past the window, with the earlier mints aged out of the five-minute
	// count: a session that is still this busy is worth saying again.
	clock.advance(mintWarnWindow + time.Minute)
	burst()
	if got := strings.Count(journal.String(), warning); got != 2 {
		t.Fatalf("a burst in the next window produced %d warnings in total, want 2:\n%s", got, journal.String())
	}
}

func TestJTIIsUniquePerToken(t *testing.T) {
	c, signer := newTestCore(t, testConfig("session"), serialA)
	// Two byte-identical requests, one after the other, on a default
	// configuration: neither is queued behind the other's touch, so each buys
	// its own signature and its own token identifier.
	startTickClock(c)
	unlockOK(t, c, pinA)

	first := parseToken(t, mintOK(t, c, roRequest()).IDToken)
	second := parseToken(t, mintOK(t, c, roRequest()).IDToken)
	if got := signer.snapshotCounts().signatures; got != 2 {
		t.Fatalf("two sequential identical requests spent %d signatures, want 2", got)
	}

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

func TestForwardSubjectTokenRejectsHostileProviderResponses(t *testing.T) {
	fixtureA := loadFixture(t, "a")
	fixtureB := loadFixture(t, "b")
	now := time.Unix(testNowUnix, 0).UTC()
	card := func(serial uint32, kid string, fixture fixtureKey) forwardapi.CardIdentity {
		return forwardapi.CardIdentity{Serial: serial, KeyID: kid, SPKIDER: append([]byte(nil), fixture.cert.RawSubjectPublicKeyInfo...)}
	}
	cardA := card(serialA, kidA, fixtureA)
	cardB := card(serialB, kidB, fixtureB)
	forwardContext := forwardapi.ForwardContext{
		OriginNodeID: strings.Repeat("a", 32), WorkspaceID: strings.Repeat("b", 32), Bundle: "work",
		ClaimGeneration: 7, ProviderNodeID: strings.Repeat("c", 32), ProviderAttachID: strings.Repeat("d", 32),
		OperationID: strings.Repeat("e", 32),
	}

	type responseCase struct {
		mutateClaims   func(*wif.Claims)
		mutateResponse func(*forwardapi.MintResponse)
		fixture        fixtureKey
		serial         uint32
		kid            string
		expected       forwardapi.CardIdentity
		wantSuccess    bool
	}
	tests := map[string]responseCase{
		"valid response":                 {wantSuccess: true},
		"wrong issuer":                   {mutateClaims: func(c *wif.Claims) { c.Iss = "https://attacker.example" }},
		"wrong audience":                 {mutateClaims: func(c *wif.Claims) { c.Aud = "https://attacker.example/audience" }},
		"wrong subject":                  {mutateClaims: func(c *wif.Claims) { c.Sub = "pivb-key:attacker" }},
		"wrong alias":                    {mutateClaims: func(c *wif.Claims) { c.Alias = "deploy" }},
		"wrong target":                   {mutateClaims: func(c *wif.Claims) { c.Target = deployTarget }},
		"wrong serial claim":             {mutateClaims: func(c *wif.Claims) { c.Serial = fmt.Sprint(serialB) }},
		"missing jti":                    {mutateClaims: func(c *wif.Claims) { c.Jti = "" }},
		"header kid disagrees with SPKI": {mutateClaims: func(c *wif.Claims) { c.KeyID = kidB }},
		"invalid lifetime":               {mutateClaims: func(c *wif.Claims) { c.Exp++ }},
		"expired": {mutateClaims: func(c *wif.Claims) {
			c.Exp = now.Unix()
			c.Iat = c.Exp - int64(wif.Lifetime/time.Second)
		}},
		"pre-dated iat": {mutateClaims: func(c *wif.Claims) {
			c.Iat = now.Add(-2*wif.ClockSkew - time.Second).Unix()
			c.Exp = c.Iat + int64(wif.Lifetime/time.Second)
		}},
		"future iat": {mutateClaims: func(c *wif.Claims) {
			c.Iat = now.Add(wif.ClockSkew + time.Second).Unix()
			c.Exp = c.Iat + int64(wif.Lifetime/time.Second)
		}},
		"expiration envelope disagrees": {mutateResponse: func(r *forwardapi.MintResponse) { r.ExpirationTime++ }},
		"different enrolled fleet card": {fixture: fixtureB, serial: serialB, kid: kidB, expected: cardA},
		"response card key disagrees": {
			mutateResponse: func(r *forwardapi.MintResponse) { r.Card.KeyID = kidB; r.ExpectedCard = r.Card },
		},
		"response SPKI disagrees with header kid": {
			mutateResponse: func(r *forwardapi.MintResponse) {
				r.Card.SPKIDER = append([]byte(nil), cardB.SPKIDER...)
				r.ExpectedCard = r.Card
			},
		},
		"active route serial pin disagrees": {mutateResponse: func(r *forwardapi.MintResponse) { r.ExpectedCard.Serial = serialB }},
		"active route key pin disagrees":    {mutateResponse: func(r *forwardapi.MintResponse) { r.ExpectedCard.KeyID = kidB }},
		"active route SPKI pin disagrees":   {mutateResponse: func(r *forwardapi.MintResponse) { r.ExpectedCard.SPKIDER = append([]byte(nil), cardB.SPKIDER...) }},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			fixture, serial, kid := test.fixture, test.serial, test.kid
			if fixture.cert == nil {
				fixture, serial, kid = fixtureA, serialA, kidA
			}
			claims, err := wif.NewClaims(testConfig("session").Provider(), "ro", roTarget, serial, kid, testJTI, now)
			if err != nil {
				t.Fatal(err)
			}
			if test.mutateClaims != nil {
				test.mutateClaims(&claims)
			}
			input, err := wif.SigningInput(claims)
			if err != nil {
				t.Fatal(err)
			}
			signature, err := rsa.SignPKCS1v15(rand.Reader, fixture.key, crypto.SHA256, wif.SigningDigest(input))
			if err != nil {
				t.Fatal(err)
			}
			token, err := wif.Assemble(input, signature)
			if err != nil {
				t.Fatal(err)
			}
			actual := card(serial, kid, fixture)
			expected := test.expected
			if expected.Serial == 0 {
				expected = actual
			}
			response := forwardapi.MintResponse{
				Version: forwardapi.ProtocolVersion, IDToken: token, ExpirationTime: claims.Exp,
				Card: actual, ExpectedCard: expected, ForwardContext: forwardContext,
			}
			if test.mutateResponse != nil {
				test.mutateResponse(&response)
			}
			socket := serveForwardResponse(t, response)
			c, signer := newTestCore(t, testConfig("session"), serialA)
			c.SetNowForTest(func() time.Time { return now })
			req := roRequest()
			req.Attachment = attachment.RouteRequired(attachment.ProtocolEnvironment, socket)
			result, err := c.SubjectToken(context.Background(), req)
			if test.wantSuccess {
				if err != nil {
					t.Fatalf("SubjectToken: %v", err)
				}
				if result.Serial != serialA || result.KeyID != kidA {
					t.Fatalf("forwarded result card = %d/%s", result.Serial, result.KeyID)
				}
				status := c.Status()
				if status.LastSignRoute != "zka-workspace-forwarded" || status.LastSignForward == nil || status.LastSignForward.OperationID != forwardContext.OperationID {
					t.Fatalf("forwarded status lacks route context: %#v", status)
				}
			} else if err == nil {
				t.Fatalf("hostile forwarded response was accepted: %#v", result)
			}
			if signer.counts != (signerCounts{}) {
				t.Fatalf("origin verification touched its local card: %+v", signer.counts)
			}
			if !test.wantSuccess {
				var apiErr *tokenapi.APIError
				if !errors.As(err, &apiErr) || apiErr.Code != tokenapi.CodeConfig {
					t.Fatalf("hostile response error = %#v, want PIVB_CONFIG", err)
				}
				if strings.Contains(apiErr.Remedy, "upgrade PIVB") {
					t.Fatalf("hostile response was misdiagnosed as version skew: %#v", apiErr)
				}
				wantSecurityLog := !strings.Contains(apiErr.Message, "stale or has an invalid lifetime")
				if apiErr.SecurityRelevant != wantSecurityLog {
					t.Fatalf("security relevance = %t, want %t for %#v", apiErr.SecurityRelevant, wantSecurityLog, apiErr)
				}
				status := c.Status()
				if status.LastSignAlias != "" || !status.LastSignAt.IsZero() {
					t.Fatalf("rejected response recorded a sign event: %#v", status)
				}
			}
		})
	}
}

func serveForwardResponse(t *testing.T, response forwardapi.MintResponse) string {
	t.Helper()
	directory, err := os.MkdirTemp("/tmp", "pivb-route-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(directory) })
	socket := filepath.Join(directory, "route.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/v1/mint" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(response); err != nil {
			t.Errorf("encode fake forward response: %v", err)
		}
	})}
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() {
		_ = server.Close()
		_ = listener.Close()
	})
	return socket
}

func TestForwardContextIsVisibleInTouchPrompt(t *testing.T) {
	c, signer := newTestCore(t, testConfig("session"), serialA)
	fixClock(c)
	unlockOK(t, c, pinA)
	req := roRequest()
	req.ExpectedCard = forwardapi.CardIdentity{Serial: serialA, KeyID: kidA, SPKIDER: signer.cards[serialA].cert.RawSubjectPublicKeyInfo}
	req.ForwardContext = forwardapi.ForwardContext{
		OriginNodeID: strings.Repeat("a", 32), WorkspaceID: strings.Repeat("b", 32), Bundle: "work",
		ClaimGeneration: 7, ProviderNodeID: strings.Repeat("c", 32), OperationID: strings.Repeat("d", 32),
	}
	mintOK(t, c, req)
	if len(signer.labels) != 1 {
		t.Fatalf("touch labels = %q", signer.labels)
	}
	for _, value := range []string{req.ForwardContext.OriginNodeID, req.ForwardContext.WorkspaceID, "bundle=work", "generation=7", req.ForwardContext.OperationID} {
		if !strings.Contains(signer.labels[0], value) {
			t.Errorf("touch label %q does not contain %q", signer.labels[0], value)
		}
	}
}
