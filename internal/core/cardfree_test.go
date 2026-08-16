package core

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/xlfe/pivb/internal/attachment"
	"github.com/xlfe/pivb/internal/config"
	"github.com/xlfe/pivb/internal/forwardapi"
	"github.com/xlfe/pivb/internal/pivsigner"
	"github.com/xlfe/pivb/internal/wif"
)

// cardFreeConfig is the shared fleet configuration with this host declared a
// card-free origin. Everything except the card key is identical to a card
// host's, which is the deployment the mode exists for.
func cardFreeConfig() *config.Config {
	cfg := testConfig("session")
	cfg.Card = config.CardNone
	return cfg
}

func newCardFreeCore() *Core {
	return New(cardFreeConfig(), pivsigner.CardFree{}, testVersion)
}

// wantCardFree asserts one refusal is the typed card-free error, names the
// configuration that caused it, and returns it for remedy checks.
func wantCardFree(t *testing.T, err error, operation string) *pivsigner.CardFreeError {
	t.Helper()
	var cardFree *pivsigner.CardFreeError
	if !errors.As(err, &cardFree) {
		t.Fatalf("error = %v, want *pivsigner.CardFreeError", err)
	}
	if !strings.Contains(err.Error(), `card = "none"`) {
		t.Errorf("card-free refusal does not name the configuration: %v", err)
	}
	if !strings.Contains(cardFree.Operation, operation) {
		t.Errorf("refused operation %q does not name %q", cardFree.Operation, operation)
	}
	return cardFree
}

func TestCardFreeCoreRefusesEveryCardOperation(t *testing.T) {
	c := newCardFreeCore()

	_, err := c.Unlock(context.Background(), pinA)
	unlockErr := wantCardFree(t, err, "PIN")
	if !strings.Contains(unlockErr.Remedy, "provider host") {
		t.Errorf("unlock remedy %q does not point at the provider host", unlockErr.Remedy)
	}

	// The local mint is refused from configuration alone: never PIVB_LOCKED,
	// which would send the operator to an unlock this daemon just refused.
	_, err = c.SubjectToken(context.Background(), roRequest())
	mintErr := wantCardFree(t, err, "locally signed")
	if errors.Is(err, ErrLocked) {
		t.Fatalf("card-free mint refusal reads as locked: %v", err)
	}
	if !strings.Contains(mintErr.Remedy, "route-required") {
		t.Errorf("mint remedy %q does not name the routed alternative", mintErr.Remedy)
	}

	_, err = c.DescribeForwardProvider(context.Background())
	wantCardFree(t, err, "describe")

	// Lock and invalidation stay harmless card-free: there is nothing to
	// clear, and both must keep answering so shared tooling works unchanged.
	c.Lock()
	if purged := c.InvalidateWorkspace(strings.Repeat("b", 32), 0); purged != 0 {
		t.Errorf("card-free invalidation purged %d assertions from an empty cache", purged)
	}
}

// TestCardFreePolicyAndStatusServeSharedConfiguration pins the two card-free
// discovery surfaces an origin depends on: zkad reads /v1/policy before it
// publishes a workspace route, and status is how an operator sees the mode.
func TestCardFreePolicyAndStatusServeSharedConfiguration(t *testing.T) {
	c := newCardFreeCore()

	policy := c.ForwardPolicy()
	if policy.ProviderResource != testResource || policy.IssuerURI != testIssuer {
		t.Fatalf("card-free policy identity = %q/%q", policy.ProviderResource, policy.IssuerURI)
	}
	if len(policy.EnrolledKeys) != 2 || len(policy.Aliases) != 2 {
		t.Fatalf("card-free policy dropped shared configuration: %#v", policy)
	}

	if got := c.Status().Card; got != config.CardNone {
		t.Errorf("card-free status card = %q, want %q", got, config.CardNone)
	}
	cardHost, _ := newTestCore(t, testConfig("session"), serialA)
	if got := cardHost.Status().Card; got != config.CardLocal {
		t.Errorf("hand-built card-host status card = %q, want effective default %q", got, config.CardLocal)
	}
}

// TestCardFreeCoreRoutesWorkspaceMints is the mode's whole point: a
// route-required mint on a card-free origin still routes, still verifies the
// forwarded assertion against local configuration, and never wants hardware.
func TestCardFreeCoreRoutesWorkspaceMints(t *testing.T) {
	now := time.Unix(testNowUnix, 0).UTC()
	fixture := loadFixture(t, "a")
	cfg := cardFreeConfig()

	claims, err := wif.NewClaims(cfg.Provider(), "ro", roTarget, serialA, kidA, testJTI, now, wif.DefaultLifetime)
	if err != nil {
		t.Fatal(err)
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
	cardIdentity := forwardapi.CardIdentity{Serial: serialA, KeyID: kidA, SPKIDER: append([]byte(nil), fixture.cert.RawSubjectPublicKeyInfo...)}
	forwardContext := forwardapi.ForwardContext{
		OriginNodeID: strings.Repeat("a", 32), WorkspaceID: strings.Repeat("b", 32), Bundle: "work",
		ClaimGeneration: 7, ProviderNodeID: strings.Repeat("c", 32), OperationID: strings.Repeat("e", 32),
	}
	socket := serveForwardResponse(t, forwardapi.MintResponse{
		Version: forwardapi.ProtocolVersion, IDToken: token, ExpirationTime: claims.Exp,
		Card: cardIdentity, ExpectedCard: cardIdentity, ForwardContext: forwardContext,
	})

	c := New(cfg, pivsigner.CardFree{}, testVersion)
	c.SetNowForTest(func() time.Time { return now })
	req := roRequest()
	req.Attachment = attachment.RouteRequired(attachment.ProtocolEnvironment, socket)
	result, err := c.SubjectToken(context.Background(), req)
	if err != nil {
		t.Fatalf("routed card-free SubjectToken: %v", err)
	}
	if result.IDToken != token || result.Serial != serialA || result.KeyID != kidA {
		t.Fatalf("routed card-free result = serial %d key %s", result.Serial, result.KeyID)
	}
	status := c.Status()
	if status.LastSignRoute != "zka-workspace-forwarded" || status.Card != config.CardNone {
		t.Fatalf("routed card-free status = route %q card %q", status.LastSignRoute, status.Card)
	}
}
