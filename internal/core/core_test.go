package core

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/xlfe/pivb/internal/config"
)

type fakeSigner struct{ verifies int }

func (s *fakeSigner) VerifyPIN(context.Context, string) (uint32, int, error) {
	s.verifies++
	return 99, 3, nil
}
func (s *fakeSigner) Sign(context.Context, string, string, []byte) ([]byte, uint32, error) {
	panic("core minter should own signing")
}

type fakeMinter struct {
	now       time.Time
	accessErr error
	accesses  int
	ids       int
}

func (m *fakeMinter) mintAccess(name, pin string) (MintedAccess, error) {
	m.accesses++
	if pin == "" {
		return MintedAccess{}, errors.New("empty PIN")
	}
	if m.accessErr != nil {
		return MintedAccess{}, m.accessErr
	}
	return MintedAccess{Value: "token-" + name, ExpiresAt: m.now.Add(time.Hour), Serial: 99}, nil
}

type completeFakeMinter struct{ *fakeMinter }

func (m *completeFakeMinter) Mint(_ context.Context, request MintRequest) (MintedCredential, error) {
	if request.Purpose == MintAccess {
		return m.mintAccess(request.AliasName, request.PIN)
	}
	m.ids++
	if request.PIN == "" {
		return MintedCredential{}, errors.New("empty PIN")
	}
	return MintedCredential{Value: "id-" + request.Audience, ExpiresAt: m.now.Add(time.Hour), Serial: 99}, nil
}

func testConfig(mode string) *config.Config {
	return &config.Config{
		PINCache: mode, DefaultAlias: "ro",
		Aliases: map[string]config.Alias{
			"ro":     {Cloud: "gcp", Target: "ro@example.test", ProjectID: "p", LifetimeS: 3600},
			"deploy": {Cloud: "gcp", Target: "deploy@example.test", ProjectID: "p", LifetimeS: 3600},
		},
	}
}

func TestUseSwitchesAtomicallyAndLockDropsCredentials(t *testing.T) {
	now := time.Unix(2_000_000_000, 0)
	signer := &fakeSigner{}
	base := &fakeMinter{now: now}
	minter := &completeFakeMinter{base}
	c := New(testConfig("session"), signer, minter, "test")
	c.SetNowForTest(func() time.Time { return now })
	if _, err := c.Use(context.Background(), "ro"); !errors.Is(err, ErrLocked) {
		t.Fatalf("use without unlock error = %v", err)
	}
	if _, err := c.Unlock(context.Background(), "123456"); err != nil {
		t.Fatal(err)
	}
	first, err := c.Use(context.Background(), "ro")
	if err != nil {
		t.Fatal(err)
	}
	if first.AccessToken != "token-ro" || first.Cloud != "gcp" || first.Subject != "ro@example.test" {
		t.Fatalf("first token = %#v", first)
	}
	base.accessErr = errors.New("provider down")
	if _, err := c.Use(context.Background(), "deploy"); err == nil {
		t.Fatal("failed switch unexpectedly succeeded")
	}
	status := c.Status()
	if status.ActiveAlias != "ro" || status.TokenExpiresIn != 3600 || !status.PINCached {
		t.Fatalf("status after failed switch = %#v", status)
	}
	if token, err := c.Token(); err != nil || token.AccessToken != "token-ro" {
		t.Fatalf("old token was not retained across failed mint: %#v %v", token, err)
	}
	base.accessErr = nil
	if _, err := c.Use(context.Background(), "deploy"); err != nil {
		t.Fatal(err)
	}
	if token, _ := c.Token(); token.AccessToken != "token-deploy" {
		t.Fatalf("active token = %#v", token)
	}
	c.Lock()
	if _, err := c.Token(); !errors.Is(err, ErrNoToken) {
		t.Fatalf("token after lock error = %v", err)
	}
	if c.Status().PINCached {
		t.Fatal("PIN remained cached after lock")
	}
}

func TestNeverModeConsumesUnlockAndIdentityCachesByAudience(t *testing.T) {
	now := time.Unix(2_000_000_000, 0)
	signer := &fakeSigner{}
	base := &fakeMinter{now: now}
	minter := &completeFakeMinter{base}
	c := New(testConfig("never"), signer, minter, "test")
	c.SetNowForTest(func() time.Time { return now })
	_, _ = c.Unlock(context.Background(), "123456")
	if _, err := c.Use(context.Background(), "ro"); err != nil {
		t.Fatal(err)
	}
	if c.Status().PINCached {
		t.Fatal("never mode retained PIN after mint")
	}
	if _, err := c.Renew(context.Background()); !errors.Is(err, ErrLocked) {
		t.Fatalf("renew without fresh unlock = %v", err)
	}
	_, _ = c.Unlock(context.Background(), "123456")
	first, err := c.Identity(context.Background(), "aud")
	if err != nil {
		t.Fatal(err)
	}
	second, err := c.Identity(context.Background(), "aud")
	if err != nil || second.Token != first.Token || !second.ExpiresAt.Equal(first.ExpiresAt) || minter.ids != 1 {
		t.Fatalf("identity cache failed: first=%#v second=%#v calls=%d err=%v", first, second, minter.ids, err)
	}
}
