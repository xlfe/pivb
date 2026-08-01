package core

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/xlfe/pivb/internal/config"
	"github.com/xlfe/pivb/internal/pivsigner"
)

type fakeSigner struct{ verifies int }

func (s *fakeSigner) VerifyPIN(context.Context, string) (uint32, int, error) {
	s.verifies++
	return 99, 3, nil
}
func (s *fakeSigner) Sign(context.Context, string, string, func(uint32) ([]byte, error)) ([]byte, uint32, error) {
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
	if status.ActiveAlias != "ro" || status.TokenExpiresIn != 3600 || !status.PINCached || status.PINVerifiedSerial != 99 || status.YubiKeySerial != 99 {
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

func TestStatusIsCardFree(t *testing.T) {
	signer := &fakeSigner{}
	base := &fakeMinter{now: time.Unix(2_000_000_000, 0)}
	c := New(testConfig("session"), signer, &completeFakeMinter{base}, "test")
	for range 3 {
		status := c.Status()
		if status.PINVerifiedSerial != 0 || status.YubiKeySerial != 0 {
			t.Fatalf("fresh status reported a card serial: %#v", status)
		}
	}
	if signer.verifies != 0 || base.accesses != 0 || base.ids != 0 {
		t.Fatalf("status performed card/provider work: verifies=%d accesses=%d ids=%d", signer.verifies, base.accesses, base.ids)
	}
}

type fleetSigner struct {
	current        uint32
	verified       uint32
	pins           map[uint32]string
	retries        map[uint32]int
	swapVerifies   int
	signatures     int
	digestRequests int
}

func (s *fleetSigner) VerifyPIN(_ context.Context, pin string) (uint32, int, error) {
	retries := s.retries[s.current]
	if pin != s.pins[s.current] {
		return s.current, retries - 1, &pivsigner.PINError{Retries: retries - 1, Err: errors.New("wrong PIN")}
	}
	s.verified = s.current
	return s.current, retries, nil
}

func (s *fleetSigner) Sign(_ context.Context, _ string, pin string, digestFor func(uint32) ([]byte, error)) ([]byte, uint32, error) {
	serial := s.current
	s.digestRequests++
	if _, err := digestFor(serial); err != nil {
		return nil, 0, err
	}
	if serial != s.verified {
		retries := s.retries[serial]
		if retries <= 1 {
			return nil, serial, &pivsigner.PINError{Retries: retries, Err: errors.New("refusing final PIN attempt"), Remedy: "unlock this key"}
		}
		s.swapVerifies++
		if pin != s.pins[serial] {
			s.verified = 0
			return nil, serial, &pivsigner.PINError{
				Retries: retries - 1, Err: errors.New("fleet keys have different PINs"),
				Remedy: "run `pivb unlock` with this key inserted", ClearCachedPIN: true,
			}
		}
		s.verified = serial
	}
	s.signatures++
	return []byte("signature"), serial, nil
}

type fleetMinter struct {
	signer *fleetSigner
	now    time.Time
}

func (m *fleetMinter) Mint(ctx context.Context, request MintRequest) (MintedCredential, error) {
	_, serial, err := m.signer.Sign(ctx, request.AliasName, request.PIN, func(uint32) ([]byte, error) {
		return []byte("digest"), nil
	})
	if err != nil {
		return MintedCredential{Serial: serial}, fmt.Errorf("sign fleet assertion: %w", err)
	}
	return MintedCredential{Value: "token", ExpiresAt: m.now.Add(time.Hour), Serial: serial}, nil
}

func TestFleetKeySwapPINHandling(t *testing.T) {
	now := time.Unix(2_000_000_000, 0)
	newCore := func(pinA, pinB string, retriesB int) (*Core, *fleetSigner) {
		signer := &fleetSigner{
			current: 10,
			pins:    map[uint32]string{10: pinA, 20: pinB},
			retries: map[uint32]int{10: 3, 20: retriesB},
		}
		c := New(testConfig("session"), signer, &fleetMinter{signer: signer, now: now}, "test")
		c.SetNowForTest(func() time.Time { return now })
		if _, err := c.Unlock(context.Background(), pinA); err != nil {
			t.Fatal(err)
		}
		return c, signer
	}

	t.Run("same PIN re-verifies and proceeds", func(t *testing.T) {
		c, signer := newCore("123456", "123456", 3)
		if status := c.Status(); status.PINVerifiedSerial != 10 || status.YubiKeySerial != 0 {
			t.Fatalf("status after unlock = %#v", status)
		}
		signer.current = 20
		if _, err := c.Use(context.Background(), "ro"); err != nil {
			t.Fatal(err)
		}
		if signer.swapVerifies != 1 || signer.signatures != 1 {
			t.Fatalf("swap verifies = %d, signatures = %d", signer.swapVerifies, signer.signatures)
		}
		if status := c.Status(); !status.PINCached || status.PINVerifiedSerial != 20 || status.YubiKeySerial != 20 {
			t.Fatalf("status after swap = %#v", status)
		}
	})

	t.Run("different PIN clears cache and surfaces remedy", func(t *testing.T) {
		c, signer := newCore("111111", "222222", 3)
		signer.current = 20
		_, err := c.Use(context.Background(), "ro")
		var pinErr *pivsigner.PINError
		if !errors.As(err, &pinErr) || pinErr.Remedy == "" || !strings.Contains(pinErr.Remedy, "pivb unlock") {
			t.Fatalf("swap error = %#v", err)
		}
		if signer.swapVerifies != 1 || signer.signatures != 0 {
			t.Fatalf("swap verifies = %d, signatures = %d", signer.swapVerifies, signer.signatures)
		}
		if status := c.Status(); status.PINCached || status.PINVerifiedSerial != 0 || status.YubiKeySerial != 0 {
			t.Fatalf("status after rejected swap = %#v", status)
		}
		if _, err := c.Use(context.Background(), "ro"); !errors.Is(err, ErrLocked) {
			t.Fatalf("use after rejected swap = %v", err)
		}
	})

	t.Run("final retry is never attempted", func(t *testing.T) {
		c, signer := newCore("123456", "123456", 1)
		signer.current = 20
		_, err := c.Use(context.Background(), "ro")
		var pinErr *pivsigner.PINError
		if !errors.As(err, &pinErr) || pinErr.Retries != 1 {
			t.Fatalf("swap error = %#v", err)
		}
		if signer.swapVerifies != 0 || signer.signatures != 0 {
			t.Fatalf("swap verifies = %d, signatures = %d", signer.swapVerifies, signer.signatures)
		}
		if status := c.Status(); !status.PINCached || status.PINVerifiedSerial != 10 {
			t.Fatalf("status after guarded swap = %#v", status)
		}
	})
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
