package agentapi

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/xlfe/pivb/internal/config"
	"github.com/xlfe/pivb/internal/core"
)

type apiSigner struct{}

func (apiSigner) VerifyPIN(context.Context, string) (uint32, int, error) { return 7, 3, nil }
func (apiSigner) Sign(context.Context, string, string, []byte) ([]byte, uint32, error) {
	return nil, 0, errors.New("not used")
}

type apiMinter struct{ now time.Time }

func (m apiMinter) Mint(_ context.Context, request core.MintRequest) (core.MintedCredential, error) {
	if request.Purpose == core.MintIdentity {
		return core.MintedCredential{Value: "id-" + request.Audience, ExpiresAt: m.now.Add(time.Hour), Serial: 7}, nil
	}
	return core.MintedCredential{Value: "token-" + request.AliasName, ExpiresAt: m.now.Add(time.Hour), Serial: 7}, nil
}

func TestUnixAPIAndPeerCredentials(t *testing.T) {
	now := time.Unix(2_000_000_000, 0)
	cfg := &config.Config{
		PINCache: "session", DefaultAlias: "ro",
		Aliases: map[string]config.Alias{"ro": {Cloud: "gcp", Target: "ro@example.test", ProjectID: "p", LifetimeS: 3600}},
	}
	c := core.New(cfg, apiSigner{}, apiMinter{now: now}, "test-version")
	c.SetNowForTest(func() time.Time { return now })
	api := &API{Core: c}
	socket := filepath.Join(t.TempDir(), "pivb", "agent.sock")
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- ServeUnix(ctx, socket, api.Handler(true)) }()
	client := NewClient(socket)
	deadline := time.Now().Add(2 * time.Second)
	for {
		_, err := client.Status(context.Background())
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("agent did not start: %v", err)
		}
		time.Sleep(5 * time.Millisecond)
	}
	if mode := mustMode(t, filepath.Dir(socket)); mode.Perm() != 0700 {
		t.Fatalf("socket directory mode = %o", mode.Perm())
	}
	if mode := mustMode(t, socket); mode.Perm() != 0600 || mode&os.ModeSocket == 0 {
		t.Fatalf("socket mode = %v", mode)
	}
	if _, err := client.Token(context.Background()); err == nil {
		t.Fatal("empty token cache did not fail")
	} else {
		var httpErr *HTTPError
		if !errors.As(err, &httpErr) || httpErr.Status != 503 || httpErr.Remedy == "" {
			t.Fatalf("token error = %#v", err)
		}
	}
	if _, err := client.Unlock(context.Background(), "123456"); err != nil {
		t.Fatal(err)
	}
	token, err := client.Use(context.Background(), "ro")
	if err != nil || token.AccessToken != "token-ro" || token.Cloud != "gcp" {
		t.Fatalf("use response = %#v, %v", token, err)
	}
	if _, err := client.Use(context.Background(), "missing"); err == nil {
		t.Fatal("unknown alias did not fail")
	} else {
		var httpErr *HTTPError
		if !errors.As(err, &httpErr) || httpErr.Status != 400 {
			t.Fatalf("unknown alias error = %v", err)
		}
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(socket); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("socket remained after shutdown: %v", err)
	}
}

func mustMode(t *testing.T, path string) os.FileMode {
	t.Helper()
	st, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	return st.Mode()
}
