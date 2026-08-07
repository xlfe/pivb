package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/xlfe/pivb/internal/agentsource"
	"github.com/xlfe/pivb/internal/execsource"
	"github.com/xlfe/pivb/internal/sessionapi"
	"github.com/xlfe/pivb/internal/tokenapi"
	"github.com/xlfe/pivb/internal/uds"
	"github.com/xlfe/pivb/internal/wif"
)

const (
	helperAudience = "//iam.googleapis.com/projects/123/locations/global/workloadIdentityPools/pool/providers/provider"
	helperTarget   = "readonly-sa@example-project.iam.gserviceaccount.com"
)

type helperUpstream struct{ calls int }

func (u *helperUpstream) SubjectToken(context.Context, sessionapi.UpstreamRequest) (tokenapi.SubjectTokenResponse, error) {
	u.calls++
	return tokenapi.SubjectTokenResponse{IDToken: "h.p.s", ExpirationTime: 1785585870}, nil
}

func startRelay(t *testing.T, upstream sessionapi.Upstream) string {
	t.Helper()
	socket := filepath.Join(t.TempDir(), "session.sock")
	api := &sessionapi.API{Session: sessionapi.Session{
		Alias: "ro", Target: helperTarget, ExternalAccountAudience: helperAudience,
		Source: agentsource.Agent("codex:agentic/ro", "0123456789abcdef0123456789abcdef"),
	}, Upstream: upstream}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- uds.Serve(ctx, socket, api.Handler()) }()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Errorf("serve relay: %v", err)
		}
	})
	deadline := time.Now().Add(5 * time.Second)
	for {
		conn, err := net.DialTimeout("unix", socket, 50*time.Millisecond)
		if err == nil {
			conn.Close()
			return socket
		}
		if time.Now().After(deadline) {
			t.Fatalf("relay did not start: %v", err)
		}
		time.Sleep(time.Millisecond)
	}
}

func setExecutableEnv(t *testing.T, audience string, email *string) {
	t.Helper()
	t.Setenv(execsource.EnvTokenType, wif.TokenType)
	t.Setenv(execsource.EnvAudience, audience)
	if email == nil {
		_ = os.Unsetenv(execsource.EnvImpersonatedEmail)
	} else {
		t.Setenv(execsource.EnvImpersonatedEmail, *email)
	}
	_ = os.Unsetenv(execsource.EnvOutputFile)
}

func TestHelperMintsWithoutConfiguration(t *testing.T) {
	upstream := &helperUpstream{}
	socket := startRelay(t, upstream)
	setExecutableEnv(t, helperAudience, nil)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(t.TempDir(), "no-config-here"))

	var stdout, stderr strings.Builder
	if err := run([]string{"--socket", socket}, &stdout, &stderr); err != nil {
		t.Fatalf("run: %v, stderr %q", err, stderr.String())
	}
	if upstream.calls != 1 || stderr.Len() != 0 {
		t.Fatalf("calls/stderr = %d/%q", upstream.calls, stderr.String())
	}
	var doc map[string]any
	dec := json.NewDecoder(strings.NewReader(stdout.String()))
	if err := dec.Decode(&doc); err != nil || doc["id_token"] != "h.p.s" {
		t.Fatalf("stdout = %q, err %v", stdout.String(), err)
	}
	if err := dec.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		t.Fatalf("stdout has multiple documents: %q", stdout.String())
	}
}

func TestHelperEnvironmentRejectionsDoNotMint(t *testing.T) {
	upstream := &helperUpstream{}
	socket := startRelay(t, upstream)
	tests := []struct {
		name   string
		setup  func(*testing.T)
		detail string
	}{
		{"wrong token", func(t *testing.T) { setExecutableEnv(t, helperAudience, nil); t.Setenv(execsource.EnvTokenType, "jwt") }, execsource.EnvTokenType},
		{"wrong audience", func(t *testing.T) { setExecutableEnv(t, "tampered", nil) }, "audience"},
		{"wrong email", func(t *testing.T) {
			email := "deploy@example-project.iam.gserviceaccount.com"
			setExecutableEnv(t, helperAudience, &email)
		}, "impersonation"},
		{"present empty output", func(t *testing.T) { setExecutableEnv(t, helperAudience, nil); t.Setenv(execsource.EnvOutputFile, "") }, execsource.EnvOutputFile},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.setup(t)
			var stdout, stderr strings.Builder
			err := run([]string{"--socket", socket}, &stdout, &stderr)
			if !errors.Is(err, execsource.ErrReported) || !strings.Contains(strings.ToLower(stderr.String()), strings.ToLower(tt.detail)) {
				t.Fatalf("err/stderr = %v/%q", err, stderr.String())
			}
		})
	}
	if upstream.calls != 0 {
		t.Fatalf("rejected environments minted %d times", upstream.calls)
	}
}

func TestHelperRejectsInvalidSocketInvocation(t *testing.T) {
	for _, tt := range []struct {
		name string
		args []string
	}{
		{"missing socket", nil},
		{"relative socket", []string{"--socket", "session.sock"}},
		{"positional argument", []string{"--socket", "/run/pivb-agent/session.sock", "extra"}},
		{"alias selector", []string{"--alias", "deploy", "--socket", "/run/pivb-agent/session.sock"}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var stdout, stderr strings.Builder
			err := run(tt.args, &stdout, &stderr)
			if !errors.Is(err, execsource.ErrReported) {
				t.Fatalf("run error = %v, stderr %q", err, stderr.String())
			}
			var doc execsource.Error
			if decodeErr := json.Unmarshal([]byte(stdout.String()), &doc); decodeErr != nil || doc.Success || doc.Code != tokenapi.CodeEnv {
				t.Fatalf("stdout = %q, decode error = %v", stdout.String(), decodeErr)
			}
		})
	}
}
