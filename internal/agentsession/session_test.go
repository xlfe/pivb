package agentsession

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/xlfe/pivb/internal/config"
	"github.com/xlfe/pivb/internal/core"
	"github.com/xlfe/pivb/internal/sessionapi"
	"github.com/xlfe/pivb/internal/uds"
	"github.com/xlfe/pivb/internal/wif"
	"github.com/xlfe/pivb/internal/wifapi"
)

const runtimeTarget = "readonly-sa@example-project-id.iam.gserviceaccount.com"

type childInspection struct {
	SessionDir        string            `json:"session_dir"`
	SessionID         string            `json:"session_id"`
	ProcessGroup      int               `json:"process_group"`
	Args              []string          `json:"args"`
	Descriptor        Descriptor        `json:"descriptor"`
	CredentialCommand string            `json:"credential_command"`
	Modes             map[string]uint32 `json:"modes"`
}

func TestAgentSessionChild(t *testing.T) {
	if os.Getenv("PIVB_TEST_AGENT_CHILD") != "1" {
		return
	}
	sessionDir := os.Getenv(EnvSessionDir)
	resultPath := os.Getenv("PIVB_TEST_RESULT")
	mode := os.Getenv("PIVB_TEST_CHILD_MODE")
	if mode == "wait" || mode == "ignore-hup-term" {
		if mode == "ignore-hup-term" {
			signal.Ignore(syscall.SIGHUP, syscall.SIGTERM)
		}
		_ = os.WriteFile(resultPath, []byte(sessionDir), 0o600)
		for {
			time.Sleep(time.Second)
		}
	}
	if mode == "exit7" {
		os.Exit(7)
	}
	if mode == "mint" {
		descriptorData, err := os.ReadFile(filepath.Join(sessionDir, "session.json"))
		var descriptor Descriptor
		if err != nil || json.Unmarshal(descriptorData, &descriptor) != nil {
			os.Exit(96)
		}
		client := sessionapi.NewClient(filepath.Join(sessionDir, "session.sock"))
		resp, err := client.SubjectToken(context.Background(), sessionapi.Request{ExternalAccountAudience: descriptor.ExternalAccountAudience})
		if err != nil {
			_ = os.WriteFile(resultPath, []byte(err.Error()), 0o600)
			os.Exit(97)
		}
		_ = os.WriteFile(resultPath, []byte(resp.IDToken), 0o600)
		os.Exit(0)
	}

	inspection := childInspection{
		SessionDir: sessionDir, SessionID: os.Getenv(EnvSessionID),
		ProcessGroup: syscall.Getpgrp(), Modes: map[string]uint32{},
	}
	for i, arg := range os.Args {
		if arg == "--" {
			inspection.Args = append([]string(nil), os.Args[i+1:]...)
			break
		}
	}
	descriptorData, err := os.ReadFile(filepath.Join(sessionDir, "session.json"))
	if err != nil || json.Unmarshal(descriptorData, &inspection.Descriptor) != nil {
		os.Exit(91)
	}
	credentialData, err := os.ReadFile(filepath.Join(sessionDir, "credential.json"))
	if err != nil {
		os.Exit(92)
	}
	var credential struct {
		CredentialSource struct {
			Executable struct {
				Command string `json:"command"`
			} `json:"executable"`
		} `json:"credential_source"`
	}
	if json.Unmarshal(credentialData, &credential) != nil {
		os.Exit(93)
	}
	inspection.CredentialCommand = credential.CredentialSource.Executable.Command
	for _, name := range []string{"credential.json", "session.json", "session.sock"} {
		info, err := os.Lstat(filepath.Join(sessionDir, name))
		if err != nil {
			os.Exit(94)
		}
		inspection.Modes[name] = uint32(info.Mode().Perm())
	}
	data, _ := json.Marshal(inspection)
	if os.WriteFile(resultPath, data, 0o600) != nil {
		os.Exit(95)
	}
	os.Exit(0)
}

func runtimeConfig() *config.Config {
	return &config.Config{
		WIF:     config.WIF{ProjectNumber: "123456789012", PoolID: "pivb", ProviderID: "yubikey-piv", IssuerURI: "https://auth.example/pivb"},
		Aliases: map[string]config.Alias{"ro": {Cloud: "gcp", Target: runtimeTarget, LifetimeS: 1800}},
	}
}

func childCommand(mode, result string, args ...string) ([]string, []string) {
	command := []string{os.Args[0], "-test.run=^TestAgentSessionChild$", "--"}
	command = append(command, args...)
	env := []string{
		"PIVB_TEST_AGENT_CHILD=1",
		"PIVB_TEST_CHILD_MODE=" + mode,
		"PIVB_TEST_RESULT=" + result,
		"PATH=" + os.Getenv("PATH"),
	}
	return command, env
}

func baseOptions(runtimeDir string, command, env []string) Options {
	return Options{
		Config: runtimeConfig(), Alias: "ro", SourceLabel: "codex:agentic/ro",
		WIFSocket: filepath.Join(runtimeDir, "absent-wif.sock"), RuntimeDir: runtimeDir,
		Command: command, Env: env, Stdin: bytes.NewReader(nil), Stdout: io.Discard, Stderr: io.Discard,
		Random: bytes.NewReader([]byte("0123456789abcdef")),
	}
}

func shortRuntimeDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "pivb-as-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return dir
}

func TestRunCreatesFixedArtifactsAndPreservesForegroundProcessGroup(t *testing.T) {
	runtimeDir := shortRuntimeDir(t)
	result := filepath.Join(t.TempDir(), "inspection.json")
	wantArgs := []string{"literal $HOME", "$(not-a-shell)", "semi;colon"}
	command, env := childCommand("inspect", result, wantArgs...)
	if err := Run(baseOptions(runtimeDir, command, env)); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(result)
	if err != nil {
		t.Fatal(err)
	}
	var got childInspection
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatal(err)
	}
	if fmt.Sprint(got.Args) != fmt.Sprint(wantArgs) {
		t.Fatalf("child args = %q, want %q", got.Args, wantArgs)
	}
	if got.ProcessGroup != syscall.Getpgrp() {
		t.Fatalf("child process group = %d, supervisor = %d", got.ProcessGroup, syscall.Getpgrp())
	}
	if got.Descriptor.Alias != "ro" || got.Descriptor.Target != runtimeTarget || got.Descriptor.SourceLabel != "codex:agentic/ro" || got.Descriptor.CreatedAt == "" {
		t.Fatalf("descriptor = %+v", got.Descriptor)
	}
	if got.Descriptor.SessionID != got.SessionID || len(got.SessionID) != 32 {
		t.Fatalf("descriptor/env session IDs = %q/%q", got.Descriptor.SessionID, got.SessionID)
	}
	wantCommand := wif.AgentHelperPath + " --socket " + wif.AgentSessionSocketPath
	if got.CredentialCommand != wantCommand {
		t.Fatalf("credential command = %q, want %q", got.CredentialCommand, wantCommand)
	}
	for name, mode := range got.Modes {
		if mode != 0o600 {
			t.Errorf("%s mode = %#o, want 0600", name, mode)
		}
	}
	if _, err := os.Stat(got.SessionDir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("session directory survived child exit: %v", err)
	}
}

func TestRunPropagatesChildExitCode(t *testing.T) {
	result := filepath.Join(t.TempDir(), "unused")
	command, env := childCommand("exit7", result)
	err := Run(baseOptions(shortRuntimeDir(t), command, env))
	var exit *ChildExitError
	if !errors.As(err, &exit) || exit.Code != 7 || exit.Signal != 0 {
		t.Fatalf("Run error = %#v, want exit 7", err)
	}
}

func TestRunPreservesSuccessfulChildStatusWhenCleanupFails(t *testing.T) {
	runtimeDir := shortRuntimeDir(t)
	result := filepath.Join(t.TempDir(), "inspection.json")
	command, env := childCommand("inspect", result)
	var stderr bytes.Buffer
	opts := baseOptions(runtimeDir, command, env)
	opts.Stderr = &stderr
	opts.RemoveAll = func(string) error { return errors.New("injected cleanup failure") }
	if err := Run(opts); err != nil {
		t.Fatalf("successful child status was overwritten: %v", err)
	}
	if !strings.Contains(stderr.String(), "injected cleanup failure") {
		t.Fatalf("cleanup failure was not reported: %q", stderr.String())
	}
}

func TestRunRejectsInvalidPreconditions(t *testing.T) {
	runtimeDir := shortRuntimeDir(t)
	command, env := childCommand("exit7", filepath.Join(t.TempDir(), "unused"))
	valid := baseOptions(runtimeDir, command, env)
	tests := []struct {
		name   string
		mutate func(*Options)
		want   string
	}{
		{"nil config", func(o *Options) { o.Config = nil }, "loaded configuration"},
		{"unknown alias", func(o *Options) { o.Alias = "deploy" }, "not configured"},
		{"missing WIF socket", func(o *Options) { o.WIFSocket = "" }, "socket location"},
		{"empty command", func(o *Options) { o.Command = nil }, "child command"},
		{"relative runtime", func(o *Options) { o.RuntimeDir = "relative" }, "absolute path"},
		{"unsafe label", func(o *Options) { o.SourceLabel = "codex:bad\nproject/ro" }, "source-label"},
		{"wrong label role", func(o *Options) { o.SourceLabel = "codex:agentic/deploy" }, "does not match alias"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts := valid
			tt.mutate(&opts)
			if err := Run(opts); err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("Run error = %v, want %q", err, tt.want)
			}
		})
	}
}

func TestRunForwardsTerminationAndCleansUp(t *testing.T) {
	runtimeDir := shortRuntimeDir(t)
	ready := filepath.Join(t.TempDir(), "ready")
	command, env := childCommand("wait", ready)
	signals := make(chan os.Signal, 1)
	opts := baseOptions(runtimeDir, command, env)
	opts.Signals = signals
	done := make(chan error, 1)
	go func() { done <- Run(opts) }()

	deadline := time.Now().Add(5 * time.Second)
	var sessionDir string
	for time.Now().Before(deadline) {
		if data, err := os.ReadFile(ready); err == nil {
			sessionDir = string(data)
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if sessionDir == "" {
		t.Fatal("child did not become ready")
	}
	signals <- syscall.SIGTERM
	err := <-done
	var exit *ChildExitError
	if !errors.As(err, &exit) || exit.Signal != syscall.SIGTERM {
		t.Fatalf("Run error = %#v, want SIGTERM child exit", err)
	}
	if _, err := os.Stat(sessionDir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("session directory survived signal exit: %v", err)
	}
}

func TestRunKeepsTerminalSignalsInForegroundProcessGroup(t *testing.T) {
	runtimeDir := shortRuntimeDir(t)
	ready := filepath.Join(t.TempDir(), "ready")
	command, env := childCommand("wait", ready)
	signals := make(chan os.Signal, 2)
	opts := baseOptions(runtimeDir, command, env)
	opts.Signals = signals
	done := make(chan error, 1)
	go func() { done <- Run(opts) }()
	waitForFile(t, ready)

	// The terminal already delivers these to every foreground process. The
	// supervisor consumes its copy instead of duplicating it to the child.
	signals <- os.Interrupt
	select {
	case err := <-done:
		t.Fatalf("targeted test SIGINT unexpectedly stopped child: %v", err)
	case <-time.After(50 * time.Millisecond):
	}
	signals <- syscall.SIGTERM
	if err := <-done; err == nil {
		t.Fatal("SIGTERM did not terminate child")
	}
}

func TestRunEscalatesOnlyRepeatedSameTerminationSignal(t *testing.T) {
	runtimeDir := shortRuntimeDir(t)
	ready := filepath.Join(t.TempDir(), "ready")
	command, env := childCommand("ignore-hup-term", ready)
	signals := make(chan os.Signal, 3)
	opts := baseOptions(runtimeDir, command, env)
	opts.Signals = signals
	done := make(chan error, 1)
	go func() { done <- Run(opts) }()
	waitForFile(t, ready)

	signals <- syscall.SIGHUP
	signals <- syscall.SIGTERM
	select {
	case err := <-done:
		t.Fatalf("distinct first signals escalated unexpectedly: %v", err)
	case <-time.After(50 * time.Millisecond):
	}
	signals <- syscall.SIGTERM
	err := <-done
	var exit *ChildExitError
	if !errors.As(err, &exit) || exit.Signal != syscall.SIGKILL {
		t.Fatalf("Run error = %#v, want second SIGTERM to escalate to SIGKILL", err)
	}
}

func TestRunTerminatesChildAndCleansUpWhenRelayFails(t *testing.T) {
	runtimeDir := shortRuntimeDir(t)
	ready := filepath.Join(t.TempDir(), "ready")
	command, env := childCommand("ignore-hup-term", ready)
	opts := baseOptions(runtimeDir, command, env)
	var logs bytes.Buffer
	opts.Logger = slog.New(slog.NewTextHandler(&logs, nil))
	opts.RelayGrace = 20 * time.Millisecond
	opts.ServeRelay = func(_ context.Context, _ *uds.Listener, _ http.Handler) error {
		deadline := time.Now().Add(5 * time.Second)
		for time.Now().Before(deadline) {
			if _, err := os.Stat(ready); err == nil {
				return errors.New("injected listener failure")
			}
			time.Sleep(5 * time.Millisecond)
		}
		return errors.New("child did not become ready")
	}
	err := Run(opts)
	if err == nil || !strings.Contains(err.Error(), "agent-session relay failed: injected listener failure") {
		t.Fatalf("Run error = %v, want injected relay failure", err)
	}
	sessionDir, readErr := os.ReadFile(ready)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if _, statErr := os.Stat(string(sessionDir)); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("session directory survived relay failure: %v", statErr)
	}
	if !strings.Contains(logs.String(), "signal: killed") {
		t.Fatalf("relay failure did not exercise SIGKILL escalation: %q", logs.String())
	}
}

func TestRunSweepsOldDeadSessionOnly(t *testing.T) {
	runtimeDir := shortRuntimeDir(t)
	root := filepath.Join(runtimeDir, "pivb-agent")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	stale := filepath.Join(root, strings.Repeat("a", 32))
	if err := os.Mkdir(stale, 0o700); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 8, 7, 12, 0, 0, 0, time.UTC)
	old := now.Add(-2 * time.Minute)
	if err := os.Chtimes(stale, old, old); err != nil {
		t.Fatal(err)
	}
	result := filepath.Join(t.TempDir(), "inspection.json")
	command, env := childCommand("inspect", result)
	opts := baseOptions(runtimeDir, command, env)
	opts.Now = func() time.Time { return now }
	if err := Run(opts); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(stale); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("stale directory survived sweep: %v", err)
	}
}

func TestSweepStalePreservesLiveAndRecentSessions(t *testing.T) {
	root := filepath.Join(shortRuntimeDir(t), "pivb-agent")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 8, 7, 12, 0, 0, 0, time.UTC)
	oldLive := filepath.Join(root, strings.Repeat("b", 32))
	recentDead := filepath.Join(root, strings.Repeat("c", 32))
	for _, dir := range []string{oldLive, recentDead} {
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	listener, err := net.Listen("unix", filepath.Join(oldLive, "session.sock"))
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	if err := os.Chtimes(oldLive, now.Add(-2*time.Minute), now.Add(-2*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(recentDead, now.Add(-30*time.Second), now.Add(-30*time.Second)); err != nil {
		t.Fatal(err)
	}

	sweepStale(root, now, slog.New(slog.NewTextHandler(io.Discard, nil)))
	for _, dir := range []string{oldLive, recentDead} {
		if _, err := os.Stat(dir); err != nil {
			t.Errorf("protected session %q was removed: %v", filepath.Base(dir), err)
		}
	}
}

func waitForFile(t *testing.T, path string) []byte {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if data, err := os.ReadFile(path); err == nil {
			return data
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("file %q did not become ready", path)
	return nil
}

type runtimeFakeCore struct {
	request core.SubjectTokenRequest
}

func (f *runtimeFakeCore) SubjectToken(_ context.Context, req core.SubjectTokenRequest) (core.SubjectTokenResult, error) {
	f.request = req
	return core.SubjectTokenResult{IDToken: "h.p.s", ExpiresAt: time.Unix(1785585870, 0), Serial: 123, KeyID: "kid"}, nil
}

func startHostWIF(t *testing.T, socket string, fake *runtimeFakeCore) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	api := &wifapi.API{Core: fake, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	go func() { done <- uds.Serve(ctx, socket, api.Handler()) }()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Errorf("host WIF server: %v", err)
		}
	})
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("unix", socket, 50*time.Millisecond)
		if err == nil {
			conn.Close()
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("host WIF server did not start")
}

func TestRunRelaysOnlyCapturedIdentityToHostWIF(t *testing.T) {
	runtimeDir := shortRuntimeDir(t)
	hostSocket := filepath.Join(runtimeDir, "wif.sock")
	fake := &runtimeFakeCore{}
	startHostWIF(t, hostSocket, fake)
	result := filepath.Join(t.TempDir(), "token")
	command, env := childCommand("mint", result)
	opts := baseOptions(runtimeDir, command, env)
	opts.WIFSocket = hostSocket
	if err := Run(opts); err != nil {
		t.Fatal(err)
	}
	if token, err := os.ReadFile(result); err != nil || string(token) != "h.p.s" {
		t.Fatalf("relayed token/error = %q/%v", token, err)
	}
	if fake.request.Alias != "ro" || fake.request.ImpersonatedEmail != runtimeTarget || fake.request.RequestSource.Kind != "agent-session" || fake.request.RequestSource.Label != "codex:agentic/ro" {
		t.Fatalf("host request = %+v", fake.request)
	}
}
