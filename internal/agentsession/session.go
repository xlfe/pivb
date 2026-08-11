// Package agentsession owns the lifetime of one fixed-alias relay and the
// trusted outer sandbox launcher that receives it.
package agentsession

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/xlfe/pivb/internal/agentsource"
	"github.com/xlfe/pivb/internal/attachment"
	"github.com/xlfe/pivb/internal/config"
	"github.com/xlfe/pivb/internal/sessionapi"
	"github.com/xlfe/pivb/internal/tokenapi"
	"github.com/xlfe/pivb/internal/uds"
	"github.com/xlfe/pivb/internal/wif"
	"github.com/xlfe/pivb/internal/wifapi"
)

const (
	DescriptorVersion = 2
	// One second above the 25-second forwarded-provider client, and two
	// seconds below the executable/helper clients.
	upstreamTimeout   = 26 * time.Second
	staleGrace        = 60 * time.Second
	relayFailureGrace = 5 * time.Second
	maxIDAttempts     = 16
)

const (
	EnvSessionDir = "PIVB_AGENT_SESSION_DIR"
	EnvSessionID  = "PIVB_AGENT_SESSION_ID"
)

type Descriptor struct {
	Version                 int    `json:"version"`
	SessionID               string `json:"session_id"`
	CreatedAt               string `json:"created_at"`
	Alias                   string `json:"alias"`
	Target                  string `json:"target"`
	ExternalAccountAudience string `json:"external_account_audience"`
	TokenLifetimeSeconds    int    `json:"token_lifetime_seconds"`
	SourceLabel             string `json:"source_label"`
	RouteKind               string `json:"route_kind,omitempty"`
	AttachmentMode          string `json:"attachment_mode"`
	AttachmentProtocol      int    `json:"attachment_protocol"`
}

type Options struct {
	Config      *config.Config
	Alias       string
	SourceLabel string
	WIFSocket   string
	Attachment  attachment.Context
	// RouteSocket is the legacy trusted-host spelling retained for callers
	// while the environment contract moves to Attachment.
	RouteSocket string
	RuntimeDir  string
	Command     []string
	Env         []string
	Stdin       io.Reader
	Stdout      io.Writer
	Stderr      io.Writer
	Signals     <-chan os.Signal
	Now         func() time.Time
	Random      io.Reader
	Logger      *slog.Logger
	ServeRelay  func(context.Context, *uds.Listener, http.Handler) error
	RemoveAll   func(string) error
	RelayGrace  time.Duration
}

// ChildExitError carries a supervised child's exact status back to the pivb
// entry point, which re-raises fatal signals only after session cleanup.
type ChildExitError struct {
	Code   int
	Signal syscall.Signal
}

func (e *ChildExitError) Error() string {
	if e.Signal != 0 {
		return fmt.Sprintf("child terminated by signal %s", e.Signal)
	}
	return fmt.Sprintf("child exited with status %d", e.Code)
}

type daemonUpstream struct {
	client     *wifapi.Client
	attachment attachment.Context
}

func (u daemonUpstream) SubjectToken(ctx context.Context, req sessionapi.UpstreamRequest) (tokenapi.SubjectTokenResponse, error) {
	source := req.RequestSource
	return u.client.SubjectToken(ctx, wifapi.SubjectTokenRequest{
		Alias:                   req.Alias,
		ExternalAccountAudience: req.ExternalAccountAudience,
		ImpersonatedEmail:       req.ImpersonatedEmail,
		RequestSource:           &source,
		RouteSocket:             u.attachment.RouteSocket,
		RouteRequired:           u.attachment.RouteRequired(),
	})
}

// Run creates one delegated session, supervises its child, and removes the
// delegated capability before returning the child's status.
func Run(opts Options) error {
	if opts.Config == nil {
		return errors.New("agent-session requires loaded configuration")
	}
	aliasCfg, ok := opts.Config.Aliases[opts.Alias]
	if !ok {
		return fmt.Errorf("alias %q is not configured", opts.Alias)
	}
	if opts.RouteSocket != "" && !filepath.IsAbs(opts.RouteSocket) {
		return errors.New("agent-session route socket must be absolute")
	}
	var err error
	opts.Attachment, err = attachment.WithExplicitRoute(opts.Attachment, opts.RouteSocket)
	if err != nil {
		return err
	}
	if err := opts.Attachment.Validate(); err != nil {
		return err
	}
	if opts.WIFSocket == "" {
		return errors.New("pivb signing socket location is unknown")
	}
	if len(opts.Command) == 0 || opts.Command[0] == "" {
		return errors.New("agent-session requires a child command after --")
	}
	if opts.RuntimeDir == "" || !filepath.IsAbs(opts.RuntimeDir) {
		return errors.New("XDG_RUNTIME_DIR must be a nonempty absolute path")
	}
	if _, _, err := agentsource.Validate(agentsource.Agent(opts.SourceLabel, strings.Repeat("0", agentsource.SessionIDLength)), opts.Alias); err != nil {
		return fmt.Errorf("invalid --source-label: %w", err)
	}

	now := time.Now
	if opts.Now != nil {
		now = opts.Now
	}
	random := rand.Reader
	if opts.Random != nil {
		random = opts.Random
	}
	stderr := opts.Stderr
	if stderr == nil {
		stderr = os.Stderr
	}
	logger := opts.Logger
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(stderr, nil))
	}

	root := filepath.Join(opts.RuntimeDir, "pivb-agent")
	if err := prepareRoot(root); err != nil {
		return err
	}
	sweepStale(root, now().UTC(), logger)
	sessionID, sessionDir, err := createSessionDir(root, random)
	if err != nil {
		return err
	}
	removeAll := os.RemoveAll
	if opts.RemoveAll != nil {
		removeAll = opts.RemoveAll
	}
	defer func() {
		if err := removeAll(sessionDir); err != nil {
			fmt.Fprintf(stderr, "pivb agent-session: remove session artifacts: %v\n", err)
		}
	}()

	provider := opts.Config.Provider()
	audience := provider.ExternalAccountAudience()
	credential, err := wif.AgentCredentialFile(wif.AgentCredentialFileSpec{
		Provider: provider, Target: aliasCfg.Target, LifetimeSeconds: aliasCfg.LifetimeS,
	})
	if err != nil {
		return err
	}
	if err := writePrivate(filepath.Join(sessionDir, "credential.json"), credential); err != nil {
		return fmt.Errorf("write agent credential: %w", err)
	}

	socket := filepath.Join(sessionDir, "session.sock")
	listener, err := uds.Listen(socket)
	if err != nil {
		return err
	}

	createdAt := now().UTC()
	descriptor := Descriptor{
		Version:                 DescriptorVersion,
		SessionID:               sessionID,
		CreatedAt:               createdAt.Format(time.RFC3339),
		Alias:                   opts.Alias,
		Target:                  aliasCfg.Target,
		ExternalAccountAudience: audience,
		TokenLifetimeSeconds:    aliasCfg.LifetimeS,
		SourceLabel:             opts.SourceLabel,
		AttachmentMode:          opts.Attachment.Mode,
		AttachmentProtocol:      opts.Attachment.Protocol,
	}
	if opts.Attachment.RouteRequired() {
		descriptor.RouteKind = "zka-workspace"
	}
	descriptorJSON, err := json.MarshalIndent(descriptor, "", "  ")
	if err != nil {
		listener.Close()
		return fmt.Errorf("marshal session descriptor: %w", err)
	}
	if err := writePrivate(filepath.Join(sessionDir, "session.json"), append(descriptorJSON, '\n')); err != nil {
		listener.Close()
		return fmt.Errorf("write session descriptor: %w", err)
	}

	source := agentsource.Agent(opts.SourceLabel, sessionID)
	upstreamClient := wifapi.NewClientWithTimeout(opts.WIFSocket, upstreamTimeout)
	defer upstreamClient.HTTP.CloseIdleConnections()
	api := &sessionapi.API{
		Session: sessionapi.Session{
			Alias: opts.Alias, Target: aliasCfg.Target,
			ExternalAccountAudience: audience, Source: source,
		},
		Upstream: daemonUpstream{client: upstreamClient, attachment: opts.Attachment},
	}
	relayCtx, cancelRelay := context.WithCancel(context.Background())
	relayDone := make(chan error, 1)
	serveRelay := uds.ServeListenerCancelRequests
	if opts.ServeRelay != nil {
		serveRelay = opts.ServeRelay
	}
	go func() {
		defer listener.Close()
		relayDone <- serveRelay(relayCtx, listener, api.Handler())
	}()

	cmd := exec.Command(opts.Command[0], opts.Command[1:]...)
	cmd.Stdin = opts.Stdin
	if cmd.Stdin == nil {
		cmd.Stdin = os.Stdin
	}
	cmd.Stdout = opts.Stdout
	if cmd.Stdout == nil {
		cmd.Stdout = os.Stdout
	}
	cmd.Stderr = stderr
	cmd.Env = sessionEnvironment(opts.Env, sessionDir, sessionID)
	signals := opts.Signals
	var ownedSignals chan os.Signal
	if signals == nil {
		ownedSignals = make(chan os.Signal, 4)
		signal.Notify(ownedSignals, os.Interrupt, syscall.SIGQUIT, syscall.SIGHUP, syscall.SIGTERM)
		defer signal.Stop(ownedSignals)
		signals = ownedSignals
	}
	if err := cmd.Start(); err != nil {
		cancelRelay()
		<-relayDone
		return fmt.Errorf("start agent-session child: %w", err)
	}
	childDone := make(chan error, 1)
	go func() { childDone <- cmd.Wait() }()
	relayGrace := relayFailureGrace
	if opts.RelayGrace > 0 {
		relayGrace = opts.RelayGrace
	}
	terminationRequests := make(map[os.Signal]int)
	for {
		select {
		case waitErr := <-childDone:
			cancelRelay()
			<-relayDone
			return childStatus(waitErr)
		case relayErr := <-relayDone:
			cancelRelay()
			waitErr := terminateChild(cmd, childDone, relayGrace)
			if relayErr == nil {
				relayErr = errors.New("relay stopped unexpectedly")
			}
			if waitErr != nil {
				logger.Warn("agent-session child stopped after relay failure", "error", waitErr)
			}
			return fmt.Errorf("agent-session relay failed: %w", relayErr)
		case sig := <-signals:
			switch sig {
			case os.Interrupt, syscall.SIGQUIT:
				// Terminal-generated signals already reach the child because it
				// remains in the supervisor's foreground process group. Catching
				// them here prevents cleanup before the TUI decides whether to exit.
			case syscall.SIGHUP, syscall.SIGTERM:
				terminationRequests[sig]++
				if terminationRequests[sig] == 1 {
					_ = cmd.Process.Signal(sig)
				} else {
					_ = cmd.Process.Kill()
				}
			}
		}
	}
}

func childStatus(err error) error {
	if err == nil {
		return nil
	}
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) {
		return fmt.Errorf("wait for agent-session child: %w", err)
	}
	status, ok := exitErr.Sys().(syscall.WaitStatus)
	if !ok {
		return &ChildExitError{Code: exitErr.ExitCode()}
	}
	if status.Signaled() {
		return &ChildExitError{Code: 128 + int(status.Signal()), Signal: status.Signal()}
	}
	return &ChildExitError{Code: status.ExitStatus()}
}

func terminateChild(cmd *exec.Cmd, childDone <-chan error, grace time.Duration) error {
	_ = cmd.Process.Signal(syscall.SIGTERM)
	timer := time.NewTimer(grace)
	defer timer.Stop()
	select {
	case err := <-childDone:
		return err
	case <-timer.C:
		_ = cmd.Process.Kill()
		return <-childDone
	}
}

func sessionEnvironment(env []string, sessionDir, sessionID string) []string {
	if env == nil {
		env = os.Environ()
	}
	out := make([]string, 0, len(env)+2)
	for _, item := range env {
		if strings.HasPrefix(item, EnvSessionDir+"=") || strings.HasPrefix(item, EnvSessionID+"=") {
			continue
		}
		out = append(out, item)
	}
	return append(out, EnvSessionDir+"="+sessionDir, EnvSessionID+"="+sessionID)
}

func prepareRoot(root string) error {
	if err := os.MkdirAll(root, 0o700); err != nil {
		return fmt.Errorf("create agent-session runtime root: %w", err)
	}
	info, err := os.Lstat(root)
	if err != nil {
		return fmt.Errorf("inspect agent-session runtime root: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return fmt.Errorf("agent-session runtime root %q must be a real directory", root)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Getuid()) {
		return fmt.Errorf("agent-session runtime root %q is not owned by the current user", root)
	}
	if err := os.Chmod(root, 0o700); err != nil {
		return fmt.Errorf("restrict agent-session runtime root: %w", err)
	}
	return nil
}

func createSessionDir(root string, random io.Reader) (string, string, error) {
	for range maxIDAttempts {
		b := make([]byte, agentsource.SessionIDLength/2)
		if _, err := io.ReadFull(random, b); err != nil {
			return "", "", fmt.Errorf("generate agent-session ID: %w", err)
		}
		id := hex.EncodeToString(b)
		dir := filepath.Join(root, id)
		if err := os.Mkdir(dir, 0o700); err == nil {
			if err := os.Chmod(dir, 0o700); err != nil {
				_ = os.Remove(dir)
				return "", "", fmt.Errorf("restrict agent-session directory: %w", err)
			}
			return id, dir, nil
		} else if !errors.Is(err, os.ErrExist) {
			return "", "", fmt.Errorf("create agent-session directory: %w", err)
		}
	}
	return "", "", errors.New("generate a unique agent-session ID: too many collisions")
}

func writePrivate(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	name := f.Name()
	ok := false
	defer func() {
		if !ok {
			_ = f.Close()
			_ = os.Remove(name)
		}
	}()
	if _, err := f.Write(data); err != nil {
		return err
	}
	if err := f.Chmod(0o600); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	ok = true
	return nil
}

func sweepStale(root string, now time.Time, logger *slog.Logger) {
	entries, err := os.ReadDir(root)
	if err != nil {
		logger.Warn("inspect stale agent sessions", "error", err)
		return
	}
	for _, entry := range entries {
		if err := agentsource.ValidateSessionID(entry.Name()); err != nil {
			continue
		}
		path := filepath.Join(root, entry.Name())
		info, err := os.Lstat(path)
		if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			continue
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || stat.Uid != uint32(os.Getuid()) || now.Sub(info.ModTime()) < staleGrace {
			continue
		}
		conn, dialErr := net.DialTimeout("unix", filepath.Join(path, "session.sock"), 100*time.Millisecond)
		if dialErr == nil {
			conn.Close()
			continue
		}
		if !errors.Is(dialErr, syscall.ECONNREFUSED) && !errors.Is(dialErr, os.ErrNotExist) {
			logger.Warn("probe stale agent session", "session_id", entry.Name(), "error", dialErr)
			continue
		}
		if err := os.RemoveAll(path); err != nil {
			logger.Warn("remove stale agent session", "session_id", entry.Name(), "error", err)
		}
	}
}
