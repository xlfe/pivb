// Package uds provides the shared Unix-domain-socket HTTP transport for PIVB:
// fail-closed socket creation under a 0700 runtime directory, 0600 socket
// modes, and mandatory SO_PEERCRED same-UID enforcement on every request. The
// peer check cannot distinguish two processes with the same host UID; mount
// isolation hides ordinary sockets and exposes only an explicitly delegated
// fixed-alias session socket to an agent sandbox.
package uds

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"time"
)

// MaxResponseBody bounds client-side response reads.
const MaxResponseBody = 64 << 10

type peerKey struct{}

// peerInfo is one connection's SO_PEERCRED identity. The UID and PID are
// recorded even when the UID does not match, so a refusal can name the process
// that caused it; a connection whose credentials cannot be read at all keeps
// the zero value, which is never allowed.
type peerInfo struct {
	allowed bool
	uid     uint32
	pid     int32
}

// PeerInfo identifies the process on the other end of a served connection. It
// is attribution for logs, not an authorization input: the same-UID gate has
// already run, two processes sharing the daemon's UID are indistinguishable to
// it, and a PID may be reused once its process exits.
type PeerInfo struct {
	UID uint32
	PID int32
}

// PeerFromContext returns the connection's SO_PEERCRED identity when the
// request was served over a uds listener; ok is false otherwise.
func PeerFromContext(ctx context.Context) (PeerInfo, bool) {
	info, ok := ctx.Value(peerKey{}).(peerInfo)
	if !ok {
		return PeerInfo{}, false
	}
	return PeerInfo{UID: info.uid, PID: info.pid}, true
}

// Option adjusts how a listener is served. The peer gate itself is not
// optional and no Option can disable it.
type Option func(*serveConfig)

type serveConfig struct{ logger *slog.Logger }

// WithLogger routes the transport's own records — today, refused peers — to l
// instead of slog.Default().
func WithLogger(l *slog.Logger) Option {
	return func(cfg *serveConfig) { cfg.logger = l }
}

func newServeConfig(opts []Option) serveConfig {
	var cfg serveConfig
	for _, opt := range opts {
		opt(&cfg)
	}
	return cfg
}

// Listener is a prepared Unix listener whose Close removes the socket path.
// Preparing it separately lets supervisors make the socket ready before they
// launch a child without duplicating the peer-credential gate.
type Listener struct {
	net.Listener
	socket string
	once   sync.Once
}

func (l *Listener) Close() error {
	var err error
	l.once.Do(func() {
		err = l.Listener.Close()
		if removeErr := os.Remove(l.socket); removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) && err == nil {
			err = removeErr
		}
	})
	return err
}

// Serve listens on socket and serves handler until ctx is cancelled. Every
// request is rejected with 403 unless the connecting peer has the daemon's
// real UID. The peer gate is applied here so no caller can forget it.
func Serve(ctx context.Context, socket string, handler http.Handler, opts ...Option) error {
	ln, err := Listen(socket)
	if err != nil {
		return err
	}
	return ServeListener(ctx, ln, handler, opts...)
}

// Listen prepares a private same-UID Unix listener synchronously.
func Listen(socket string) (*Listener, error) {
	if err := os.MkdirAll(filepath.Dir(socket), 0o700); err != nil {
		return nil, fmt.Errorf("create runtime socket directory: %w", err)
	}
	if err := os.Chmod(filepath.Dir(socket), 0o700); err != nil {
		return nil, fmt.Errorf("set runtime socket directory permissions: %w", err)
	}
	if st, err := os.Lstat(socket); err == nil {
		if st.Mode()&os.ModeSocket == 0 {
			return nil, fmt.Errorf("refusing to replace non-socket path %q", socket)
		}
		conn, dialErr := net.DialTimeout("unix", socket, 250*time.Millisecond)
		if dialErr == nil {
			_ = conn.Close()
			return nil, fmt.Errorf("socket %q is already in use", socket)
		}
		if errors.Is(dialErr, syscall.ECONNREFUSED) {
			if err := os.Remove(socket); err != nil {
				return nil, fmt.Errorf("remove stale socket: %w", err)
			}
		} else if !errors.Is(dialErr, os.ErrNotExist) {
			return nil, fmt.Errorf("probe existing socket: %w", dialErr)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("inspect socket path: %w", err)
	}
	ln, err := net.Listen("unix", socket)
	if err != nil {
		return nil, fmt.Errorf("listen on socket %q: %w", socket, err)
	}
	if err := os.Chmod(socket, 0o600); err != nil {
		ln.Close()
		os.Remove(socket)
		return nil, fmt.Errorf("set socket permissions: %w", err)
	}
	return &Listener{Listener: ln, socket: socket}, nil
}

// ServeListener applies the mandatory same-UID gate and serves until ctx is
// cancelled. Existing request contexts retain net/http's normal lifecycle
// during graceful shutdown.
func ServeListener(ctx context.Context, ln *Listener, handler http.Handler, opts ...Option) error {
	return serveListener(ctx, ln, handler, false, opts)
}

// ServeListenerCancelRequests is the agent-session variant: request contexts
// derive from ctx, so ending a delegation immediately cancels any in-flight
// upstream mint. The main daemon deliberately uses ServeListener instead, so a
// daemon shutdown retains its established graceful mid-touch behavior.
func ServeListenerCancelRequests(ctx context.Context, ln *Listener, handler http.Handler, opts ...Option) error {
	return serveListener(ctx, ln, handler, true, opts)
}

func serveListener(ctx context.Context, ln *Listener, handler http.Handler, cancelRequests bool, opts []Option) error {
	defer ln.Close()
	uid := uint32(os.Getuid())
	cfg := newServeConfig(opts)
	server := &http.Server{
		Handler:           requirePeer(handler, cfg.logger),
		ReadHeaderTimeout: 5 * time.Second,
		ConnContext: func(ctx context.Context, conn net.Conn) context.Context {
			return context.WithValue(ctx, peerKey{}, peerCredentials(conn, uid))
		},
	}
	if cancelRequests {
		server.BaseContext = func(net.Listener) context.Context { return ctx }
	}
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		server.Shutdown(shutdownCtx)
	}()
	err := server.Serve(ln)
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

func requirePeer(next http.Handler, logger *slog.Logger) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		info, _ := r.Context().Value(peerKey{}).(peerInfo)
		if !info.allowed {
			// A refusal is the one thing this layer records itself: the caller
			// only sees a 403, so the peer it names exists nowhere else.
			peerLogger(logger).Warn("refused socket peer",
				"peer_uid", info.uid, "peer_pid", info.pid, "method", r.Method, "path", r.URL.Path)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			_ = json.NewEncoder(w).Encode(map[string]string{
				"error":  "socket peer UID does not match daemon UID",
				"code":   "PIVB_PEER",
				"remedy": "run pivb as the same user as the daemon",
			})
			return
		}
		next.ServeHTTP(w, r)
	})
}

// peerCredentials reads SO_PEERCRED once per connection. A peer whose
// credentials the kernel will not report is refused with no identity at all.
func peerCredentials(conn net.Conn, want uint32) peerInfo {
	uc, ok := conn.(*net.UnixConn)
	if !ok {
		return peerInfo{}
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return peerInfo{}
	}
	var cred *syscall.Ucred
	var sockErr error
	if err := raw.Control(func(fd uintptr) {
		cred, sockErr = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	}); err != nil || sockErr != nil || cred == nil {
		return peerInfo{}
	}
	return peerInfo{allowed: cred.Uid == want, uid: cred.Uid, pid: cred.Pid}
}

func peerLogger(l *slog.Logger) *slog.Logger {
	if l != nil {
		return l
	}
	return slog.Default()
}

// NewHTTPClient returns an HTTP client that dials the given Unix socket.
func NewHTTPClient(socket string, timeout time.Duration) *http.Client {
	transport := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", socket)
		},
	}
	return &http.Client{Transport: transport, Timeout: timeout}
}
