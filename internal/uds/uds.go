// Package uds provides the shared Unix-domain-socket HTTP transport for the
// pivb control and WIF signing APIs: fail-closed socket creation under a 0700
// runtime directory, 0600 socket modes, and mandatory SO_PEERCRED same-UID
// enforcement on every request. The peer check cannot distinguish two
// processes with the same host UID; mount isolation keeps agent sandboxes
// away from these sockets entirely.
package uds

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"syscall"
	"time"
)

// MaxResponseBody bounds client-side response reads.
const MaxResponseBody = 64 << 10

type peerAllowedKey struct{}

// Serve listens on socket and serves handler until ctx is cancelled. Every
// request is rejected with 403 unless the connecting peer has the daemon's
// real UID. The peer gate is applied here so no caller can forget it.
func Serve(ctx context.Context, socket string, handler http.Handler) error {
	if err := os.MkdirAll(filepath.Dir(socket), 0o700); err != nil {
		return fmt.Errorf("create runtime socket directory: %w", err)
	}
	if err := os.Chmod(filepath.Dir(socket), 0o700); err != nil {
		return fmt.Errorf("set runtime socket directory permissions: %w", err)
	}
	if st, err := os.Lstat(socket); err == nil {
		if st.Mode()&os.ModeSocket == 0 {
			return fmt.Errorf("refusing to replace non-socket path %q", socket)
		}
		conn, dialErr := net.DialTimeout("unix", socket, 250*time.Millisecond)
		if dialErr == nil {
			_ = conn.Close()
			return fmt.Errorf("socket %q is already in use", socket)
		}
		if errors.Is(dialErr, syscall.ECONNREFUSED) {
			if err := os.Remove(socket); err != nil {
				return fmt.Errorf("remove stale socket: %w", err)
			}
		} else if !errors.Is(dialErr, os.ErrNotExist) {
			return fmt.Errorf("probe existing socket: %w", dialErr)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect socket path: %w", err)
	}
	ln, err := net.Listen("unix", socket)
	if err != nil {
		return fmt.Errorf("listen on socket %q: %w", socket, err)
	}
	defer func() {
		ln.Close()
		os.Remove(socket)
	}()
	if err := os.Chmod(socket, 0o600); err != nil {
		return fmt.Errorf("set socket permissions: %w", err)
	}
	uid := uint32(os.Getuid())
	server := &http.Server{
		Handler:           requirePeer(handler),
		ReadHeaderTimeout: 5 * time.Second,
		ConnContext: func(ctx context.Context, conn net.Conn) context.Context {
			return context.WithValue(ctx, peerAllowedKey{}, peerUIDMatches(conn, uid))
		},
	}
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		server.Shutdown(shutdownCtx)
	}()
	err = server.Serve(ln)
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

func requirePeer(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		allowed, _ := r.Context().Value(peerAllowedKey{}).(bool)
		if !allowed {
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

func peerUIDMatches(conn net.Conn, want uint32) bool {
	uc, ok := conn.(*net.UnixConn)
	if !ok {
		return false
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return false
	}
	var cred *syscall.Ucred
	var sockErr error
	if err := raw.Control(func(fd uintptr) {
		cred, sockErr = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	}); err != nil || sockErr != nil || cred == nil {
		return false
	}
	return cred.Uid == want
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
