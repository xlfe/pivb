package uds

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// serveHandle tracks a Serve goroutine so every test can stop it exactly once
// and still assert on the value Serve returned.
type serveHandle struct {
	cancel context.CancelFunc
	errCh  <-chan error
	once   sync.Once
	err    error
}

func startServe(t *testing.T, socket string, handler http.Handler) *serveHandle {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() { errCh <- Serve(ctx, socket, handler) }()
	h := &serveHandle{cancel: cancel, errCh: errCh}
	t.Cleanup(func() { h.stop(t) })
	return h
}

func (h *serveHandle) stop(t *testing.T) error {
	t.Helper()
	h.once.Do(func() {
		h.cancel()
		select {
		case h.err = <-h.errCh:
		case <-time.After(5 * time.Second):
			h.err = errors.New("Serve did not return after context cancellation")
		}
	})
	return h.err
}

// waitReady polls until the socket accepts a connection, so tests never race
// the listener.
func waitReady(t *testing.T, socket string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("unix", socket, 100*time.Millisecond)
		if err == nil {
			conn.Close()
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("socket %q never became ready", socket)
}

func okHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "pong")
	})
}

func TestServeEndToEnd(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "run")
	// Deliberately loose: Serve must tighten the directory to 0700 itself.
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatalf("create runtime dir: %v", err)
	}
	socket := filepath.Join(dir, "s.sock")

	handle := startServe(t, socket, okHandler())
	waitReady(t, socket)

	resp, err := NewHTTPClient(socket, 2*time.Second).Get("http://pivb/ping")
	if err != nil {
		t.Fatalf("same-UID request failed: %v", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200 (peer gate should admit the same UID); body %q", resp.StatusCode, body)
	}
	if string(body) != "pong" {
		t.Errorf("body = %q, want %q", body, "pong")
	}

	st, err := os.Lstat(socket)
	if err != nil {
		t.Fatalf("stat socket: %v", err)
	}
	if st.Mode()&os.ModeSocket == 0 {
		t.Errorf("socket path mode = %v, want a socket", st.Mode())
	}
	if got := st.Mode().Perm(); got != 0o600 {
		t.Errorf("socket permissions = %#o, want 0600", got)
	}
	dirSt, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("stat runtime dir: %v", err)
	}
	if got := dirSt.Mode().Perm(); got != 0o700 {
		t.Errorf("runtime dir permissions = %#o, want 0700", got)
	}

	if err := handle.stop(t); err != nil {
		t.Errorf("Serve after context cancellation = %v, want nil", err)
	}
	if _, err := os.Lstat(socket); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("socket still present after shutdown: err = %v, want ErrNotExist", err)
	}
}

func TestServeCreatesMissingRuntimeDir(t *testing.T) {
	socket := filepath.Join(t.TempDir(), "a", "b", "s.sock")
	startServe(t, socket, okHandler())
	waitReady(t, socket)

	st, err := os.Stat(filepath.Dir(socket))
	if err != nil {
		t.Fatalf("stat runtime dir: %v", err)
	}
	if got := st.Mode().Perm(); got != 0o700 {
		t.Errorf("created runtime dir permissions = %#o, want 0700", got)
	}
}

func TestServeFailsOnUnusableRuntimeDir(t *testing.T) {
	blocker := filepath.Join(t.TempDir(), "f")
	if err := os.WriteFile(blocker, nil, 0o600); err != nil {
		t.Fatalf("write blocking file: %v", err)
	}
	// A regular file where a parent directory belongs: MkdirAll must fail and
	// Serve must not fall through to listening.
	socket := filepath.Join(blocker, "run", "s.sock")

	err := Serve(context.Background(), socket, okHandler())
	if err == nil {
		t.Fatal("Serve = nil, want an error when the runtime directory cannot be created")
	}
	if !strings.Contains(err.Error(), "runtime socket directory") {
		t.Errorf("Serve error = %v, want it to mention the runtime socket directory", err)
	}
}

func TestServeRefusesNonSocketPath(t *testing.T) {
	socket := filepath.Join(t.TempDir(), "s.sock")
	if err := os.WriteFile(socket, []byte("precious"), 0o600); err != nil {
		t.Fatalf("write regular file: %v", err)
	}

	err := Serve(context.Background(), socket, okHandler())
	if err == nil {
		t.Fatal("Serve = nil, want an error for a regular file at the socket path")
	}
	if !strings.Contains(err.Error(), "non-socket") {
		t.Errorf("Serve error = %v, want it to mention %q", err, "non-socket")
	}
	// The refusal must be non-destructive.
	content, readErr := os.ReadFile(socket)
	if readErr != nil {
		t.Fatalf("regular file was removed: %v", readErr)
	}
	if string(content) != "precious" {
		t.Errorf("file content = %q, want it untouched", content)
	}
}

func TestServeReplacesStaleSocket(t *testing.T) {
	socket := filepath.Join(t.TempDir(), "s.sock")

	// Leave a socket file behind with nothing listening: SetUnlinkOnClose(false)
	// stops Go from tidying it up, which is what a killed daemon leaves.
	ln, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatalf("bind stale socket: %v", err)
	}
	ln.(*net.UnixListener).SetUnlinkOnClose(false)
	if err := ln.Close(); err != nil {
		t.Fatalf("close stale listener: %v", err)
	}
	stale, err := os.Lstat(socket)
	if err != nil {
		t.Fatalf("stale socket file missing, test premise broken: %v", err)
	}
	if stale.Mode()&os.ModeSocket == 0 {
		t.Fatalf("stale path mode = %v, want a socket", stale.Mode())
	}

	startServe(t, socket, okHandler())
	waitReady(t, socket)

	resp, err := NewHTTPClient(socket, 2*time.Second).Get("http://pivb/ping")
	if err != nil {
		t.Fatalf("request after stale-socket recovery: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
}

func TestServeRefusesActiveSocket(t *testing.T) {
	socket := filepath.Join(t.TempDir(), "s.sock")
	startServe(t, socket, okHandler())
	waitReady(t, socket)

	err := Serve(context.Background(), socket, okHandler())
	if err == nil {
		t.Fatal("second Serve = nil, want an error while the first still listens")
	}
	if !strings.Contains(err.Error(), "already in use") {
		t.Errorf("second Serve error = %v, want it to mention %q", err, "already in use")
	}

	// The loser must not have unlinked the winner's socket.
	resp, reqErr := NewHTTPClient(socket, 2*time.Second).Get("http://pivb/ping")
	if reqErr != nil {
		t.Fatalf("first server stopped answering after the second Serve failed: %v", reqErr)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
}

func TestRequirePeer(t *testing.T) {
	tests := []struct {
		name       string
		setContext func(*http.Request) *http.Request
		wantNext   bool
	}{
		{
			name:       "no peer value",
			setContext: func(r *http.Request) *http.Request { return r },
		},
		{
			name: "peer rejected",
			setContext: func(r *http.Request) *http.Request {
				return r.WithContext(context.WithValue(r.Context(), peerAllowedKey{}, false))
			},
		},
		{
			name: "wrong value type",
			setContext: func(r *http.Request) *http.Request {
				return r.WithContext(context.WithValue(r.Context(), peerAllowedKey{}, "true"))
			},
		},
		{
			name: "peer allowed",
			setContext: func(r *http.Request) *http.Request {
				return r.WithContext(context.WithValue(r.Context(), peerAllowedKey{}, true))
			},
			wantNext: true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			reached := false
			handler := requirePeer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				reached = true
				w.WriteHeader(http.StatusTeapot)
			}))
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, tc.setContext(httptest.NewRequest(http.MethodGet, "/v1/status", nil)))

			if reached != tc.wantNext {
				t.Fatalf("next handler reached = %v, want %v", reached, tc.wantNext)
			}
			if tc.wantNext {
				if rec.Code != http.StatusTeapot {
					t.Errorf("status = %d, want %d from the wrapped handler", rec.Code, http.StatusTeapot)
				}
				return
			}
			if rec.Code != http.StatusForbidden {
				t.Errorf("status = %d, want 403", rec.Code)
			}
			if got := rec.Header().Get("Content-Type"); got != "application/json" {
				t.Errorf("Content-Type = %q, want application/json", got)
			}
			var body map[string]string
			if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
				t.Fatalf("decode body %q: %v", rec.Body.String(), err)
			}
			if body["code"] != "PIVB_PEER" {
				t.Errorf("code = %q, want PIVB_PEER", body["code"])
			}
			if body["error"] == "" {
				t.Error("error field is empty")
			}
			if body["remedy"] == "" {
				t.Error("remedy field is empty")
			}
		})
	}
}

func TestPeerUIDMatches(t *testing.T) {
	t.Run("non-unix conn", func(t *testing.T) {
		client, server := net.Pipe()
		defer client.Close()
		defer server.Close()
		if peerUIDMatches(client, uint32(os.Getuid())) {
			t.Error("peerUIDMatches(net.Pipe conn) = true, want false: SO_PEERCRED is unavailable there")
		}
	})

	t.Run("unix conn", func(t *testing.T) {
		socket := filepath.Join(t.TempDir(), "s.sock")
		ln, err := net.Listen("unix", socket)
		if err != nil {
			t.Fatalf("listen: %v", err)
		}
		defer ln.Close()

		accepted := make(chan net.Conn, 1)
		go func() {
			conn, acceptErr := ln.Accept()
			if acceptErr != nil {
				accepted <- nil
				return
			}
			accepted <- conn
		}()
		dialed, err := net.Dial("unix", socket)
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		defer dialed.Close()
		conn := <-accepted
		if conn == nil {
			t.Fatal("accept failed")
		}
		defer conn.Close()

		uid := uint32(os.Getuid())
		if !peerUIDMatches(conn, uid) {
			t.Errorf("peerUIDMatches(conn, %d) = false, want true for our own connection", uid)
		}
		if peerUIDMatches(conn, uid+1) {
			t.Errorf("peerUIDMatches(conn, %d) = true, want false for a different UID", uid+1)
		}
	})
}

func TestNewHTTPClientTimesOut(t *testing.T) {
	socket := filepath.Join(t.TempDir(), "s.sock")
	release := make(chan struct{})
	startServe(t, socket, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		<-release
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(func() { close(release) })
	waitReady(t, socket)

	if _, err := NewHTTPClient(socket, 100*time.Millisecond).Get("http://pivb/slow"); err == nil {
		t.Fatal("request = nil error, want a client timeout")
	}
}

func TestNewHTTPClientMissingSocket(t *testing.T) {
	socket := filepath.Join(t.TempDir(), "s.sock")
	_, err := NewHTTPClient(socket, time.Second).Get("http://pivb/ping")
	if err == nil {
		t.Fatal("request to a nonexistent socket = nil error, want a dial failure")
	}
}
