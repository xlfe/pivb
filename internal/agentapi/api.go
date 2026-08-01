package agentapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"github.com/xlfe/pivb/internal/core"
	"github.com/xlfe/pivb/internal/pivsigner"
)

const maxRequestBody = 1 << 20

type API struct{ Core *core.Core }

type errorResponse struct {
	Error  string `json:"error"`
	Remedy string `json:"remedy,omitempty"`
}

func (a *API) Handler(requirePeer bool) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/health", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	mux.HandleFunc("GET /v1/status", func(w http.ResponseWriter, _ *http.Request) { writeJSON(w, http.StatusOK, a.Core.Status()) })
	mux.HandleFunc("POST /v1/unlock", a.unlock)
	mux.HandleFunc("POST /v1/lock", a.lock)
	mux.HandleFunc("POST /v1/use", a.use)
	mux.HandleFunc("POST /v1/renew", a.renew)
	mux.HandleFunc("GET /v1/token", a.token)
	mux.HandleFunc("GET /v1/identity", a.identity)
	if !requirePeer {
		return mux
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		allowed, _ := r.Context().Value(peerAllowedKey{}).(bool)
		if !allowed {
			writeError(w, http.StatusForbidden, "agent socket peer UID does not match daemon UID", "run pivb as the same user as the daemon")
			return
		}
		mux.ServeHTTP(w, r)
	})
}

func (a *API) unlock(w http.ResponseWriter, r *http.Request) {
	var req struct {
		PIN string `json:"pin"`
	}
	if err := decode(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error(), "send JSON as {\"pin\":\"...\"}")
		return
	}
	retries, err := a.Core.Unlock(r.Context(), req.PIN)
	if err != nil {
		var pinErr *pivsigner.PINError
		if errors.As(err, &pinErr) {
			writeJSON(w, http.StatusForbidden, struct {
				Error   string `json:"error"`
				Remedy  string `json:"remedy"`
				Retries int    `json:"retries"`
			}{err.Error(), "check the PIN; pivb will never spend the final retry", retries})
			return
		}
		writeError(w, http.StatusServiceUnavailable, err.Error(), "insert exactly one configured YubiKey and retry")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"unlocked": true, "retries": retries})
}

func (a *API) lock(w http.ResponseWriter, _ *http.Request) {
	a.Core.Lock()
	writeJSON(w, http.StatusOK, map[string]bool{"locked": true})
}

func (a *API) use(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Alias string `json:"alias"`
	}
	if err := decode(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error(), "send JSON as {\"alias\":\"ro\"}")
		return
	}
	t, err := a.Core.Use(r.Context(), req.Alias)
	if err != nil {
		a.writeCoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, t)
}

func (a *API) renew(w http.ResponseWriter, r *http.Request) {
	t, err := a.Core.Renew(r.Context())
	if err != nil {
		a.writeCoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, t)
}

func (a *API) token(w http.ResponseWriter, _ *http.Request) {
	t, err := a.Core.Token()
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, err.Error(), "run `pivb unlock` then `pivb use <alias>`, or `pivb renew`")
		return
	}
	writeJSON(w, http.StatusOK, t)
}

func (a *API) identity(w http.ResponseWriter, r *http.Request) {
	id, err := a.Core.Identity(r.Context(), r.URL.Query().Get("audience"))
	if err != nil {
		a.writeCoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, id)
}

func (a *API) writeCoreError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, core.ErrLocked):
		writeError(w, http.StatusConflict, err.Error(), "run `pivb unlock` before minting")
	case errors.Is(err, core.ErrAudience):
		writeError(w, http.StatusBadRequest, err.Error(), "add a non-empty audience query parameter")
	case func() bool { var e *core.UnknownAliasError; return errors.As(err, &e) }():
		writeError(w, http.StatusBadRequest, err.Error(), "choose an alias defined in the pivb config")
	default:
		writeError(w, http.StatusBadGateway, err.Error(), "check the daemon log, touch the YubiKey when prompted, then retry")
	}
}

func decode(r *http.Request, dst any) error {
	r.Body = http.MaxBytesReader(nil, r.Body, maxRequestBody)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return fmt.Errorf("invalid JSON body: %w", err)
	}
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		return errors.New("invalid JSON body: multiple values")
	}
	return nil
}

func writeError(w http.ResponseWriter, status int, message, remedy string) {
	writeJSON(w, status, errorResponse{Error: message, Remedy: remedy})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

type peerAllowedKey struct{}

func ServeUnix(ctx context.Context, socket string, handler http.Handler) error {
	if err := os.MkdirAll(filepath.Dir(socket), 0700); err != nil {
		return fmt.Errorf("create agent socket directory: %w", err)
	}
	if err := os.Chmod(filepath.Dir(socket), 0700); err != nil {
		return fmt.Errorf("set agent socket directory permissions: %w", err)
	}
	if st, err := os.Lstat(socket); err == nil {
		if st.Mode()&os.ModeSocket == 0 {
			return fmt.Errorf("refusing to replace non-socket path %q", socket)
		}
		conn, dialErr := net.DialTimeout("unix", socket, 250*time.Millisecond)
		if dialErr == nil {
			_ = conn.Close()
			return fmt.Errorf("agent socket %q is already in use", socket)
		}
		if errors.Is(dialErr, syscall.ECONNREFUSED) {
			if err := os.Remove(socket); err != nil {
				return fmt.Errorf("remove stale agent socket: %w", err)
			}
		} else if !errors.Is(dialErr, os.ErrNotExist) {
			return fmt.Errorf("probe existing agent socket: %w", dialErr)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect agent socket: %w", err)
	}
	ln, err := net.Listen("unix", socket)
	if err != nil {
		return fmt.Errorf("listen on agent socket: %w", err)
	}
	defer func() {
		ln.Close()
		os.Remove(socket)
	}()
	if err := os.Chmod(socket, 0600); err != nil {
		return fmt.Errorf("set agent socket permissions: %w", err)
	}
	uid := uint32(os.Getuid())
	server := &http.Server{
		Handler:           handler,
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
