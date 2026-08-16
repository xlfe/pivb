// Package agentapi implements the control API on the pivb control socket:
// health, status, unlock, and lock. It deliberately contains no route that
// returns credential material. The WIF subject-token operation lives on a
// separate socket in package wifapi.
package agentapi

import (
	"context"
	"errors"
	"log/slog"
	"net/http"

	"github.com/xlfe/pivb/internal/core"
	"github.com/xlfe/pivb/internal/jsonhttp"
	"github.com/xlfe/pivb/internal/pivsigner"
	"github.com/xlfe/pivb/internal/tokenapi"
	"github.com/xlfe/pivb/internal/uds"
)

const maxRequestBody = 16 << 10

type API struct {
	Core   *core.Core
	Logger *slog.Logger
}

type errorResponse struct {
	Error  string `json:"error"`
	Code   string `json:"code,omitempty"`
	Remedy string `json:"remedy,omitempty"`
}

func (a *API) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/health", func(w http.ResponseWriter, _ *http.Request) {
		jsonhttp.Write(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	mux.HandleFunc("GET /v1/status", func(w http.ResponseWriter, _ *http.Request) { jsonhttp.Write(w, http.StatusOK, a.Core.Status()) })
	mux.HandleFunc("POST /v1/unlock", a.unlock)
	mux.HandleFunc("POST /v1/lock", a.lock)
	return mux
}

func (a *API) unlock(w http.ResponseWriter, r *http.Request) {
	var req struct {
		PIN string `json:"pin"`
	}
	if err := jsonhttp.Decode(r, &req, maxRequestBody); err != nil {
		writeError(w, http.StatusBadRequest, err.Error(), "send JSON as {\"pin\":\"...\"}")
		return
	}
	retries, err := a.Core.Unlock(r.Context(), req.PIN)
	if err != nil {
		// The submitted PIN and the card's remaining attempts stay out of the
		// journal: the caller supplied the first and receives the second in
		// its own response, so writing either to disk adds risk and nothing
		// else.
		a.logger().Warn("unlock failed", append([]any{"error", err}, peerAttrs(r.Context())...)...)
		var pinErr *pivsigner.PINError
		if errors.As(err, &pinErr) {
			jsonhttp.Write(w, http.StatusForbidden, struct {
				Error   string `json:"error"`
				Code    string `json:"code"`
				Remedy  string `json:"remedy"`
				Retries int    `json:"retries"`
			}{err.Error(), tokenapi.CodePIN, "check the PIN; pivb will never spend the final retry", retries})
			return
		}
		if hardwareErr, ok := pivsigner.MapAPIError(err); ok {
			writeCodedError(w, hardwareErr.Status, hardwareErr.Message, hardwareErr.Code, hardwareErr.Remedy)
			return
		}
		writeError(w, http.StatusServiceUnavailable, err.Error(), "insert exactly one configured YubiKey and retry")
		return
	}
	// The serial comes from the cached state the unlock just wrote, so naming
	// the card in the journal still costs no card work.
	a.logger().Info("unlocked", append([]any{"serial", a.Core.Status().PINVerifiedSerial}, peerAttrs(r.Context())...)...)
	jsonhttp.Write(w, http.StatusOK, map[string]any{"unlocked": true, "retries": retries})
}

func (a *API) lock(w http.ResponseWriter, r *http.Request) {
	a.Core.Lock()
	a.logger().Info("locked; cached PIN and signing metadata discarded", peerAttrs(r.Context())...)
	jsonhttp.Write(w, http.StatusOK, map[string]bool{"locked": true})
}

func writeError(w http.ResponseWriter, status int, message, remedy string) {
	jsonhttp.Write(w, status, errorResponse{Error: message, Remedy: remedy})
}

func writeCodedError(w http.ResponseWriter, status int, message, code, remedy string) {
	jsonhttp.Write(w, status, errorResponse{Error: message, Code: code, Remedy: remedy})
}

// peerAttrs attributes a control-socket request to the process that made it.
// The peer gate has already proven that process shares the daemon's UID; this
// only records which one of them asked.
func peerAttrs(ctx context.Context) []any {
	info, ok := uds.PeerFromContext(ctx)
	if !ok {
		return nil
	}
	return []any{"peer_pid", info.PID}
}

func (a *API) logger() *slog.Logger {
	if a.Logger != nil {
		return a.Logger
	}
	return slog.Default()
}
