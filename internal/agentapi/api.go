// Package agentapi implements the control API on the pivb control socket:
// health, status, unlock, and lock. It deliberately contains no route that
// returns credential material. The WIF subject-token operation lives on a
// separate socket in package wifapi.
package agentapi

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/xlfe/pivb/internal/core"
	"github.com/xlfe/pivb/internal/pivsigner"
)

const maxRequestBody = 16 << 10

type API struct{ Core *core.Core }

type errorResponse struct {
	Error  string `json:"error"`
	Remedy string `json:"remedy,omitempty"`
}

func (a *API) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/health", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	mux.HandleFunc("GET /v1/status", func(w http.ResponseWriter, _ *http.Request) { writeJSON(w, http.StatusOK, a.Core.Status()) })
	mux.HandleFunc("POST /v1/unlock", a.unlock)
	mux.HandleFunc("POST /v1/lock", a.lock)
	return mux
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
