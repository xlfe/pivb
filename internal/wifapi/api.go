// Package wifapi implements the narrow WIF signing API on the dedicated
// signing socket. It exposes exactly one operation: mint the configured OIDC
// subject token for one alias. It accepts no raw bytes, digests, scopes,
// custom claims, custom audiences, or arbitrary service-account addresses,
// and its responses contain only the subject token and its expiry.
package wifapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"

	"github.com/xlfe/pivb/internal/core"
	"github.com/xlfe/pivb/internal/pivsigner"
)

// maxRequestBody bounds the fixed-shape signing request.
const maxRequestBody = 4 << 10

// Stable machine-readable error codes surfaced through the executable
// protocol.
const (
	CodeLocked      = "PIVB_LOCKED"
	CodeConfig      = "PIVB_CONFIG"
	CodePIN         = "PIVB_PIN"
	CodeSign        = "PIVB_SIGN"
	CodeUnavailable = "PIVB_UNAVAILABLE"
	CodeEnv         = "PIVB_ENV"
	CodeInternal    = "PIVB_INTERNAL"
)

// SubjectTokenRequest is the fixed request shape. Every field is validated
// against daemon configuration; the request selects among configured values
// and can introduce nothing new.
type SubjectTokenRequest struct {
	Alias                   string `json:"alias"`
	ExternalAccountAudience string `json:"external_account_audience"`
	ImpersonatedEmail       string `json:"impersonated_email"`
}

// SubjectTokenResponse carries the subject token and its Unix expiry. No
// other credential state exists to return.
type SubjectTokenResponse struct {
	IDToken        string `json:"id_token"`
	ExpirationTime int64  `json:"expiration_time"`
}

type errorResponse struct {
	Error  string `json:"error"`
	Code   string `json:"code"`
	Remedy string `json:"remedy,omitempty"`
}

// Core is the daemon seam.
type Core interface {
	SubjectToken(ctx context.Context, req core.SubjectTokenRequest) (core.SubjectTokenResult, error)
}

type API struct {
	Core   Core
	Logger *slog.Logger
}

func (a *API) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/subject-token", a.subjectToken)
	return mux
}

func (a *API) subjectToken(w http.ResponseWriter, r *http.Request) {
	var req SubjectTokenRequest
	if err := decode(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error(), CodeConfig, "send the fixed subject-token request shape")
		return
	}
	result, err := a.Core.SubjectToken(r.Context(), core.SubjectTokenRequest{
		Alias:                   req.Alias,
		ExternalAccountAudience: req.ExternalAccountAudience,
		ImpersonatedEmail:       req.ImpersonatedEmail,
	})
	if err != nil {
		a.writeCoreError(w, req.Alias, err)
		return
	}
	// Log signing metadata only; the token itself is never logged or cached.
	a.logger().Info("minted WIF subject token",
		"alias", req.Alias, "serial", result.Serial, "key_id", result.KeyID, "expires_at", result.ExpiresAt)
	writeJSON(w, http.StatusOK, SubjectTokenResponse{IDToken: result.IDToken, ExpirationTime: result.ExpiresAt.Unix()})
}

func (a *API) writeCoreError(w http.ResponseWriter, alias string, err error) {
	var unknownAlias *core.UnknownAliasError
	var mismatch *core.RequestMismatchError
	var pinErr *pivsigner.PINError
	switch {
	case errors.Is(err, core.ErrLocked):
		a.logger().Warn("subject-token request while locked", "alias", alias)
		writeError(w, http.StatusConflict, err.Error(), CodeLocked, "run `pivb unlock` on the trusted host")
	case errors.As(err, &unknownAlias):
		a.logger().Warn("subject-token request for unknown alias", "alias", alias)
		writeError(w, http.StatusBadRequest, err.Error(), CodeConfig, "choose an alias defined in the pivb config")
	case errors.As(err, &mismatch):
		a.logger().Warn("subject-token request mismatched configuration", "alias", alias, "field", mismatch.Field)
		writeError(w, http.StatusForbidden, err.Error(), CodeConfig, "regenerate the credential file with `pivb wif credentials`")
	case errors.As(err, &pinErr):
		a.logger().Warn("subject-token PIN failure", "alias", alias, "error", err)
		remedy := pinErr.Remedy
		if remedy == "" {
			remedy = "run `pivb unlock` with the inserted YubiKey and retry"
		}
		writeError(w, http.StatusConflict, err.Error(), CodePIN, remedy)
	default:
		a.logger().Warn("subject-token signing failed", "alias", alias, "error", err)
		writeError(w, http.StatusBadGateway, err.Error(), CodeSign, "touch the YubiKey when prompted, check the daemon journal, then retry")
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

func writeError(w http.ResponseWriter, status int, message, code, remedy string) {
	writeJSON(w, status, errorResponse{Error: message, Code: code, Remedy: remedy})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func (a *API) logger() *slog.Logger {
	if a.Logger != nil {
		return a.Logger
	}
	return slog.Default()
}
