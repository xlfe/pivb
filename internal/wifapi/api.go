// Package wifapi implements the narrow WIF signing API on the dedicated
// signing socket. It exposes exactly one operation: mint the configured OIDC
// subject token for one alias. It accepts no raw bytes, digests, scopes,
// custom claims, custom audiences, or arbitrary service-account addresses,
// and its responses contain only the subject token and its expiry.
package wifapi

import (
	"context"
	"errors"
	"log/slog"
	"net/http"

	"github.com/xlfe/pivb/internal/agentsource"
	"github.com/xlfe/pivb/internal/core"
	"github.com/xlfe/pivb/internal/jsonhttp"
	"github.com/xlfe/pivb/internal/pivsigner"
	"github.com/xlfe/pivb/internal/tokenapi"
)

// maxRequestBody bounds the fixed-shape signing request.
const maxRequestBody = 4 << 10

// Re-export the stable protocol types for compatibility with existing clients.
const (
	CodeLocked      = tokenapi.CodeLocked
	CodeConfig      = tokenapi.CodeConfig
	CodePIN         = tokenapi.CodePIN
	CodeSign        = tokenapi.CodeSign
	CodeUnavailable = tokenapi.CodeUnavailable
	CodeEnv         = tokenapi.CodeEnv
	CodeInternal    = tokenapi.CodeInternal
)

// SubjectTokenRequest is the fixed request shape. Every field is validated
// against daemon configuration; the request selects among configured values
// and can introduce nothing new.
type SubjectTokenRequest struct {
	Alias                   string              `json:"alias"`
	ExternalAccountAudience string              `json:"external_account_audience"`
	ImpersonatedEmail       string              `json:"impersonated_email"`
	RequestSource           *agentsource.Source `json:"request_source,omitempty"`
}

type SubjectTokenResponse = tokenapi.SubjectTokenResponse
type errorResponse = tokenapi.ErrorResponse

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
	if err := jsonhttp.Decode(r, &req, maxRequestBody); err != nil {
		writeError(w, http.StatusBadRequest, err.Error(), CodeConfig, "send the fixed subject-token request shape")
		return
	}
	var source agentsource.Source
	if req.RequestSource != nil {
		source = *req.RequestSource
	}
	result, err := a.Core.SubjectToken(r.Context(), core.SubjectTokenRequest{
		Alias:                   req.Alias,
		ExternalAccountAudience: req.ExternalAccountAudience,
		ImpersonatedEmail:       req.ImpersonatedEmail,
		RequestSource:           source,
	})
	if err != nil {
		a.writeCoreError(w, req.Alias, source, err)
		return
	}
	source, _, _ = agentsource.Validate(source, req.Alias)
	// Log signing metadata only; the token itself is never logged or cached.
	attrs := []any{"alias", req.Alias, "target", req.ImpersonatedEmail,
		"source_kind", source.Kind, "serial", result.Serial, "key_id", result.KeyID, "expires_at", result.ExpiresAt}
	if source.Kind == agentsource.KindAgentSession {
		attrs = append(attrs, "source_label", source.Label, "session_id", source.SessionID)
	}
	a.logger().Info("minted WIF subject token", attrs...)
	jsonhttp.Write(w, http.StatusOK, SubjectTokenResponse{IDToken: result.IDToken, ExpirationTime: result.ExpiresAt.Unix()})
}

func (a *API) writeCoreError(w http.ResponseWriter, alias string, source agentsource.Source, err error) {
	var unknownAlias *core.UnknownAliasError
	var mismatch *core.RequestMismatchError
	var invalidSource *core.RequestSourceError
	var pinErr *pivsigner.PINError
	attrs := []any{"alias", alias}
	if normalized, _, sourceErr := agentsource.Validate(source, alias); sourceErr == nil {
		attrs = append(attrs, "source_kind", normalized.Kind)
		if normalized.Kind == agentsource.KindAgentSession {
			attrs = append(attrs, "source_label", normalized.Label, "session_id", normalized.SessionID)
		}
	}
	switch {
	case errors.Is(err, core.ErrLocked):
		a.logger().Warn("subject-token request while locked", attrs...)
		writeError(w, http.StatusConflict, err.Error(), CodeLocked, "run `pivb unlock` on the trusted host")
	case errors.As(err, &invalidSource):
		a.logger().Warn("subject-token request has invalid source context", "alias", alias, "error", err)
		writeError(w, http.StatusBadRequest, err.Error(), CodeConfig, "send a valid trusted-host request source")
	case errors.As(err, &unknownAlias):
		a.logger().Warn("subject-token request for unknown alias", attrs...)
		writeError(w, http.StatusBadRequest, err.Error(), CodeConfig, "choose an alias defined in the pivb config")
	case errors.As(err, &mismatch):
		a.logger().Warn("subject-token request mismatched configuration", append(attrs, "field", mismatch.Field)...)
		writeError(w, http.StatusForbidden, err.Error(), CodeConfig, "regenerate the credential file with `pivb wif credentials`")
	case errors.As(err, &pinErr):
		a.logger().Warn("subject-token PIN failure", append(attrs, "error", err)...)
		remedy := pinErr.Remedy
		if remedy == "" {
			remedy = "run `pivb unlock` with the inserted YubiKey and retry"
		}
		writeError(w, http.StatusConflict, err.Error(), CodePIN, remedy)
	default:
		a.logger().Warn("subject-token signing failed", append(attrs, "error", err)...)
		writeError(w, http.StatusBadGateway, err.Error(), CodeSign, "touch the YubiKey when prompted, check the daemon journal, then retry")
	}
}

func writeError(w http.ResponseWriter, status int, message, code, remedy string) {
	jsonhttp.Write(w, status, errorResponse{Error: message, Code: code, Remedy: remedy})
}

func (a *API) logger() *slog.Logger {
	if a.Logger != nil {
		return a.Logger
	}
	return slog.Default()
}
