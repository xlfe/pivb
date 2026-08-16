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
	"github.com/xlfe/pivb/internal/attachment"
	"github.com/xlfe/pivb/internal/core"
	"github.com/xlfe/pivb/internal/jsonhttp"
	"github.com/xlfe/pivb/internal/pivsigner"
	"github.com/xlfe/pivb/internal/procinfo"
	"github.com/xlfe/pivb/internal/tokenapi"
	"github.com/xlfe/pivb/internal/uds"
)

// maxRequestBody bounds the fixed-shape signing request.
const maxRequestBody = 4 << 10

// peerChainDepth is how far back a logged mint names its caller's ancestry:
// far enough to reach the shell or agent behind a wrapper, short enough to
// stay one readable journal attribute.
const peerChainDepth = 5

// Re-export the stable protocol types for compatibility with existing clients.
const (
	CodeLocked           = tokenapi.CodeLocked
	CodeConfig           = tokenapi.CodeConfig
	CodePIN              = tokenapi.CodePIN
	CodeSign             = tokenapi.CodeSign
	CodeUnavailable      = tokenapi.CodeUnavailable
	CodeRouteRequired    = tokenapi.CodeRouteRequired
	CodeEnv              = tokenapi.CodeEnv
	CodeInternal         = tokenapi.CodeInternal
	CodeWindowNotAllowed = tokenapi.CodeWindowNotAllowed
	CodeCardFree         = tokenapi.CodeCardFree
)

// SubjectTokenRequest is the fixed request shape. Every field is validated
// against daemon configuration; the request selects among configured values
// and can introduce nothing new.
type SubjectTokenRequest struct {
	Alias                   string              `json:"alias"`
	ExternalAccountAudience string              `json:"external_account_audience"`
	ImpersonatedEmail       string              `json:"impersonated_email"`
	RequestSource           *agentsource.Source `json:"request_source,omitempty"`
	// RouteSocket is accepted only on the trusted-host wif.sock. The fixed
	// agent-session relay injects it; the sandbox request has no such field.
	RouteSocket   string `json:"route_socket,omitempty"`
	RouteRequired bool   `json:"route_required,omitempty"`
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
	attachmentContext := attachment.LocalAllowed()
	if req.RouteRequired {
		if err := attachment.ValidateRoute(req.RouteSocket); err != nil {
			writeError(w, http.StatusBadRequest, err.Error(), CodeRouteRequired, "recreate the managed pane or agent session")
			return
		}
		attachmentContext = attachment.RouteRequired(attachment.ProtocolEnvironment, req.RouteSocket)
	} else if req.RouteSocket != "" {
		writeError(w, http.StatusBadRequest, "route_socket requires route_required", CodeRouteRequired, "use the complete managed attachment protocol")
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
		Attachment:              attachmentContext,
		RouteSocket:             req.RouteSocket,
	})
	if err != nil {
		a.writeCoreError(w, r, req.Alias, source, err)
		return
	}
	source, _, _ = agentsource.Validate(source, req.Alias)
	// Log signing metadata only; the token itself is never logged or cached.
	attrs := []any{"alias", req.Alias, "target", req.ImpersonatedEmail,
		"source_kind", source.Kind, "attachment_mode", attachmentContext.Mode,
		"attachment_protocol", attachmentContext.Protocol, "route_kind", routeKind(attachmentContext),
		"serial", result.Serial, "key_id", result.KeyID, "expires_at", result.ExpiresAt,
		"reused", result.Reused}
	if source.Kind == agentsource.KindAgentSession {
		attrs = append(attrs, "source_label", source.Label, "session_id", source.SessionID)
	}
	a.logger().Info("minted WIF subject token", append(attrs, peerAttrs(r.Context())...)...)
	jsonhttp.Write(w, http.StatusOK, SubjectTokenResponse{IDToken: result.IDToken, ExpirationTime: result.ExpiresAt.Unix()})
}

func (a *API) writeCoreError(w http.ResponseWriter, r *http.Request, alias string, source agentsource.Source, err error) {
	var unknownAlias *core.UnknownAliasError
	var mismatch *core.RequestMismatchError
	var invalidSource *core.RequestSourceError
	var windowErr *core.WindowNotAllowedError
	var policyErr *attachment.PolicyError
	var pinErr *pivsigner.PINError
	var cardFreeErr *pivsigner.CardFreeError
	var upstreamErr *tokenapi.APIError
	peer := peerAttrs(r.Context())
	attrs := []any{"alias", alias}
	if normalized, _, sourceErr := agentsource.Validate(source, alias); sourceErr == nil {
		attrs = append(attrs, "source_kind", normalized.Kind)
		if normalized.Kind == agentsource.KindAgentSession {
			attrs = append(attrs, "source_label", normalized.Label, "session_id", normalized.SessionID)
		}
	}
	attrs = append(attrs, peer...)
	switch {
	case errors.As(err, &policyErr):
		a.logger().Warn("subject-token request violates attachment policy", append(attrs, "error", policyErr.Message)...)
		writeError(w, http.StatusForbidden, policyErr.Message, CodeRouteRequired, "recreate the managed pane or agent session")
	case errors.As(err, &upstreamErr):
		logAttrs := append(attrs, "code", upstreamErr.Code, "error", upstreamErr.Message)
		if upstreamErr.SecurityRelevant {
			a.logger().Error("forwarded subject-token response failed a security check", logAttrs...)
		} else {
			a.logger().Warn("forwarded subject-token request failed", logAttrs...)
		}
		status := upstreamErr.Status
		if status == 0 {
			status = http.StatusBadGateway
		}
		writeError(w, status, upstreamErr.Message, upstreamErr.Code, upstreamErr.Remedy)
	case errors.Is(err, core.ErrLocked):
		a.logger().Warn("subject-token request while locked", attrs...)
		writeError(w, http.StatusConflict, err.Error(), CodeLocked, "run `pivb unlock` on the trusted host")
	case errors.As(err, &invalidSource):
		a.logger().Warn("subject-token request has invalid source context", append([]any{"alias", alias, "error", err}, peer...)...)
		writeError(w, http.StatusBadRequest, err.Error(), CodeConfig, "send a valid trusted-host request source")
	case errors.As(err, &unknownAlias):
		a.logger().Warn("subject-token request for unknown alias", attrs...)
		writeError(w, http.StatusBadRequest, err.Error(), CodeConfig, "choose an alias defined in the pivb config")
	case errors.As(err, &mismatch):
		a.logger().Warn("subject-token request mismatched configuration", append(attrs, "field", mismatch.Field)...)
		writeError(w, http.StatusForbidden, err.Error(), CodeConfig, "regenerate the credential file with `pivb wif credentials`")
	case errors.As(err, &windowErr):
		a.logger().Warn("subject-token request asked for a window this provider does not grant",
			append(attrs, "requested_window_s", windowErr.Requested)...)
		writeError(w, http.StatusForbidden, err.Error(), CodeWindowNotAllowed, core.WindowNotAllowedRemedy)
	case errors.As(err, &cardFreeErr):
		// A routing mistake, not contention: a local-allowed mint reached a
		// daemon whose card is on another host.
		a.logger().Warn("subject-token request needs the local card on a card-free origin", attrs...)
		remedy := cardFreeErr.Remedy
		if remedy == "" {
			remedy = pivsigner.CardFreeRemedy
		}
		writeError(w, http.StatusForbidden, err.Error(), CodeCardFree, remedy)
	case errors.As(err, &pinErr):
		a.logger().Warn("subject-token PIN failure", append(attrs, "error", err)...)
		remedy := pinErr.Remedy
		if remedy == "" {
			remedy = "run `pivb unlock` with the inserted YubiKey and retry"
		}
		writeError(w, http.StatusConflict, err.Error(), CodePIN, remedy)
	default:
		if hardwareErr, ok := pivsigner.MapAPIError(err); ok {
			a.logger().Warn("subject-token smart-card contention", append(attrs, "error", err)...)
			writeError(w, hardwareErr.Status, hardwareErr.Message, hardwareErr.Code, hardwareErr.Remedy)
			return
		}
		a.logger().Warn("subject-token signing failed", append(attrs, "error", err)...)
		writeError(w, http.StatusBadGateway, err.Error(), CodeSign, "touch the YubiKey when prompted, check the daemon journal, then retry")
	}
}

// peerAttrs names the process behind a request, and the ancestry behind that
// process, so a journal line answers "who asked" and not only "what was
// signed". It is called only after the mint outcome is decided: reading /proc
// can therefore never delay, block, or fail a signature. The chain is one
// attribute value because comm is process-controlled text and the log handler
// must stay free to quote it.
func peerAttrs(ctx context.Context) []any {
	info, ok := uds.PeerFromContext(ctx)
	if !ok {
		return nil
	}
	return []any{"peer_pid", info.PID, "peer_chain", procinfo.FormatChain(procinfo.Chain("", info.PID, peerChainDepth))}
}

func routeKind(ctx attachment.Context) string {
	if ctx.RouteRequired() {
		return "zka-workspace"
	}
	return "local"
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
