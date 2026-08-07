// Package sessionapi implements the fixed-alias agent-session relay protocol.
// The request has no alias-selection field; the supervising host process
// injects all identity-bearing values before calling its trusted WIF upstream.
package sessionapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/xlfe/pivb/internal/agentsource"
	"github.com/xlfe/pivb/internal/jsonhttp"
	"github.com/xlfe/pivb/internal/tokenapi"
)

const maxRequestBody = 4 << 10

// Request is the helper-to-relay wire shape. ImpersonatedEmail is optional
// because some Google auth libraries omit that executable environment value.
type Request struct {
	ExternalAccountAudience string  `json:"external_account_audience"`
	ImpersonatedEmail       *string `json:"impersonated_email,omitempty"`
}

type optionalString struct {
	set   bool
	value string
}

func (s *optionalString) UnmarshalJSON(data []byte) error {
	if string(data) == "null" {
		return errors.New("must be a string, not null")
	}
	if err := json.Unmarshal(data, &s.value); err != nil {
		return err
	}
	s.set = true
	return nil
}

type requestWire struct {
	ExternalAccountAudience string         `json:"external_account_audience"`
	ImpersonatedEmail       optionalString `json:"impersonated_email"`
}

type UpstreamRequest struct {
	Alias                   string
	ExternalAccountAudience string
	ImpersonatedEmail       string
	RequestSource           agentsource.Source
}

type Upstream interface {
	SubjectToken(context.Context, UpstreamRequest) (tokenapi.SubjectTokenResponse, error)
}

type Session struct {
	Alias                   string
	Target                  string
	ExternalAccountAudience string
	Source                  agentsource.Source
}

type API struct {
	Session  Session
	Upstream Upstream
}

func (a *API) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/subject-token", a.subjectToken)
	return mux
}

func (a *API) subjectToken(w http.ResponseWriter, r *http.Request) {
	var req requestWire
	if err := jsonhttp.Decode(r, &req, maxRequestBody); err != nil {
		writeError(w, http.StatusBadRequest, err.Error(), tokenapi.CodeEnv, "send the fixed agent-session request shape")
		return
	}
	if req.ExternalAccountAudience != a.Session.ExternalAccountAudience {
		writeError(w, http.StatusForbidden,
			"credential configuration audience does not match the delegated session",
			tokenapi.CodeEnv, "use the session's generated credential.json")
		return
	}
	if req.ImpersonatedEmail.set && req.ImpersonatedEmail.value != a.Session.Target {
		writeError(w, http.StatusForbidden,
			"credential configuration impersonation target does not match the delegated session",
			tokenapi.CodeEnv, "use the session's generated credential.json")
		return
	}
	result, err := a.Upstream.SubjectToken(r.Context(), UpstreamRequest{
		Alias:                   a.Session.Alias,
		ExternalAccountAudience: a.Session.ExternalAccountAudience,
		ImpersonatedEmail:       a.Session.Target,
		RequestSource:           a.Session.Source,
	})
	if err != nil {
		var apiErr *tokenapi.APIError
		if errors.As(err, &apiErr) {
			writeError(w, apiErr.Status, apiErr.Message, apiErr.Code, apiErr.Remedy)
			return
		}
		writeError(w, http.StatusServiceUnavailable,
			"pivb daemon is not reachable on the signing socket",
			tokenapi.CodeUnavailable, "start or restart the trusted-host pivb daemon")
		return
	}
	jsonhttp.Write(w, http.StatusOK, result)
}

func writeError(w http.ResponseWriter, status int, message, code, remedy string) {
	jsonhttp.Write(w, status, tokenapi.ErrorResponse{Error: message, Code: code, Remedy: remedy})
}
