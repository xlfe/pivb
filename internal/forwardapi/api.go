// Package forwardapi defines the constrained PIVB credential-provider
// protocol used behind pivbd. It forwards complete PIVB mint requests and
// public card identity; it never accepts raw digests, APDUs, PINs, or unlock
// operations.
package forwardapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/xlfe/pivb/internal/agentsource"
	"github.com/xlfe/pivb/internal/jsonhttp"
	"github.com/xlfe/pivb/internal/tokenapi"
	"github.com/xlfe/pivb/internal/uds"
)

const (
	ProtocolVersion = 3
	maxRequestBody  = 16 << 10
	// Hardware minting is bounded at 23 seconds (one-second lease acquisition,
	// 20-second hardware deadline, two-second worker drain), leaving two
	// seconds for forwarding transport and JSON work.
	clientTimeout = 25 * time.Second
)

type CardIdentity struct {
	Serial  uint32 `json:"serial"`
	KeyID   string `json:"jwk_kid"`
	SPKIDER []byte `json:"spki_der"`
}

type AliasBinding struct {
	Target string `json:"target"`
	// AssertionLifetimeS advertises how long one touch's assertion may be
	// reused for this alias. Zero means every mint costs a touch.
	AssertionLifetimeS int64 `json:"assertion_lifetime_s,omitempty"`
}

type EnrolledKey struct {
	Serial uint32 `json:"serial"`
	KeyID  string `json:"jwk_kid"`
}

type Policy struct {
	Version          int                     `json:"version"`
	ProviderResource string                  `json:"provider_resource"`
	IssuerURI        string                  `json:"issuer_uri"`
	Aliases          map[string]AliasBinding `json:"aliases"`
	EnrolledKeys     []EnrolledKey           `json:"enrolled_keys"`
	// MaxGrantWindowS is the longest authorisation window this provider will
	// grant a claim. Zero means the provider grants no windows at all.
	MaxGrantWindowS int64 `json:"max_grant_window_s,omitempty"`
}

type Description struct {
	Version          int                     `json:"version"`
	ProviderResource string                  `json:"provider_resource"`
	IssuerURI        string                  `json:"issuer_uri"`
	Aliases          map[string]AliasBinding `json:"aliases"`
	Card             CardIdentity            `json:"card"`
	MaxGrantWindowS  int64                   `json:"max_grant_window_s,omitempty"`
}

type ForwardContext struct {
	OriginNodeID     string `json:"origin_node_id"`
	WorkspaceID      string `json:"workspace_id"`
	Bundle           string `json:"bundle"`
	ClaimGeneration  uint64 `json:"claim_generation"`
	ProviderNodeID   string `json:"provider_node_id"`
	ProviderAttachID string `json:"provider_attachment_id,omitempty"`
	OperationID      string `json:"operation_id"`
	// WindowSeconds is the authorisation window the claim asks this mint to be
	// covered by, and WindowDeadline is the absolute unix second the claim
	// anchored that window to. They travel together: both zero means the mint
	// asks for no window at all.
	WindowSeconds  int64 `json:"window_s,omitempty"`
	WindowDeadline int64 `json:"window_deadline,omitempty"`
}

type MintRequest struct {
	Version                 int                 `json:"version"`
	Alias                   string              `json:"alias"`
	ExternalAccountAudience string              `json:"external_account_audience"`
	ImpersonatedEmail       string              `json:"impersonated_email"`
	RequestSource           *agentsource.Source `json:"request_source,omitempty"`
	ExpectedCard            CardIdentity        `json:"expected_card"`
	ForwardContext          ForwardContext      `json:"forward_context"`
}

type MintResponse struct {
	Version        int            `json:"version"`
	IDToken        string         `json:"id_token"`
	ExpirationTime int64          `json:"expiration_time"`
	Card           CardIdentity   `json:"card"`
	ExpectedCard   CardIdentity   `json:"expected_card"`
	ForwardContext ForwardContext `json:"forward_context"`
	// The granted window is top-level rather than inside ForwardContext
	// because an origin rewrites the whole forwarded context when it binds a
	// response to its own route; what the provider granted must survive that.
	GrantedWindowSeconds  int64 `json:"granted_window_s,omitempty"`
	GrantedWindowDeadline int64 `json:"granted_window_deadline,omitempty"`
}

// InvalidateRequest drops every reusable assertion a provider still holds for
// one ZKA workspace claim. ClaimGeneration bounds the purge to that generation
// and below; zero means every generation, which is what a release sends.
type InvalidateRequest struct {
	Version         int    `json:"version"`
	WorkspaceID     string `json:"workspace_id"`
	ClaimGeneration uint64 `json:"claim_generation"`
}

type InvalidateResponse struct {
	Version int `json:"version"`
	Purged  int `json:"purged"`
}

type Backend interface {
	Policy(context.Context) (Policy, *tokenapi.APIError)
	Describe(context.Context) (Description, *tokenapi.APIError)
	Mint(context.Context, MintRequest) (MintResponse, *tokenapi.APIError)
	Invalidate(context.Context, InvalidateRequest) (InvalidateResponse, *tokenapi.APIError)
}

type API struct{ Backend Backend }

func (a *API) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/policy", a.policy)
	mux.HandleFunc("GET /v1/describe", a.describe)
	mux.HandleFunc("POST /v1/mint", a.mint)
	mux.HandleFunc("POST /v1/invalidate", a.invalidate)
	return mux
}

func (a *API) policy(w http.ResponseWriter, r *http.Request) {
	result, apiErr := a.Backend.Policy(r.Context())
	if apiErr != nil {
		writeAPIError(w, apiErr)
		return
	}
	result.Version = ProtocolVersion
	jsonhttp.Write(w, http.StatusOK, result)
}

func (a *API) describe(w http.ResponseWriter, r *http.Request) {
	result, apiErr := a.Backend.Describe(r.Context())
	if apiErr != nil {
		writeAPIError(w, apiErr)
		return
	}
	result.Version = ProtocolVersion
	jsonhttp.Write(w, http.StatusOK, result)
}

func (a *API) mint(w http.ResponseWriter, r *http.Request) {
	var req MintRequest
	if apiErr := decodeVersionedRequest(r, &req); apiErr != nil {
		writeAPIError(w, apiErr)
		return
	}
	if req.Version != ProtocolVersion {
		writeAPIError(w, versionSkewError(req.Version))
		return
	}
	result, apiErr := a.Backend.Mint(r.Context(), req)
	if apiErr != nil {
		writeAPIError(w, apiErr)
		return
	}
	result.Version = ProtocolVersion
	jsonhttp.Write(w, http.StatusOK, result)
}

func (a *API) invalidate(w http.ResponseWriter, r *http.Request) {
	var req InvalidateRequest
	if apiErr := decodeVersionedRequest(r, &req); apiErr != nil {
		writeAPIError(w, apiErr)
		return
	}
	if req.Version != ProtocolVersion {
		writeAPIError(w, versionSkewError(req.Version))
		return
	}
	result, apiErr := a.Backend.Invalidate(r.Context(), req)
	if apiErr != nil {
		writeAPIError(w, apiErr)
		return
	}
	result.Version = ProtocolVersion
	jsonhttp.Write(w, http.StatusOK, result)
}

// decodeVersionedRequest reads one bounded request body and answers a version
// skew before it answers a shape complaint. A peer one protocol behind sends
// fields this build has never heard of, so strict decoding alone would report
// a malformed request and send an operator hunting the wrong fault; the
// tolerant version peek turns that into "upgrade both sides".
func decodeVersionedRequest(r *http.Request, dst any) *tokenapi.APIError {
	body, err := io.ReadAll(http.MaxBytesReader(nil, r.Body, maxRequestBody))
	if err != nil {
		return badRequestShape(err)
	}
	var peek struct {
		Version *int `json:"version"`
	}
	if json.Unmarshal(body, &peek) == nil && peek.Version != nil && *peek.Version != ProtocolVersion {
		return versionSkewError(*peek.Version)
	}
	if err := decodeStrict(body, dst); err != nil {
		return badRequestShape(err)
	}
	return nil
}

func decodeStrict(body []byte, dst any) error {
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return fmt.Errorf("invalid JSON body: %w", err)
	}
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		return errors.New("invalid JSON body: multiple values")
	}
	return nil
}

func badRequestShape(err error) *tokenapi.APIError {
	return &tokenapi.APIError{Status: http.StatusBadRequest, Code: tokenapi.CodeConfig, Message: err.Error(), Remedy: "send the fixed PIVB forwarding request shape"}
}

func versionSkewError(version int) *tokenapi.APIError {
	return &tokenapi.APIError{Status: http.StatusBadRequest, Code: tokenapi.CodeConfig, Message: fmt.Sprintf("unsupported PIVB forwarding protocol %d", version), Remedy: "upgrade PIVB and ZKA together"}
}

func writeAPIError(w http.ResponseWriter, err *tokenapi.APIError) {
	status := err.Status
	if status == 0 {
		status = http.StatusBadGateway
	}
	jsonhttp.Write(w, status, tokenapi.ErrorResponse{Error: err.Message, Code: err.Code, Remedy: err.Remedy})
}

type Client struct {
	HTTP *http.Client
}

// TransportError means the selected endpoint could not be reached or read.
type TransportError struct{ Err error }

func (e *TransportError) Error() string { return e.Err.Error() }
func (e *TransportError) Unwrap() error { return e.Err }

// ProtocolError means the selected endpoint responded but did not speak the
// negotiated forwarding protocol. Callers expose this as PIVB_CONFIG rather
// than misdiagnosing it as a transient outage.
type ProtocolError struct{ Err error }

func (e *ProtocolError) Error() string { return e.Err.Error() }
func (e *ProtocolError) Unwrap() error { return e.Err }

func NewClient(socket string) *Client {
	return &Client{HTTP: uds.NewHTTPClient(socket, clientTimeout)}
}

func NewClientWithTimeout(socket string, timeout time.Duration) *Client {
	return &Client{HTTP: uds.NewHTTPClient(socket, timeout)}
}

func (c *Client) Describe(ctx context.Context) (Description, error) {
	var out Description
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://pivb-forward/v1/describe", nil)
	if err != nil {
		return out, err
	}
	if err := c.do(req, &out); err != nil {
		return out, err
	}
	if out.Version != ProtocolVersion || out.ProviderResource == "" || out.IssuerURI == "" || out.Card.Serial == 0 || out.Card.KeyID == "" || len(out.Card.SPKIDER) == 0 {
		return Description{}, &ProtocolError{Err: errors.New("PIVB forwarding description is incomplete")}
	}
	return out, nil
}

func (c *Client) Policy(ctx context.Context) (Policy, error) {
	var out Policy
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://pivb-forward/v1/policy", nil)
	if err != nil {
		return out, err
	}
	if err := c.do(req, &out); err != nil {
		return out, err
	}
	if out.Version != ProtocolVersion || out.ProviderResource == "" || out.IssuerURI == "" || len(out.EnrolledKeys) == 0 {
		return Policy{}, &ProtocolError{Err: errors.New("PIVB forwarding policy is incomplete")}
	}
	return out, nil
}

func (c *Client) Mint(ctx context.Context, req MintRequest) (MintResponse, error) {
	var out MintResponse
	req.Version = ProtocolVersion
	body, err := json.Marshal(req)
	if err != nil {
		return out, err
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://pivb-forward/v1/mint", bytes.NewReader(body))
	if err != nil {
		return out, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	if err := c.do(httpReq, &out); err != nil {
		return out, err
	}
	if out.Version != ProtocolVersion || out.IDToken == "" || out.ExpirationTime <= 0 ||
		out.Card.Serial == 0 || out.Card.KeyID == "" || len(out.Card.SPKIDER) == 0 ||
		out.ExpectedCard.Serial == 0 || out.ExpectedCard.KeyID == "" || len(out.ExpectedCard.SPKIDER) == 0 ||
		out.ForwardContext.OriginNodeID == "" || out.ForwardContext.WorkspaceID == "" || out.ForwardContext.OperationID == "" {
		return MintResponse{}, &ProtocolError{Err: errors.New("PIVB forwarding response is incomplete")}
	}
	return out, nil
}

// Invalidate asks the provider to drop the reusable assertions it holds for a
// workspace claim. It is safe to call for a claim the provider never served:
// the provider answers with a purge count of zero.
func (c *Client) Invalidate(ctx context.Context, req InvalidateRequest) (InvalidateResponse, error) {
	var out InvalidateResponse
	req.Version = ProtocolVersion
	body, err := json.Marshal(req)
	if err != nil {
		return out, err
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://pivb-forward/v1/invalidate", bytes.NewReader(body))
	if err != nil {
		return out, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	if err := c.do(httpReq, &out); err != nil {
		return out, err
	}
	if out.Version != ProtocolVersion || out.Purged < 0 {
		return InvalidateResponse{}, &ProtocolError{Err: errors.New("PIVB forwarding invalidation response is incomplete")}
	}
	return out, nil
}

func (c *Client) do(req *http.Request, out any) error {
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return &TransportError{Err: fmt.Errorf("call PIVB forwarding socket: %w", err)}
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, uds.MaxResponseBody+1))
	if err != nil {
		return &TransportError{Err: fmt.Errorf("read PIVB forwarding response: %w", err)}
	}
	if len(body) > uds.MaxResponseBody {
		return &ProtocolError{Err: errors.New("PIVB forwarding response is too large")}
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		var er tokenapi.ErrorResponse
		decodeErr := json.Unmarshal(body, &er)
		if er.Error == "" {
			er.Error = strings.TrimSpace(string(body))
		}
		if decodeErr != nil || er.Code == "" || er.Error == "" {
			return &ProtocolError{Err: fmt.Errorf("PIVB forwarding endpoint returned an invalid error response (status %d)", resp.StatusCode)}
		}
		return &tokenapi.APIError{Status: resp.StatusCode, Code: er.Code, Message: er.Error, Remedy: er.Remedy}
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(out); err != nil {
		return &ProtocolError{Err: fmt.Errorf("decode PIVB forwarding response: %w", err)}
	}
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		return &ProtocolError{Err: errors.New("decode PIVB forwarding response: multiple values")}
	}
	return nil
}
