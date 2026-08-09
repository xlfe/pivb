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
	ProtocolVersion = 2
	maxRequestBody  = 16 << 10
	clientTimeout   = 25 * time.Second
)

type CardIdentity struct {
	Serial  uint32 `json:"serial"`
	KeyID   string `json:"jwk_kid"`
	SPKIDER []byte `json:"spki_der"`
}

type AliasBinding struct {
	Target string `json:"target"`
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
}

type Description struct {
	Version          int                     `json:"version"`
	ProviderResource string                  `json:"provider_resource"`
	IssuerURI        string                  `json:"issuer_uri"`
	Aliases          map[string]AliasBinding `json:"aliases"`
	Card             CardIdentity            `json:"card"`
}

type ForwardContext struct {
	OriginNodeID     string `json:"origin_node_id"`
	WorkspaceID      string `json:"workspace_id"`
	Bundle           string `json:"bundle"`
	ClaimGeneration  uint64 `json:"claim_generation"`
	ProviderNodeID   string `json:"provider_node_id"`
	ProviderAttachID string `json:"provider_attachment_id,omitempty"`
	OperationID      string `json:"operation_id"`
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
}

type Backend interface {
	Policy(context.Context) (Policy, *tokenapi.APIError)
	Describe(context.Context) (Description, *tokenapi.APIError)
	Mint(context.Context, MintRequest) (MintResponse, *tokenapi.APIError)
}

type API struct{ Backend Backend }

func (a *API) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/policy", a.policy)
	mux.HandleFunc("GET /v1/describe", a.describe)
	mux.HandleFunc("POST /v1/mint", a.mint)
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
	if err := jsonhttp.Decode(r, &req, maxRequestBody); err != nil {
		writeAPIError(w, &tokenapi.APIError{Status: http.StatusBadRequest, Code: tokenapi.CodeConfig, Message: err.Error(), Remedy: "send the fixed PIVB forwarding request shape"})
		return
	}
	if req.Version != ProtocolVersion {
		writeAPIError(w, &tokenapi.APIError{Status: http.StatusBadRequest, Code: tokenapi.CodeConfig, Message: fmt.Sprintf("unsupported PIVB forwarding protocol %d", req.Version), Remedy: "upgrade PIVB and ZKA together"})
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
		return Description{}, errors.New("PIVB forwarding description is incomplete")
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
		return Policy{}, errors.New("PIVB forwarding policy is incomplete")
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
		return MintResponse{}, errors.New("PIVB forwarding response is incomplete")
	}
	return out, nil
}

func (c *Client) do(req *http.Request, out any) error {
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return fmt.Errorf("call PIVB forwarding socket: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, uds.MaxResponseBody+1))
	if err != nil {
		return fmt.Errorf("read PIVB forwarding response: %w", err)
	}
	if len(body) > uds.MaxResponseBody {
		return errors.New("PIVB forwarding response is too large")
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		var er tokenapi.ErrorResponse
		_ = json.Unmarshal(body, &er)
		if er.Error == "" {
			er.Error = strings.TrimSpace(string(body))
		}
		if er.Code == "" {
			er.Code = tokenapi.CodeInternal
		}
		return &tokenapi.APIError{Status: resp.StatusCode, Code: er.Code, Message: er.Error, Remedy: er.Remedy}
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(out); err != nil {
		return fmt.Errorf("decode PIVB forwarding response: %w", err)
	}
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		return errors.New("decode PIVB forwarding response: multiple values")
	}
	return nil
}
