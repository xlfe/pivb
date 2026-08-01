package agentapi

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/xlfe/pivb/internal/core"
)

type Client struct {
	HTTP *http.Client
}

func NewClient(socket string) *Client {
	transport := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", socket)
		},
	}
	return &Client{HTTP: &http.Client{Transport: transport, Timeout: 40 * time.Second}}
}

func (c *Client) Status(ctx context.Context) (core.Status, error) {
	var out core.Status
	err := c.call(ctx, http.MethodGet, "/v1/status", nil, &out)
	return out, err
}

func (c *Client) Unlock(ctx context.Context, pin string) (int, error) {
	var out struct {
		Retries int `json:"retries"`
	}
	err := c.call(ctx, http.MethodPost, "/v1/unlock", map[string]string{"pin": pin}, &out)
	return out.Retries, err
}

func (c *Client) Lock(ctx context.Context) error {
	return c.call(ctx, http.MethodPost, "/v1/lock", map[string]any{}, &struct{}{})
}

func (c *Client) Use(ctx context.Context, alias string) (core.Token, error) {
	var out core.Token
	err := c.call(ctx, http.MethodPost, "/v1/use", map[string]string{"alias": alias}, &out)
	return out, err
}

func (c *Client) Renew(ctx context.Context) (core.Token, error) {
	var out core.Token
	err := c.call(ctx, http.MethodPost, "/v1/renew", map[string]any{}, &out)
	return out, err
}

func (c *Client) Token(ctx context.Context) (core.Token, error) {
	var out core.Token
	err := c.call(ctx, http.MethodGet, "/v1/token", nil, &out)
	return out, err
}

func (c *Client) Identity(ctx context.Context, audience string) (core.Identity, error) {
	var out core.Identity
	err := c.call(ctx, http.MethodGet, "/v1/identity?audience="+url.QueryEscape(audience), nil, &out)
	return out, err
}

type HTTPError struct {
	Status       int
	Body         []byte
	ErrorMessage string
	Remedy       string
}

func (e *HTTPError) Error() string {
	if e.Remedy != "" {
		return fmt.Sprintf("agent HTTP %d: %s (remedy: %s)", e.Status, e.ErrorMessage, e.Remedy)
	}
	return fmt.Sprintf("agent HTTP %d: %s", e.Status, e.ErrorMessage)
}

func (c *Client) call(ctx context.Context, method, path string, input, output any) error {
	var body io.Reader
	if input != nil {
		b, err := json.Marshal(input)
		if err != nil {
			return err
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, "http://pivb"+path, body)
	if err != nil {
		return err
	}
	if input != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return fmt.Errorf("call pivb agent: %w", err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxRequestBody+1))
	if err != nil {
		return fmt.Errorf("read pivb agent response: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		var er errorResponse
		_ = json.Unmarshal(b, &er)
		if er.Error == "" {
			er.Error = strings.TrimSpace(string(b))
		}
		return &HTTPError{Status: resp.StatusCode, Body: b, ErrorMessage: er.Error, Remedy: er.Remedy}
	}
	if err := json.Unmarshal(b, output); err != nil {
		return fmt.Errorf("decode pivb agent response: %w", err)
	}
	return nil
}
