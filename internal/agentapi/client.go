package agentapi

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/xlfe/pivb/internal/core"
	"github.com/xlfe/pivb/internal/uds"
)

type Client struct {
	HTTP *http.Client
}

// NewClient returns a control-socket client. The timeout covers unlock, which
// performs one PIV PIN verification.
func NewClient(socket string) *Client {
	return &Client{HTTP: uds.NewHTTPClient(socket, 40*time.Second)}
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

type HTTPError struct {
	Status       int
	Body         []byte
	ErrorMessage string
	Remedy       string
}

func (e *HTTPError) Error() string {
	if e.Remedy != "" {
		return fmt.Sprintf("control API HTTP %d: %s (remedy: %s)", e.Status, e.ErrorMessage, e.Remedy)
	}
	return fmt.Sprintf("control API HTTP %d: %s", e.Status, e.ErrorMessage)
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
		return fmt.Errorf("call pivb control socket: %w", err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, uds.MaxResponseBody+1))
	if err != nil {
		return fmt.Errorf("read pivb control response: %w", err)
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
		return fmt.Errorf("decode pivb control response: %w", err)
	}
	return nil
}
