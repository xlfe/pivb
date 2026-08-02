package wifapi

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

	"github.com/xlfe/pivb/internal/uds"
)

// clientTimeout stays under the 30-second credential-source budget while
// covering the 20-second signing deadline plus one scdaemon retry.
const clientTimeout = 28 * time.Second

type Client struct {
	HTTP *http.Client
}

func NewClient(socket string) *Client {
	return &Client{HTTP: uds.NewHTTPClient(socket, clientTimeout)}
}

// APIError is a structured daemon rejection with a stable code.
type APIError struct {
	Status  int
	Code    string
	Message string
	Remedy  string
}

func (e *APIError) Error() string {
	if e.Remedy != "" {
		return fmt.Sprintf("pivb daemon %s: %s (remedy: %s)", e.Code, e.Message, e.Remedy)
	}
	return fmt.Sprintf("pivb daemon %s: %s", e.Code, e.Message)
}

func (c *Client) SubjectToken(ctx context.Context, req SubjectTokenRequest) (SubjectTokenResponse, error) {
	var out SubjectTokenResponse
	body, err := json.Marshal(req)
	if err != nil {
		return out, err
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://pivb/v1/subject-token", bytes.NewReader(body))
	if err != nil {
		return out, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	resp, err := c.HTTP.Do(httpReq)
	if err != nil {
		return out, fmt.Errorf("call pivb signing socket: %w", err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, uds.MaxResponseBody+1))
	if err != nil {
		return out, fmt.Errorf("read pivb signing response: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		var er errorResponse
		_ = json.Unmarshal(b, &er)
		if er.Error == "" {
			er.Error = strings.TrimSpace(string(b))
		}
		if er.Code == "" {
			er.Code = CodeInternal
		}
		return out, &APIError{Status: resp.StatusCode, Code: er.Code, Message: er.Error, Remedy: er.Remedy}
	}
	if err := json.Unmarshal(b, &out); err != nil {
		return out, fmt.Errorf("decode pivb signing response: %w", err)
	}
	if out.IDToken == "" || out.ExpirationTime <= 0 {
		return SubjectTokenResponse{}, errors.New("pivb signing response is incomplete")
	}
	return out, nil
}
