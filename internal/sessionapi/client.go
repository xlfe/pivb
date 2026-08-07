package sessionapi

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

	"github.com/xlfe/pivb/internal/tokenapi"
	"github.com/xlfe/pivb/internal/uds"
)

const HelperTimeout = 28 * time.Second

type Client struct {
	HTTP *http.Client
}

func NewClient(socket string) *Client {
	return &Client{HTTP: uds.NewHTTPClient(socket, HelperTimeout)}
}

func (c *Client) SubjectToken(ctx context.Context, req Request) (tokenapi.SubjectTokenResponse, error) {
	var out tokenapi.SubjectTokenResponse
	body, err := json.Marshal(req)
	if err != nil {
		return out, err
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://pivb-agent/v1/subject-token", bytes.NewReader(body))
	if err != nil {
		return out, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	resp, err := c.HTTP.Do(httpReq)
	if err != nil {
		return out, fmt.Errorf("call pivb agent-session socket: %w", err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, uds.MaxResponseBody+1))
	if err != nil {
		return out, fmt.Errorf("read pivb agent-session response: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		var er tokenapi.ErrorResponse
		_ = json.Unmarshal(b, &er)
		if er.Error == "" {
			er.Error = strings.TrimSpace(string(b))
		}
		if er.Code == "" {
			er.Code = tokenapi.CodeInternal
		}
		return out, &tokenapi.APIError{Status: resp.StatusCode, Code: er.Code, Message: er.Error, Remedy: er.Remedy}
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&out); err != nil {
		return out, fmt.Errorf("decode pivb agent-session response: %w", err)
	}
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		return out, errors.New("decode pivb agent-session response: multiple JSON values")
	}
	if out.IDToken == "" || out.ExpirationTime <= 0 {
		return tokenapi.SubjectTokenResponse{}, errors.New("pivb agent-session response is incomplete")
	}
	return out, nil
}
