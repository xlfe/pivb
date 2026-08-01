package gcp

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/xlfe/pivb/internal/config"
	"github.com/xlfe/pivb/internal/core"
	"github.com/xlfe/pivb/internal/pivsigner"
)

const (
	defaultOAuthURL = "https://oauth2.googleapis.com/token"
	defaultIAMURL   = "https://iamcredentials.googleapis.com"
	cloudScope      = "https://www.googleapis.com/auth/cloud-platform"
	maxErrorBody    = 64 << 10
)

type Minter struct {
	Signer     pivsigner.Signer
	HTTPClient *http.Client
	BrokerSA   string
	KeyID      string
	OAuthURL   string
	IAMURL     string
	Now        func() time.Time
	Logger     *slog.Logger

	// TokenWiped is a test seam. Production leaves it nil.
	TokenWiped func([]byte)
}

func (m *Minter) Mint(ctx context.Context, request core.MintRequest) (core.MintedCredential, error) {
	switch request.Purpose {
	case core.MintAccess:
		credential, err := m.MintAccess(ctx, request.AliasName, request.Alias, request.PIN)
		credential.Cloud = "gcp"
		credential.Subject = request.Alias.Target
		if credential.Value != "" {
			credential.Fields = map[string]string{"access_token": credential.Value}
		}
		return credential, err
	case core.MintIdentity:
		credential, err := m.MintIdentity(ctx, request.AliasName, request.Alias, request.Audience, request.PIN)
		credential.Cloud = "gcp"
		credential.Subject = request.Alias.Target
		if credential.Value != "" {
			credential.Fields = map[string]string{"token": credential.Value}
		}
		return credential, err
	default:
		return core.MintedCredential{}, fmt.Errorf("GCP minter does not support mint purpose %q", request.Purpose)
	}
}

func (m *Minter) MintAccess(ctx context.Context, aliasName string, alias config.Alias, pin string) (core.MintedAccess, error) {
	broker, serial, err := m.brokerToken(ctx, aliasName, pin)
	if err != nil {
		return core.MintedAccess{Serial: serial}, err
	}
	defer func() {
		if broker != nil {
			m.wipe(broker)
		}
	}()

	endpoint := m.iamBase() + "/v1/projects/-/serviceAccounts/" + url.PathEscape(alias.Target) + ":generateAccessToken"
	body, err := json.Marshal(struct {
		Scope    []string `json:"scope"`
		Lifetime string   `json:"lifetime"`
	}{[]string{cloudScope}, strconv.Itoa(alias.LifetimeS) + "s"})
	if err != nil {
		return core.MintedAccess{Serial: serial}, err
	}
	var response struct {
		AccessToken string    `json:"accessToken"`
		ExpireTime  time.Time `json:"expireTime"`
	}
	err = m.providerJSON(ctx, http.MethodPost, endpoint, body, broker, &response)
	m.wipe(broker)
	broker = nil
	if err != nil {
		return core.MintedAccess{Serial: serial}, fmt.Errorf("generate access token for %s: %w", alias.Target, err)
	}
	if response.AccessToken == "" || response.ExpireTime.IsZero() {
		return core.MintedAccess{Serial: serial}, fmt.Errorf("generate access token for %s: provider returned an incomplete response", alias.Target)
	}
	return core.MintedAccess{Value: response.AccessToken, ExpiresAt: response.ExpireTime, Serial: serial}, nil
}

func (m *Minter) MintIdentity(ctx context.Context, aliasName string, alias config.Alias, audience, pin string) (core.MintedIdentity, error) {
	broker, serial, err := m.brokerToken(ctx, aliasName, pin)
	if err != nil {
		return core.MintedIdentity{Serial: serial}, err
	}
	defer func() {
		if broker != nil {
			m.wipe(broker)
		}
	}()
	endpoint := m.iamBase() + "/v1/projects/-/serviceAccounts/" + url.PathEscape(alias.Target) + ":generateIdToken"
	body, _ := json.Marshal(struct {
		Audience     string `json:"audience"`
		IncludeEmail bool   `json:"includeEmail"`
	}{audience, true})
	var response struct {
		Token string `json:"token"`
	}
	err = m.providerJSON(ctx, http.MethodPost, endpoint, body, broker, &response)
	m.wipe(broker)
	broker = nil
	if err != nil {
		return core.MintedIdentity{Serial: serial}, fmt.Errorf("generate ID token for %s: %w", alias.Target, err)
	}
	expires, err := jwtExpiry(response.Token)
	if err != nil {
		return core.MintedIdentity{Serial: serial}, fmt.Errorf("generate ID token for %s: invalid token response: %w", alias.Target, err)
	}
	return core.MintedIdentity{Value: response.Token, ExpiresAt: expires, Serial: serial}, nil
}

func (m *Minter) brokerToken(ctx context.Context, aliasName, pin string) ([]byte, uint32, error) {
	now := m.now()
	header, _ := json.Marshal(struct {
		Alg string `json:"alg"`
		Typ string `json:"typ"`
		Kid string `json:"kid"`
	}{"RS256", "JWT", m.KeyID})
	claims, _ := json.Marshal(struct {
		Iss   string `json:"iss"`
		Sub   string `json:"sub"`
		Aud   string `json:"aud"`
		Scope string `json:"scope"`
		Iat   int64  `json:"iat"`
		Exp   int64  `json:"exp"`
	}{m.BrokerSA, m.BrokerSA, defaultOAuthURL, cloudScope, now.Unix(), now.Add(10 * time.Minute).Unix()})
	enc := base64.RawURLEncoding
	input := enc.EncodeToString(header) + "." + enc.EncodeToString(claims)
	digest := sha256.Sum256([]byte(input))
	sig, serial, err := m.Signer.Sign(ctx, aliasName, pin, digest[:])
	if err != nil {
		return nil, serial, fmt.Errorf("sign broker assertion: %w", err)
	}
	assertion := input + "." + enc.EncodeToString(sig)
	form := url.Values{
		"grant_type": {"urn:ietf:params:oauth:grant-type:jwt-bearer"},
		"assertion":  {assertion},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, m.oauthURL(), strings.NewReader(form.Encode()))
	if err != nil {
		return nil, serial, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := m.client().Do(req)
	if err != nil {
		return nil, serial, fmt.Errorf("exchange broker assertion at %s: %w", m.oauthURL(), err)
	}
	defer resp.Body.Close()
	limited, readErr := io.ReadAll(io.LimitReader(resp.Body, maxErrorBody+1))
	if readErr != nil {
		return nil, serial, fmt.Errorf("exchange broker assertion at %s: read response: %w", m.oauthURL(), readErr)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		m.logger().Error("OAuth provider rejected broker assertion", "status", resp.Status, "body", bounded(limited))
		return nil, serial, fmt.Errorf("exchange broker assertion at %s: HTTP %s: %s", m.oauthURL(), resp.Status, bounded(limited))
	}
	var token struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(limited, &token); err != nil {
		return nil, serial, fmt.Errorf("exchange broker assertion at %s: decode response: %w", m.oauthURL(), err)
	}
	if token.AccessToken == "" {
		return nil, serial, fmt.Errorf("exchange broker assertion at %s: response omitted access_token", m.oauthURL())
	}
	return []byte(token.AccessToken), serial, nil
}

func (m *Minter) providerJSON(ctx context.Context, method, endpoint string, body, bearer []byte, out any) error {
	req, err := http.NewRequestWithContext(ctx, method, endpoint, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+string(bearer))
	resp, err := m.client().Do(req)
	if err != nil {
		return fmt.Errorf("call %s: %w", endpoint, err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxErrorBody+1))
	if err != nil {
		return fmt.Errorf("call %s: read response: %w", endpoint, err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		m.logger().Error("IAM Credentials provider request failed", "endpoint", endpoint, "status", resp.Status, "body", bounded(b))
		return fmt.Errorf("call %s: HTTP %s: %s", endpoint, resp.Status, bounded(b))
	}
	if err := json.Unmarshal(b, out); err != nil {
		return fmt.Errorf("call %s: decode response: %w", endpoint, err)
	}
	return nil
}

func (m *Minter) wipe(token []byte) {
	for i := range token {
		token[i] = 0
	}
	if m.TokenWiped != nil {
		m.TokenWiped(token)
	}
}

func (m *Minter) client() *http.Client {
	if m.HTTPClient != nil {
		return m.HTTPClient
	}
	return &http.Client{Timeout: 30 * time.Second}
}

func (m *Minter) now() time.Time {
	if m.Now != nil {
		return m.Now().UTC()
	}
	return time.Now().UTC()
}

func (m *Minter) oauthURL() string {
	if m.OAuthURL != "" {
		return m.OAuthURL
	}
	return defaultOAuthURL
}

func (m *Minter) iamBase() string {
	if m.IAMURL != "" {
		return strings.TrimRight(m.IAMURL, "/")
	}
	return defaultIAMURL
}

func (m *Minter) logger() *slog.Logger {
	if m.Logger != nil {
		return m.Logger
	}
	return slog.Default()
}

func bounded(b []byte) string {
	if len(b) <= maxErrorBody {
		return strings.TrimSpace(string(b))
	}
	return strings.TrimSpace(string(b[:maxErrorBody])) + "…(truncated)"
}

func jwtExpiry(token string) (time.Time, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return time.Time{}, fmt.Errorf("JWT has %d parts", len(parts))
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return time.Time{}, fmt.Errorf("decode JWT payload: %w", err)
	}
	var claims struct {
		Exp int64 `json:"exp"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return time.Time{}, fmt.Errorf("decode JWT claims: %w", err)
	}
	if claims.Exp == 0 {
		return time.Time{}, fmt.Errorf("JWT has no exp claim")
	}
	return time.Unix(claims.Exp, 0).UTC(), nil
}
