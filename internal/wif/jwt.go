// Package wif implements the OIDC subject-token, JWKS, and credential-file
// primitives for Google Workload Identity Federation with executable-sourced
// credentials. It performs no I/O with Google: pivb only mints short-lived
// RS256 assertions; STS exchange and impersonation belong to the calling
// Google auth library.
package wif

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"
)

const (
	// TokenType is the OIDC subject token type used in credential files, the
	// executable protocol, and the STS exchange.
	TokenType = "urn:ietf:params:oauth:token-type:id_token"

	// SubjectPrefix namespaces every federated subject to an enrolled key.
	SubjectPrefix = "pivb-key:"

	// DefaultLifetime is the validity of one assertion when the alias does not
	// configure its own. An alias may raise it up to MaxLifetime through
	// assertion_lifetime_s.
	DefaultLifetime = 300 * time.Second

	// MaxLifetime is the absolute ceiling on assertion validity, enforced here
	// at claim construction so no configuration path can exceed it. Each extra
	// second extends the horizon one touch authorises: an assertion stays
	// exchangeable for its whole life, and the access token it buys lives on
	// after that, so the horizon is assertion lifetime plus the target's
	// lifetime_s.
	MaxLifetime = 3600 * time.Second

	// ClockSkew backdates iat so a slightly slow verifier clock still accepts
	// a freshly signed token. exp remains iat plus the assertion's lifetime, so
	// the usable window after signing is that lifetime less one ClockSkew.
	ClockSkew = 30 * time.Second

	jtiBytes = 16
)

// Provider identifies one workload identity pool OIDC provider. All audience
// forms are derived from it; none are accepted as free-form input.
type Provider struct {
	ProjectNumber string
	PoolID        string
	ProviderID    string
	IssuerURI     string
}

// Resource returns the provider resource name without a scheme or host.
func (p Provider) Resource() string {
	return "projects/" + p.ProjectNumber +
		"/locations/global/workloadIdentityPools/" + p.PoolID +
		"/providers/" + p.ProviderID
}

// ExternalAccountAudience is the audience used in external-account credential
// files and STS exchange requests.
func (p Provider) ExternalAccountAudience() string {
	return "//iam.googleapis.com/" + p.Resource()
}

// OIDCAudience is the aud claim required by the workload identity provider.
func (p Provider) OIDCAudience() string {
	return "https://iam.googleapis.com/" + p.Resource()
}

type header struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
	Kid string `json:"kid"`
}

// VerifiedToken is the strictly decoded result of verifying a forwarded PIVB
// assertion. Forwarded assertions are never trusted merely because they
// arrived over an authenticated transport: the receiving pivbd re-validates
// their complete shape and signature against its local enrollment.
type VerifiedToken struct {
	HeaderKeyID string
	Claims      Claims
	PublicKey   *rsa.PublicKey
}

// Claims is the fixed OIDC subject-token claim set. The daemon never accepts
// caller-supplied claims, audiences, or targets; every field is derived from
// validated configuration and the live signing session.
type Claims struct {
	Iss    string `json:"iss"`
	Sub    string `json:"sub"`
	Aud    string `json:"aud"`
	Iat    int64  `json:"iat"`
	Exp    int64  `json:"exp"`
	Jti    string `json:"jti"`
	Alias  string `json:"alias"`
	Target string `json:"target"`
	Serial string `json:"serial"`
	KeyID  string `json:"key_id"`
}

// ExpiresAt returns the exp claim as a time.
func (c Claims) ExpiresAt() time.Time { return time.Unix(c.Exp, 0).UTC() }

// NewJTI returns a 128-bit random base64url token identifier. Pass a CSPRNG
// (crypto/rand.Reader in production; tests may inject a fixed stream).
func NewJTI(random io.Reader) (string, error) {
	b := make([]byte, jtiBytes)
	if _, err := io.ReadFull(random, b); err != nil {
		return "", fmt.Errorf("generate jti: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// NewClaims builds the claim set for one enrolled key and one configured
// alias/target pair. Every field is required; empty inputs fail closed. The
// lifetime is the alias's configured assertion validity and is bounded here
// rather than trusted from the caller.
func NewClaims(p Provider, alias, target string, serial uint32, keyID, jti string, now time.Time, lifetime time.Duration) (Claims, error) {
	switch {
	case p.ProjectNumber == "" || p.PoolID == "" || p.ProviderID == "":
		return Claims{}, errors.New("wif provider is incompletely configured")
	case p.IssuerURI == "":
		return Claims{}, errors.New("wif issuer_uri is not configured")
	case alias == "" || target == "":
		return Claims{}, errors.New("subject-token alias and target are required")
	case serial == 0:
		return Claims{}, errors.New("subject-token serial must be nonzero")
	case keyID == "":
		return Claims{}, errors.New("subject-token key ID is required")
	case jti == "":
		return Claims{}, errors.New("subject-token jti is required")
	case now.IsZero():
		return Claims{}, errors.New("subject-token signing time is required")
	case lifetime < DefaultLifetime || lifetime > MaxLifetime:
		return Claims{}, fmt.Errorf("subject-token lifetime %s is outside the permitted %s..%s", lifetime, DefaultLifetime, MaxLifetime)
	}
	iat := now.Add(-ClockSkew).Unix()
	return Claims{
		Iss:    p.IssuerURI,
		Sub:    SubjectPrefix + keyID,
		Aud:    p.OIDCAudience(),
		Iat:    iat,
		Exp:    iat + int64(lifetime/time.Second),
		Jti:    jti,
		Alias:  alias,
		Target: target,
		Serial: strconv.FormatUint(uint64(serial), 10),
		KeyID:  keyID,
	}, nil
}

// SigningInput returns the RS256 JWS signing input HEADER.PAYLOAD for the
// claim set, with the JWK key ID bound into the protected header.
func SigningInput(claims Claims) (string, error) {
	if claims.KeyID == "" {
		return "", errors.New("claims have no key ID")
	}
	h, err := json.Marshal(header{Alg: "RS256", Typ: "JWT", Kid: claims.KeyID})
	if err != nil {
		return "", fmt.Errorf("marshal JWS header: %w", err)
	}
	c, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("marshal JWT claims: %w", err)
	}
	enc := base64.RawURLEncoding
	return enc.EncodeToString(h) + "." + enc.EncodeToString(c), nil
}

// SigningDigest returns the SHA-256 digest that the PIV key must sign with
// PKCS#1 v1.5 to complete the RS256 JWS over input.
func SigningDigest(input string) []byte {
	sum := sha256.Sum256([]byte(input))
	return sum[:]
}

// Assemble joins the signing input and raw RS256 signature into a compact JWS.
func Assemble(input string, signature []byte) (string, error) {
	if input == "" {
		return "", errors.New("empty JWS signing input")
	}
	if len(signature) == 0 {
		return "", errors.New("empty RS256 signature")
	}
	return input + "." + base64.RawURLEncoding.EncodeToString(signature), nil
}

// VerifyForwarded verifies a compact PIVB assertion using the public SPKI
// returned by the provider. It rejects extensions to the fixed header and
// claim schemas as well as non-RSA-2048/F4 keys.
func VerifyForwarded(token string, spki []byte) (VerifiedToken, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return VerifiedToken{}, errors.New("forwarded subject token is not a three-part compact JWS")
	}
	decode := func(label, encoded string, dst any) error {
		raw, err := base64.RawURLEncoding.DecodeString(encoded)
		if err != nil {
			return fmt.Errorf("decode forwarded %s: %w", label, err)
		}
		dec := json.NewDecoder(bytes.NewReader(raw))
		dec.DisallowUnknownFields()
		if err := dec.Decode(dst); err != nil {
			return fmt.Errorf("decode forwarded %s JSON: %w", label, err)
		}
		if err := dec.Decode(&struct{}{}); err != io.EOF {
			return fmt.Errorf("decode forwarded %s JSON: multiple values", label)
		}
		return nil
	}
	var h header
	if err := decode("header", parts[0], &h); err != nil {
		return VerifiedToken{}, err
	}
	if h.Alg != "RS256" || h.Typ != "JWT" || h.Kid == "" {
		return VerifiedToken{}, fmt.Errorf("forwarded JWS header must be alg=RS256, typ=JWT, and carry kid")
	}
	var claims Claims
	if err := decode("claims", parts[1], &claims); err != nil {
		return VerifiedToken{}, err
	}
	parsed, err := x509.ParsePKIXPublicKey(spki)
	if err != nil {
		return VerifiedToken{}, fmt.Errorf("parse forwarded SubjectPublicKeyInfo: %w", err)
	}
	pub, ok := parsed.(*rsa.PublicKey)
	if !ok || pub.N.BitLen() != 2048 || pub.E != rsaPublicExponent {
		return VerifiedToken{}, errors.New("forwarded public key is not RSA-2048/F4")
	}
	kid, err := KeyID(pub)
	if err != nil {
		return VerifiedToken{}, err
	}
	if h.Kid != kid || claims.KeyID != kid {
		return VerifiedToken{}, fmt.Errorf("forwarded key identity mismatch: header=%q claims=%q spki=%q", h.Kid, claims.KeyID, kid)
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return VerifiedToken{}, fmt.Errorf("decode forwarded signature: %w", err)
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest[:], signature); err != nil {
		return VerifiedToken{}, fmt.Errorf("verify forwarded RS256 signature: %w", err)
	}
	return VerifiedToken{HeaderKeyID: h.Kid, Claims: claims, PublicKey: pub}, nil
}
