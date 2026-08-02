package wif

import (
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"sort"
	"strconv"
)

// MaxJWKSKeys is Google's uploaded-JWK limit per OIDC provider. Larger fleets
// need multiple providers and are out of scope.
const MaxJWKSKeys = 8

// KeyIDLength is the length of an unpadded base64url SHA-256 digest.
const KeyIDLength = 43

const rsaPublicExponent = 65537

// JWK is the exact uploaded key shape for one enrolled PIV certificate.
type JWK struct {
	Kty string `json:"kty"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	Kid string `json:"kid"`
	N   string `json:"n"`
	E   string `json:"e"`
}

// JWKS is the complete uploaded key set. Google replaces the whole set on
// every provider update, so it must always contain every trusted key.
type JWKS struct {
	Keys []JWK `json:"keys"`
}

// RSAPublicKey returns the certificate's public key if and only if it is the
// RSA-2048/F4 shape used by the enrolled fleet.
func RSAPublicKey(cert *x509.Certificate) (*rsa.PublicKey, error) {
	pub, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("certificate public key is %T, not RSA", cert.PublicKey)
	}
	if bits := pub.N.BitLen(); bits != 2048 {
		return nil, fmt.Errorf("certificate RSA key is %d bits; pivb requires RSA-2048", bits)
	}
	if pub.E != rsaPublicExponent {
		return nil, fmt.Errorf("certificate RSA public exponent is %d; pivb requires 65537", pub.E)
	}
	return pub, nil
}

// KeyID derives the stable key identifier: unpadded base64url SHA-256 of the
// DER SubjectPublicKeyInfo encoding of the public key.
func KeyID(pub *rsa.PublicKey) (string, error) {
	spki, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", fmt.Errorf("marshal SubjectPublicKeyInfo: %w", err)
	}
	sum := sha256.Sum256(spki)
	return base64.RawURLEncoding.EncodeToString(sum[:]), nil
}

// CertificateKeyID derives the key ID for an enrolled certificate, enforcing
// the fleet key shape.
func CertificateKeyID(cert *x509.Certificate) (string, error) {
	pub, err := RSAPublicKey(cert)
	if err != nil {
		return "", err
	}
	return KeyID(pub)
}

// JWKFromCertificate converts one enrolled certificate to its uploaded JWK.
func JWKFromCertificate(cert *x509.Certificate) (JWK, error) {
	pub, err := RSAPublicKey(cert)
	if err != nil {
		return JWK{}, err
	}
	kid, err := KeyID(pub)
	if err != nil {
		return JWK{}, err
	}
	return JWK{
		Kty: "RSA",
		Use: "sig",
		Alg: "RS256",
		Kid: kid,
		N:   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
		E:   base64.RawURLEncoding.EncodeToString(big.NewInt(rsaPublicExponent).Bytes()),
	}, nil
}

// ParseCertificatePEM parses exactly one CERTIFICATE block. Concatenated
// bundles are rejected so a serial can never be bound to an ambiguous key.
func ParseCertificatePEM(data []byte) (*x509.Certificate, error) {
	block, rest := pem.Decode(data)
	if block == nil {
		return nil, errors.New("no PEM block found")
	}
	if block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("PEM block is %q, want CERTIFICATE", block.Type)
	}
	if next, _ := pem.Decode(rest); next != nil {
		return nil, errors.New("file contains more than one PEM block; provide exactly one certificate")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse certificate: %w", err)
	}
	return cert, nil
}

// BuildJWKS converts the full enrolled certificate set into the uploaded
// JWKS. It fails unless the set matches the configured keys one-to-one: every
// certificate serial must be configured with exactly the derived key ID, and
// every configured serial must have a certificate. Errors always name the
// derived key ID so first-time enrollment can copy it into configuration.
func BuildJWKS(certs map[uint32]*x509.Certificate, configured map[uint32]string) (JWKS, error) {
	if len(certs) == 0 {
		return JWKS{}, errors.New("at least one certificate is required")
	}
	if len(certs) > MaxJWKSKeys {
		return JWKS{}, fmt.Errorf("%d certificates exceed the Google limit of %d uploaded JWKs per provider", len(certs), MaxJWKSKeys)
	}

	serials := make([]uint32, 0, len(certs))
	for serial := range certs {
		serials = append(serials, serial)
	}
	sort.Slice(serials, func(i, j int) bool { return serials[i] < serials[j] })

	jwks := JWKS{Keys: make([]JWK, 0, len(certs))}
	kids := make(map[string]uint32, len(certs))
	for _, serial := range serials {
		jwk, err := JWKFromCertificate(certs[serial])
		if err != nil {
			return JWKS{}, fmt.Errorf("certificate for YubiKey %d: %w", serial, err)
		}
		if previous, dup := kids[jwk.Kid]; dup {
			return JWKS{}, fmt.Errorf("YubiKeys %d and %d present the same public key (jwk_kid %s)", previous, serial, jwk.Kid)
		}
		kids[jwk.Kid] = serial
		want, ok := configured[serial]
		if !ok {
			return JWKS{}, fmt.Errorf("YubiKey %d is not configured; add [keys.%d] with jwk_kid = %q", serial, serial, jwk.Kid)
		}
		if want != jwk.Kid {
			return JWKS{}, fmt.Errorf("YubiKey %d certificate derives jwk_kid %q but [keys.%d] is configured with %q; enroll the new key deliberately or use the matching certificate", serial, jwk.Kid, serial, want)
		}
		jwks.Keys = append(jwks.Keys, jwk)
	}
	for serial := range configured {
		if _, ok := certs[serial]; !ok {
			return JWKS{}, fmt.Errorf("configured YubiKey %d has no certificate input; uploading this set would revoke it (pass --cert %s=<pem> or remove [keys.%d])", serial, strconv.FormatUint(uint64(serial), 10), serial)
		}
	}
	return jwks, nil
}

// MarshalJWKS renders the uploaded JWKS document deterministically.
func MarshalJWKS(jwks JWKS) ([]byte, error) {
	out, err := json.MarshalIndent(jwks, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal JWKS: %w", err)
	}
	return append(out, '\n'), nil
}
