package wif_test

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/xlfe/pivb/internal/wif"
)

// Pinned key IDs for the checked-in fixtures. An operator copies these into
// configuration and Google trusts them by value, so any change here is a
// breaking fleet change and must be deliberate.
const (
	kidA = "g4tW--9GFcDvwdryp8vTG76EyUg-QhfOEjBo0YQg3Wg"
	kidB = "klDBeSjlLGunctWm3FyntSOcV9bk3MZ9pNbuDxn_E-I"
	kidC = "opeuSy-BfStl6F6KWUhhi_YLZNepNhoL8Q56Qa_Mils"
)

const (
	serialA = uint32(12345678)
	serialB = uint32(23456789)
	serialC = uint32(34567890)
)

func readFixture(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("read fixture %s: %v", name, err)
	}
	return data
}

func loadCert(t *testing.T, name string) *x509.Certificate {
	t.Helper()
	cert, err := wif.ParseCertificatePEM(readFixture(t, name))
	if err != nil {
		t.Fatalf("parse fixture %s: %v", name, err)
	}
	return cert
}

func requireErrorContains(t *testing.T, err error, want ...string) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected an error, got nil")
	}
	for _, w := range want {
		if !strings.Contains(err.Error(), w) {
			t.Fatalf("error %q does not contain %q", err.Error(), w)
		}
	}
}

func TestCertificateKeyIDGolden(t *testing.T) {
	tests := []struct {
		name string
		file string
		want string
	}{
		{"cert-a", "cert-a.pem", kidA},
		{"cert-b", "cert-b.pem", kidB},
		{"cert-c", "cert-c.pem", kidC},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := wif.CertificateKeyID(loadCert(t, tc.file))
			if err != nil {
				t.Fatalf("CertificateKeyID: %v", err)
			}
			if got != tc.want {
				t.Fatalf("CertificateKeyID = %q, want %q", got, tc.want)
			}
			if len(got) != wif.KeyIDLength {
				t.Fatalf("key ID %q is %d chars, want %d", got, len(got), wif.KeyIDLength)
			}
		})
	}
}

func TestRSAPublicKeyRejectsWrongKeyShape(t *testing.T) {
	tests := []struct {
		name string
		file string
		want []string
	}{
		{"ecdsa p-256", "cert-ec.pem", []string{"not RSA"}},
		{"rsa 1024", "cert-rsa1024.pem", []string{"1024 bits"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cert := loadCert(t, tc.file)
			_, err := wif.RSAPublicKey(cert)
			requireErrorContains(t, err, tc.want...)

			// The rejection must also hold on the paths the enrollment and
			// upload commands actually take.
			_, err = wif.CertificateKeyID(cert)
			requireErrorContains(t, err, tc.want...)
			_, err = wif.JWKFromCertificate(cert)
			requireErrorContains(t, err, tc.want...)
		})
	}
}

func TestParseCertificatePEMRejects(t *testing.T) {
	certA := readFixture(t, "cert-a.pem")
	certB := readFixture(t, "cert-b.pem")

	tests := []struct {
		name string
		data []byte
		want []string
	}{
		{"empty", nil, []string{"no PEM block"}},
		{"garbage", []byte("not a pem file at all\n"), []string{"no PEM block"}},
		{"private key", readFixture(t, "key-a.pem"), []string{"CERTIFICATE", "RSA PRIVATE KEY"}},
		{"bundle", append(append([]byte{}, certA...), certB...), []string{"more than one PEM block"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cert, err := wif.ParseCertificatePEM(tc.data)
			if cert != nil {
				t.Fatalf("expected no certificate, got subject %q", cert.Subject)
			}
			requireErrorContains(t, err, tc.want...)
		})
	}
}

func TestJWKFromCertificate(t *testing.T) {
	cert := loadCert(t, "cert-a.pem")
	jwk, err := wif.JWKFromCertificate(cert)
	if err != nil {
		t.Fatalf("JWKFromCertificate: %v", err)
	}

	for _, f := range []struct{ name, got, want string }{
		{"kty", jwk.Kty, "RSA"},
		{"use", jwk.Use, "sig"},
		{"alg", jwk.Alg, "RS256"},
		{"kid", jwk.Kid, kidA},
		{"e", jwk.E, "AQAB"},
	} {
		if f.got != f.want {
			t.Errorf("%s = %q, want %q", f.name, f.got, f.want)
		}
	}

	// n and e must be unpadded base64url: Google rejects padded JWK members.
	for _, f := range []struct{ name, value string }{{"n", jwk.N}, {"e", jwk.E}} {
		if strings.Contains(f.value, "=") {
			t.Errorf("%s = %q contains base64 padding", f.name, f.value)
		}
		if _, err := base64.RawURLEncoding.DecodeString(f.value); err != nil {
			t.Errorf("%s = %q is not unpadded base64url: %v", f.name, f.value, err)
		}
	}

	pub, err := wif.RSAPublicKey(cert)
	if err != nil {
		t.Fatalf("RSAPublicKey: %v", err)
	}
	gotN, err := base64.RawURLEncoding.DecodeString(jwk.N)
	if err != nil {
		t.Fatalf("decode n: %v", err)
	}
	if !reflect.DeepEqual(gotN, pub.N.Bytes()) {
		t.Fatalf("decoded n does not match the certificate modulus\n got %x\nwant %x", gotN, pub.N.Bytes())
	}
	gotE, err := base64.RawURLEncoding.DecodeString(jwk.E)
	if err != nil {
		t.Fatalf("decode e: %v", err)
	}
	if !reflect.DeepEqual(gotE, []byte{0x01, 0x00, 0x01}) {
		t.Fatalf("decoded e = %x, want 010001 (65537)", gotE)
	}
}

func TestBuildJWKSOrdersBySerial(t *testing.T) {
	certs := map[uint32]*x509.Certificate{
		serialC: loadCert(t, "cert-c.pem"),
		serialA: loadCert(t, "cert-a.pem"),
		serialB: loadCert(t, "cert-b.pem"),
	}
	configured := map[uint32]string{serialA: kidA, serialB: kidB, serialC: kidC}

	jwks, err := wif.BuildJWKS(certs, configured)
	if err != nil {
		t.Fatalf("BuildJWKS: %v", err)
	}
	if len(jwks.Keys) != 3 {
		t.Fatalf("got %d keys, want 3", len(jwks.Keys))
	}
	wantKids := []string{kidA, kidB, kidC}
	for i, want := range wantKids {
		if jwks.Keys[i].Kid != want {
			t.Errorf("key %d kid = %q, want %q", i, jwks.Keys[i].Kid, want)
		}
	}

	out, err := wif.MarshalJWKS(jwks)
	if err != nil {
		t.Fatalf("MarshalJWKS: %v", err)
	}
	if !json.Valid(out) {
		t.Fatalf("MarshalJWKS output is not valid JSON:\n%s", out)
	}
	if !strings.HasSuffix(string(out), "\n") {
		t.Errorf("MarshalJWKS output does not end with a newline")
	}
	if !strings.HasPrefix(string(out), "{\n  \"keys\": [\n") {
		t.Errorf("MarshalJWKS output is not two-space indented:\n%s", out)
	}
	var round wif.JWKS
	if err := json.Unmarshal(out, &round); err != nil {
		t.Fatalf("unmarshal MarshalJWKS output: %v", err)
	}
	if !reflect.DeepEqual(round, jwks) {
		t.Fatalf("round trip changed the key set\n got %+v\nwant %+v", round, jwks)
	}
}

func TestBuildJWKSErrors(t *testing.T) {
	certA := loadCert(t, "cert-a.pem")
	certB := loadCert(t, "cert-b.pem")

	tooMany := map[uint32]*x509.Certificate{}
	for serial := uint32(1); serial <= 9; serial++ {
		tooMany[serial] = certA
	}

	tests := []struct {
		name       string
		certs      map[uint32]*x509.Certificate
		configured map[uint32]string
		want       []string
	}{
		{
			// The documented bootstrap path: the operator reads the derived
			// kid straight out of this error and pastes it into config.
			name:       "serial not configured",
			certs:      map[uint32]*x509.Certificate{serialA: certA},
			configured: map[uint32]string{},
			want:       []string{"not configured", "12345678", kidA},
		},
		{
			name:       "configured kid differs",
			certs:      map[uint32]*x509.Certificate{serialA: certA},
			configured: map[uint32]string{serialA: kidB},
			want:       []string{kidA, kidB},
		},
		{
			name:       "configured serial has no certificate",
			certs:      map[uint32]*x509.Certificate{serialA: certA},
			configured: map[uint32]string{serialA: kidA, serialB: kidB},
			want:       []string{"revoke", "23456789"},
		},
		{
			name:       "same key under two serials",
			certs:      map[uint32]*x509.Certificate{serialA: certA, serialB: certA},
			configured: map[uint32]string{serialA: kidA, serialB: kidA},
			want:       []string{"same public key", "12345678", "23456789"},
		},
		{
			name:       "more keys than google accepts",
			certs:      tooMany,
			configured: map[uint32]string{},
			want:       []string{"exceed the Google limit", "9 certificates"},
		},
		{
			name:       "no certificates",
			certs:      map[uint32]*x509.Certificate{},
			configured: map[uint32]string{serialA: kidA},
			want:       []string{"at least one certificate"},
		},
		{
			name:       "wrong key shape names the serial",
			certs:      map[uint32]*x509.Certificate{serialA: loadCert(t, "cert-rsa1024.pem")},
			configured: map[uint32]string{serialA: kidA},
			want:       []string{"12345678", "1024 bits"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			jwks, err := wif.BuildJWKS(tc.certs, tc.configured)
			if len(jwks.Keys) != 0 {
				t.Fatalf("expected an empty key set on failure, got %d keys", len(jwks.Keys))
			}
			requireErrorContains(t, err, tc.want...)
		})
	}

	// Guard the arrangement the "same key" case depends on: cert-b really is
	// a different key, so that case fails on duplication and nothing else.
	if kidOfB, err := wif.CertificateKeyID(certB); err != nil || kidOfB == kidA {
		t.Fatalf("fixture precondition broken: cert-b kid %q err %v", kidOfB, err)
	}
}
