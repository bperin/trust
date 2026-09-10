package x509util_test

import (
	"bytes"
	"crypto"
	stdecdsa "crypto/ecdsa"
	stded25519 "crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	stdrsa "crypto/rsa"
	"crypto/subtle"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"errors"
	"math/big"
	"os"
	"testing"
	"time"

	"github.com/bperin/trust/crypto/ecdsa"
	"github.com/bperin/trust/crypto/ed25519"
	"github.com/bperin/trust/crypto/rsa"
	x509util "github.com/bperin/trust/identity/x509"
)

// Vector: [RFC 5280] Appendix C.1 — RSA self-signed CA certificate
// (cn=Example CA,dc=example,dc=com, serial 17, 1024-bit RSA, valid
// 2004-04-30 to 2005-04-30). The identical DER object is distributed by
// NIST PKI Testing as rfc5280_cert1.cer.
const rfc5280C1 = "MIICPjCCAaegAwIBAgIBETANBgkqhkiG9w0BAQUFADBDMRMwEQYKCZImiZPyLGQBGRYDY29tMRcw" +
	"FQYKCZImiZPyLGQBGRYHZXhhbXBsZTETMBEGA1UEAxMKRXhhbXBsZSBDQTAeFw0wNDA0MzAxNDI1" +
	"MzRaFw0wNTA0MzAxNDI1MzRaMEMxEzARBgoJkiaJk/IsZAEZFgNjb20xFzAVBgoJkiaJk/IsZAEZ" +
	"FgdleGFtcGxlMRMwEQYDVQQDEwpFeGFtcGxlIENBMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKB" +
	"gQDC15dtKHCqW88jLoBwOe7bb9Ut1WpPejQt+SJyR3Ad74DpyjCMAMSabltFtG6l5myUDfqR6UD8" +
	"JZ3Ht2gZVo8RcGrX8ckRTzp+P5mNbnaldF9epFVT5cdoNlPHHTsSpoX+vW6hyt81UKwI17m0flz+" +
	"4qMs0SOEqpjAm2YYmmhH6QIDAQABo0IwQDAdBgNVHQ4EFgQUCGivhTPIOUp6+IKTjnBqSiCELDIw" +
	"DgYDVR0PAQH/BAQDAgEGMA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQEFBQADgYEAbPgCdKZh" +
	"4mQEplQMbHITrTxH+/ZlE6mFkDPqdqMm2fzRDhVfKLfvk7888+I+fLlS/BZuKarh9Hpv1X/vs5XK" +
	"82aIg06hNUWEy7ybuMitxV5G2QsOjYDhMyvcviuSfkpDqWrvimNhs25HOL7oDaNnXfP6kYE8krvF" +
	"XyUl63zn2KE="

// Vector: [RFC 5280] Appendix C.2 — RSA end-entity certificate
// (cn=End Entity,dc=example,dc=com, serial 18, 1024-bit RSA, valid
// 2004-09-15 to 2005-03-15, rfc822 SAN end.entity@example.com, issued
// by the C.1 CA). Distributed by NIST PKI Testing as rfc5280_cert2.cer.
const rfc5280C2 = "MIICcTCCAdqgAwIBAgIBEjANBgkqhkiG9w0BAQUFADBDMRMwEQYKCZImiZPyLGQBGRYDY29tMRcw" +
	"FQYKCZImiZPyLGQBGRYHZXhhbXBsZTETMBEGA1UEAxMKRXhhbXBsZSBDQTAeFw0wNDA5MTUxMTQ4" +
	"MjFaFw0wNTAzMTUxMTQ4MjFaMEMxEzARBgoJkiaJk/IsZAEZFgNjb20xFzAVBgoJkiaJk/IsZAEZ" +
	"FgdleGFtcGxlMRMwEQYDVQQDEwpFbmQgRW50aXR5MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKB" +
	"gQDhauQDMJcCPPQQ87UeTX8Ue/b10HjppIrwo3Xs7bZWln+ImYWa8j5od4frntGfwLQX3KuJI6Qd" +
	"fhYjTE+oTfUxuHyq4xpJCfRLJtsnZzCCEgFK6Rq2wQxTi2z8L3pD7DM2fjKye9WqzwEUxhLsE/It" +
	"FHqLIVgUE0xGo5ryFpX/IwIDAQABo3UwczAhBgNVHREEGjAYgRZlbmQuZW50aXR5QGV4YW1wbGUu" +
	"Y29tMB0GA1UdDgQWBBQXe5Iw/0TWZuGQECJsFk/AjkHdbTAfBgNVHSMEGDAWgBQIaK+FM8g5Snr4" +
	"gpOOcGpKIIQsMjAOBgNVHQ8BAf8EBAMCBsAwDQYJKoZIhvcNAQEFBQADgYEAACAoNFtoMgG7CjYO" +
	"rXHFlRrhBM+urcdiFKQbNjHA4gw92R7AANwQoLqFb0HLYnq3TGOBJl7SgEVeM+dwRTs5OyZKnDvyJ" +
	"jZpCHm7+5ZDd0thi6GrkWTg8zdhPBqjpMmKsr9z1E3kWORi6rwgdJKGDs6EYHbpc7vHhdORRepiXc" +
	"0="

// Vector: [RFC 5280] Appendix C.3 — DSA end-entity certificate
// (cn=DSA End Entity,dc=example,dc=com, serial 256, DSA with SHA-1).
// Not part of the minimal certification path. Distributed by NIST PKI
// Testing as rfc5280_cert3.cer.
const rfc5280C3 = "MIIDjjCCA06gAwIBAgICAQAwCQYHKoZIzjgEAzBHMRMwEQYKCZImiZPyLGQBGRYDY29tMRcw" +
	"FQYKCZImiZPyLGQBGRYHZXhhbXBsZTEXMBUGA1UEAxMORXhhbXBsZSBEU0EgQ0EwHhcNMDQwNTAy" +
	"MTY0NzM4WhcNMDUwNTAyMTY0NzM4WjBHMRMwEQYKCZImiZPyLGQBGRYDY29tMRcwFQYKCZImiZPy" +
	"LGQBGRYHZXhhbXBsZTEXMBUGA1UEAxMORFNBIEVuZCBFbnRpdHkwggG3MIIBLAYHKoZIzjgEATCC" +
	"AR8CgYEAtosPlCuazqUlxvLt/PuVMqwBEjO54BytkJu8SFSe85R3PCxxNVXm/k8iy9XYPomTM038v" +
	"U9BZD6imHDsMbRQ3uvxmCgKyT5Es/0il5aD0Bij4701W//uoyFyanuW2rk/HlqQryTWIPANIafUAr" +
	"ka/Kwh+56UnktCRZ5qskhj/kMCFQCyDbCxAd8MZiT8E5K6Vfd9V3SB5QKBgQCav0ax9T9EPcmlZfu" +
	"RwI5H8QrDAUfCREI2qZKB3lfF4GiGWAB7H/mbd6HFEKWAkXhRUTz2/PzMRsaBeJKEPfSTPQw4fhpb" +
	"mU6rFGT2DCEiTigInJK5Zp9A6JX21TEq7zmiYseybZ5YxDqoEYGEba/4tBm0whGu0CI7qiB/7h5XG" +
	"AOBhAACgYAwtnX3fCAxrji7fg0rq6CcS98g1SQTPM2Y5V9st8G6SrqplYBT8A1y3DM39AEL9QQfnS" +
	"4fYtiEOpslCVotyEaOK9T1DTvHLcZsuZjBJTpETo7KlWE1fM4VMVwjEx6iBdF6JBzL03IJkP+bnSj" +
	"AoQrsRp8NuNDc0BimK175j7WVvqOByjCBxzA5BgNVHREEMjAwhi5odHRwOi8vd3d3LmV4YW1wbGUu" +
	"Y29tL3VzZXJzL0RTQWVuZGVudGl0eS5odG1sMCEGA1UdEgQaMBiGFmh0dHA6Ly93d3cuZXhhbXBs" +
	"ZS5jb20wHQYDVR0OBBYEFN0lZpZDq3gRQ0T+lRb52ba3AmaNMB8GA1UdIwQYMBaAFIbKpSKBYu+t" +
	"Com8rXJBLClJ9IZWMBcGA1UdIAQQMA4wDAYKYIZIAWUDAgEwCTAOBgNVHQ8BAf8EBAMCB4AwCQYH" +
	"KoZIzjgEAwMvADAsAhRlVwc03dzKzF70AvRWQixe4bM7gAIUYPQxF8r0z//u9Ain2bJhvrHD2r8="

// Vector: [RFC 5280] Appendix C.4 — CRL issued by the C.1 CA
// (cn=Example CA,dc=example,dc=com), revoking serial 18 (the C.2
// certificate) for key compromise, thisUpdate 2005-02-05 12:00:00 UTC,
// nextUpdate 2005-02-06 12:00:00 UTC. Distributed by NIST PKI Testing
// as rfc5280_CRL.crl.
const rfc5280C4 = "MIIBYDCBygIBATANBgkqhkiG9w0BAQUFADBDMRMwEQYKCZImiZPyLGQBGRYDY29tMRcw" +
	"FQYKCZImiZPyLGQBGRYHZXhhbXBsZTETMBEGA1UEAxMKRXhhbXBsZSBDQRcNMDUwMjA1MTIwMDAw" +
	"WhcNMDUwMjA2MTIwMDAwWjAiMCACARIXDTA0MTExOTE1NTcwM1owDDAKBgNVHRUEAwoBAaAvMC0w" +
	"HwYDVR0jBBgwFoAUCGivhTPIOUp6+IKTjnBqSiCELDIwCgYDVR0UBAMCAQwwDQYJKoZIhvcNAQEF" +
	"BQADgYEAItwYffcIzsx10NBqm60Q9HYjtIFutW2+DvsVFGzIF20f7pAXom9g5L2qjFXejoRvkvif" +
	"EBInr0rUL4XiNkR9qqNMJTgV/wD9Pn7uPSYS69jnK2LiK8NGgO94gtEVxtCccmrLznrtZ5mLbnCB" +
	"fUNCdMGmr8FVF6IzTNYGmCuk/C4="

// mustDER decodes a base64 DER fixture.
func mustDER(t *testing.T, b64 string) []byte {
	t.Helper()
	der, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		t.Fatalf("base64 decode fixture: %v", err)
	}
	return der
}

// mustParse parses a base64 DER fixture into a Certificate.
func mustParse(t *testing.T, b64 string) *x509util.Certificate {
	t.Helper()
	cert, err := x509util.ParseCertificate(mustDER(t, b64))
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}
	return cert
}

// mustStdParse parses a base64 DER fixture with the standard library,
// for building root pools in tests.
func mustStdParse(t *testing.T, b64 string) *x509.Certificate {
	t.Helper()
	cert, err := x509.ParseCertificate(mustDER(t, b64))
	if err != nil {
		t.Fatalf("x509.ParseCertificate: %v", err)
	}
	return cert
}

// testCA is a generated CA for path-validation tests. Certificates are
// generated with the standard library (the package under test only
// consumes certificates) using crypto/rand.
type testCA struct {
	cert *x509.Certificate
	key  crypto.Signer
}

// newTestCA generates a self-signed CA certificate for the given key.
func newTestCA(t *testing.T, key crypto.Signer, commonName string) *testCA {
	t.Helper()
	tpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: commonName},
		NotBefore:             time.Now().Add(-24 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, key.Public(), key)
	if err != nil {
		t.Fatalf("CreateCertificate CA: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("ParseCertificate CA: %v", err)
	}
	return &testCA{cert: cert, key: key}
}

// issue generates an end-entity certificate carrying pub as its subject
// public key, signed by the CA. sigAlg 0 lets the standard library
// choose.
func (ca *testCA) issue(t *testing.T, pub crypto.PublicKey, serial int64, notBefore, notAfter time.Time, eku []x509.ExtKeyUsage, sigAlg x509.SignatureAlgorithm) *x509.Certificate {
	t.Helper()
	tpl := &x509.Certificate{
		SerialNumber:       big.NewInt(serial),
		Subject:            pkix.Name{CommonName: "leaf"},
		NotBefore:          notBefore,
		NotAfter:           notAfter,
		KeyUsage:           x509.KeyUsageDigitalSignature,
		ExtKeyUsage:        eku,
		SignatureAlgorithm: sigAlg,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, ca.cert, pub, ca.key)
	if err != nil {
		t.Fatalf("CreateCertificate leaf: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("ParseCertificate leaf: %v", err)
	}
	return cert
}

// newTestCRL generates and parses a CRL issued by the CA revoking the
// given serials.
func newTestCRL(t *testing.T, ca *testCA, revokedSerials []*big.Int, thisUpdate, nextUpdate time.Time) *x509.RevocationList {
	t.Helper()
	entries := make([]x509.RevocationListEntry, len(revokedSerials))
	for i, serial := range revokedSerials {
		entries[i] = x509.RevocationListEntry{SerialNumber: serial, RevocationTime: thisUpdate}
	}
	der, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		Number:                    big.NewInt(1),
		ThisUpdate:                thisUpdate,
		NextUpdate:                nextUpdate,
		RevokedCertificateEntries: entries,
	}, ca.cert, ca.key)
	if err != nil {
		t.Fatalf("CreateRevocationList: %v", err)
	}
	crl, err := x509.ParseRevocationList(der)
	if err != nil {
		t.Fatalf("ParseRevocationList: %v", err)
	}
	return crl
}

// wrap converts a stdlib certificate to the wrapper type.
func wrap(t *testing.T, cert *x509.Certificate) *x509util.Certificate {
	t.Helper()
	w, err := x509util.ParseCertificate(cert.Raw)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}
	return w
}

// pool builds a root pool from stdlib certificates.
func pool(certs ...*x509.Certificate) *x509.CertPool {
	p := x509.NewCertPool()
	for _, c := range certs {
		p.AddCert(c)
	}
	return p
}

// TestParseCertificateRFC5280 parses the [RFC 5280] Appendix C.1 and
// C.2 RSA certificates and checks the exposed metadata against the
// values stated in the RFC text.
func TestParseCertificateRFC5280(t *testing.T) {
	tests := []struct {
		name      string
		fixture   string
		common    string
		issuer    string
		serial    int64
		notBefore time.Time
		notAfter  time.Time
		keyUsage  x509.KeyUsage
		isCA      bool
		rawLen    int
		extsLen   int
	}{
		{
			name:      "C.1 RSA self-signed CA",
			fixture:   rfc5280C1,
			common:    "Example CA",
			issuer:    "Example CA",
			serial:    17,
			notBefore: time.Date(2004, 4, 30, 14, 25, 34, 0, time.UTC),
			notAfter:  time.Date(2005, 4, 30, 14, 25, 34, 0, time.UTC),
			keyUsage:  x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
			isCA:      true,
			rawLen:    578,
			extsLen:   3,
		},
		{
			name:      "C.2 RSA end entity",
			fixture:   rfc5280C2,
			common:    "End Entity",
			issuer:    "Example CA",
			serial:    18,
			notBefore: time.Date(2004, 9, 15, 11, 48, 21, 0, time.UTC),
			notAfter:  time.Date(2005, 3, 15, 11, 48, 21, 0, time.UTC),
			keyUsage:  x509.KeyUsageDigitalSignature | x509.KeyUsageContentCommitment,
			isCA:      false,
			rawLen:    629,
			extsLen:   4,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cert := mustParse(t, tt.fixture)
			if got := cert.Subject().CommonName; got != tt.common {
				t.Errorf("Subject().CommonName: got %q, want %q", got, tt.common)
			}
			if got := cert.Issuer().CommonName; got != tt.issuer {
				t.Errorf("Issuer().CommonName: got %q, want %q", got, tt.issuer)
			}
			if got := cert.SerialNumber().Int64(); got != tt.serial {
				t.Errorf("SerialNumber: got %d, want %d", got, tt.serial)
			}
			if got, want := cert.NotBefore().UTC(), tt.notBefore; !got.Equal(want) {
				t.Errorf("NotBefore: got %s, want %s", got, want)
			}
			if got, want := cert.NotAfter().UTC(), tt.notAfter; !got.Equal(want) {
				t.Errorf("NotAfter: got %s, want %s", got, want)
			}
			if got := cert.KeyUsage(); got != tt.keyUsage {
				t.Errorf("KeyUsage: got %d, want %d", got, tt.keyUsage)
			}
			if got := cert.IsCA(); got != tt.isCA {
				t.Errorf("IsCA: got %v, want %v", got, tt.isCA)
			}
			if got := len(cert.Raw()); got != tt.rawLen {
				t.Errorf("len(Raw): got %d, want %d", got, tt.rawLen)
			}
			if got := len(cert.Extensions()); got != tt.extsLen {
				t.Errorf("len(Extensions): got %d, want %d", got, tt.extsLen)
			}
			if got := cert.PublicKeyAlgorithm(); got != x509.RSA {
				t.Errorf("PublicKeyAlgorithm: got %v, want RSA", got)
			}
			if got := cert.SignatureAlgorithm(); got != x509.SHA1WithRSA {
				t.Errorf("SignatureAlgorithm: got %v, want SHA1WithRSA", got)
			}
			if got := len(cert.ExtKeyUsage()); got != 0 {
				t.Errorf("len(ExtKeyUsage): got %d, want 0 (unrestricted)", got)
			}
		})
	}
}

// TestParseCertificateMalformed covers boundary and malformed inputs.
func TestParseCertificateMalformed(t *testing.T) {
	c2 := mustDER(t, rfc5280C2)
	tests := []struct {
		name    string
		der     []byte
		wantErr error
	}{
		{name: "nil input", der: nil, wantErr: x509util.ErrEmptyInput},
		{name: "empty input", der: []byte{}, wantErr: x509util.ErrEmptyInput},
		{name: "garbage bytes", der: bytes.Repeat([]byte{0x41}, 64), wantErr: x509util.ErrMalformedCertificate},
		{name: "single byte", der: []byte{0x30}, wantErr: x509util.ErrMalformedCertificate},
		{name: "truncated C.2", der: c2[:100], wantErr: x509util.ErrMalformedCertificate},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := x509util.ParseCertificate(tt.der)
			if err == nil {
				t.Fatalf("ParseCertificate(%q): got nil error, want %v", tt.name, tt.wantErr)
			}
			if !errors.Is(err, tt.wantErr) {
				t.Errorf("ParseCertificate(%q): got %v, want errors.Is %v", tt.name, err, tt.wantErr)
			}
		})
	}
}

// TestParseCertificateUnsupportedAlgorithm verifies the [RFC 5280]
// Appendix C.3 DSA certificate is rejected as an unsupported public-key
// type.
func TestParseCertificateUnsupportedAlgorithm(t *testing.T) {
	_, err := x509util.ParseCertificate(mustDER(t, rfc5280C3))
	if err == nil {
		t.Fatal("ParseCertificate(C.3 DSA): got nil error, want ErrUnsupportedPublicKeyAlgorithm")
	}
	if !errors.Is(err, x509util.ErrUnsupportedPublicKeyAlgorithm) {
		t.Errorf("ParseCertificate(C.3 DSA): got %v, want errors.Is ErrUnsupportedPublicKeyAlgorithm", err)
	}
}

// TestPublicKeyRFC5280Policy verifies that the legacy [RFC 5280]
// Appendix C samples parse but PublicKey refuses to mint a trust
// wrapper: the certificates carry 1024-bit RSA keys, below the
// platform's 2048-bit minimum enforced by the trust constructors. This
// is deliberate fail-closed behavior, not a parsing failure.
func TestPublicKeyRFC5280Policy(t *testing.T) {
	tests := []struct {
		name string
		b64  string
	}{
		{name: "C.1 RSA self-signed CA", b64: rfc5280C1},
		{name: "C.2 RSA end entity", b64: rfc5280C2},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cert := mustParse(t, tt.b64)
			_, err := x509util.PublicKey(cert)
			if err == nil {
				t.Fatal("PublicKey: got nil error, want ErrKeyTooSmall for 1024-bit RSA")
			}
			if !errors.Is(err, rsa.ErrKeyTooSmall) {
				t.Errorf("PublicKey: got %v, want errors.Is rsa.ErrKeyTooSmall", err)
			}
		})
	}
}

// TestPublicKeyWrapperTypes verifies PublicKey returns the concrete
// trust wrapper types for certificates that meet the platform key
// policy, with the scheme, hash, and key material derived correctly.
func TestPublicKeyWrapperTypes(t *testing.T) {
	notBefore := time.Now().Add(-time.Hour)
	notAfter := time.Now().Add(time.Hour)

	t.Run("RSA PKCS1v1.5 SHA-256", func(t *testing.T) {
		key, err := stdrsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatalf("GenerateKey: %v", err)
		}
		ca := newTestCA(t, key, "RSA CA")
		leaf := ca.issue(t, key.Public(), 2, notBefore, notAfter, nil, x509.SHA256WithRSA)
		got, err := wrap(t, leaf).PublicKey()
		if err != nil {
			t.Fatalf("PublicKey: %v", err)
		}
		pub, ok := got.(*rsa.PKCS1PublicKey)
		if !ok {
			t.Fatalf("PublicKey: got %T, want *rsa.PKCS1PublicKey", got)
		}
		if pub.Hash() != crypto.SHA256 {
			t.Errorf("Hash: got %v, want SHA-256", pub.Hash())
		}
		if pub.E() != key.E {
			t.Errorf("E: got %d, want %d", pub.E(), key.E)
		}
		if subtle.ConstantTimeCompare(pub.N().Bytes(), key.N.Bytes()) != 1 {
			t.Errorf("N: got %x, want %x", pub.N().Bytes(), key.N.Bytes())
		}
	})

	t.Run("RSA PSS SHA-256", func(t *testing.T) {
		key, err := stdrsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatalf("GenerateKey: %v", err)
		}
		ca := newTestCA(t, key, "PSS CA")
		leaf := ca.issue(t, key.Public(), 3, notBefore, notAfter, nil, x509.SHA256WithRSAPSS)
		got, err := wrap(t, leaf).PublicKey()
		if err != nil {
			t.Fatalf("PublicKey: %v", err)
		}
		pub, ok := got.(*rsa.PSSPublicKey)
		if !ok {
			t.Fatalf("PublicKey: got %T, want *rsa.PSSPublicKey", got)
		}
		if pub.Hash() != crypto.SHA256 {
			t.Errorf("Hash: got %v, want SHA-256", pub.Hash())
		}
	})

	t.Run("RSA SHA-1 rejected by hash policy", func(t *testing.T) {
		key, err := stdrsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatalf("GenerateKey: %v", err)
		}
		ca := newTestCA(t, key, "legacy CA")
		leaf := ca.issue(t, key.Public(), 4, notBefore, notAfter, nil, x509.SHA1WithRSA)
		_, err = wrap(t, leaf).PublicKey()
		if !errors.Is(err, rsa.ErrUnsupportedHash) {
			t.Errorf("PublicKey: got %v, want errors.Is rsa.ErrUnsupportedHash", err)
		}
	})

	t.Run("RSA key with non-RSA signature algorithm", func(t *testing.T) {
		_, edPriv, err := stded25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatalf("GenerateKey: %v", err)
		}
		ca := newTestCA(t, edPriv, "Ed CA")
		// RSA subject key, Ed25519 issuer signature: no in-band RSA
		// scheme hint exists.
		rsaKey, err := stdrsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatalf("GenerateKey: %v", err)
		}
		leaf := ca.issue(t, &rsaKey.PublicKey, 5, notBefore, notAfter, nil, 0)
		_, err = wrap(t, leaf).PublicKey()
		if !errors.Is(err, x509util.ErrUnsupportedSignatureAlgorithm) {
			t.Errorf("PublicKey: got %v, want errors.Is ErrUnsupportedSignatureAlgorithm", err)
		}
	})

	t.Run("ECDSA P-256", func(t *testing.T) {
		caKey, err := stdrsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatalf("GenerateKey: %v", err)
		}
		ca := newTestCA(t, caKey, "EC CA")
		ecKey, err := stdecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("GenerateKey: %v", err)
		}
		leaf := ca.issue(t, &ecKey.PublicKey, 6, notBefore, notAfter, nil, 0)
		got, err := wrap(t, leaf).PublicKey()
		if err != nil {
			t.Fatalf("PublicKey: %v", err)
		}
		pub, ok := got.(*ecdsa.PublicKey)
		if !ok {
			t.Fatalf("PublicKey: got %T, want *ecdsa.PublicKey", got)
		}
		if pub.Curve() != elliptic.P256() {
			t.Errorf("Curve: got %v, want P-256", pub.Curve())
		}
		if pub.X().Cmp(ecKey.PublicKey.X) != 0 || pub.Y().Cmp(ecKey.PublicKey.Y) != 0 {
			t.Errorf("point: got (%s, %s), want (%s, %s)", pub.X(), pub.Y(), ecKey.PublicKey.X, ecKey.PublicKey.Y)
		}
	})

	t.Run("ECDSA P-521 curve rejected", func(t *testing.T) {
		caKey, err := stdrsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatalf("GenerateKey: %v", err)
		}
		ca := newTestCA(t, caKey, "EC CA")
		ecKey, err := stdecdsa.GenerateKey(elliptic.P521(), rand.Reader)
		if err != nil {
			t.Fatalf("GenerateKey: %v", err)
		}
		leaf := ca.issue(t, &ecKey.PublicKey, 7, notBefore, notAfter, nil, 0)
		_, err = wrap(t, leaf).PublicKey()
		if !errors.Is(err, ecdsa.ErrUnsupportedCurve) {
			t.Errorf("PublicKey: got %v, want errors.Is ecdsa.ErrUnsupportedCurve", err)
		}
	})

	t.Run("Ed25519", func(t *testing.T) {
		caKey, err := stdrsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatalf("GenerateKey: %v", err)
		}
		ca := newTestCA(t, caKey, "Ed CA")
		edPub, _, err := stded25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatalf("GenerateKey: %v", err)
		}
		leaf := ca.issue(t, edPub, 8, notBefore, notAfter, nil, 0)
		got, err := wrap(t, leaf).PublicKey()
		if err != nil {
			t.Fatalf("PublicKey: %v", err)
		}
		pub, ok := got.(*ed25519.PublicKey)
		if !ok {
			t.Fatalf("PublicKey: got %T, want *ed25519.PublicKey", got)
		}
		b := pub.Bytes()
		if subtle.ConstantTimeCompare(b[:], edPub) != 1 {
			t.Errorf("public key bytes: got %x, want %x", b[:], edPub)
		}
	})
}

// TestPublicKeyNil verifies PublicKey fails closed on nil and
// zero-value certificates instead of panicking.
func TestPublicKeyNil(t *testing.T) {
	if _, err := x509util.PublicKey(nil); !errors.Is(err, x509util.ErrNilCertificate) {
		t.Errorf("PublicKey(nil): got %v, want ErrNilCertificate", err)
	}
	var zero x509util.Certificate
	if _, err := zero.PublicKey(); !errors.Is(err, x509util.ErrNilCertificate) {
		t.Errorf("zero.PublicKey(): got %v, want ErrNilCertificate", err)
	}
}

// TestVerifyPathPositive validates generated chains against explicit
// roots: a direct leaf-under-CA path and a path through an
// intermediate.
func TestVerifyPathPositive(t *testing.T) {
	t.Run("leaf under root CA", func(t *testing.T) {
		key, err := stdrsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatalf("GenerateKey: %v", err)
		}
		ca := newTestCA(t, key, "root")
		leaf := ca.issue(t, key.Public(), 11, time.Now().Add(-time.Hour), time.Now().Add(time.Hour),
			[]x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, 0)
		err = x509util.VerifyPath([]*x509util.Certificate{wrap(t, leaf)}, pool(ca.cert), x509util.VerifyOptions{})
		if err != nil {
			t.Errorf("VerifyPath: got %v, want nil", err)
		}
	})

	t.Run("leaf through intermediate", func(t *testing.T) {
		rootKey, err := stdrsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatalf("GenerateKey: %v", err)
		}
		root := newTestCA(t, rootKey, "root")
		intKey, err := stdrsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatalf("GenerateKey: %v", err)
		}
		intDER, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
			SerialNumber:          big.NewInt(2),
			Subject:               pkix.Name{CommonName: "intermediate"},
			NotBefore:             time.Now().Add(-time.Hour),
			NotAfter:              time.Now().Add(24 * time.Hour),
			KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
			BasicConstraintsValid: true,
			IsCA:                  true,
		}, root.cert, intKey.Public(), root.key)
		if err != nil {
			t.Fatalf("CreateCertificate intermediate: %v", err)
		}
		intCert, err := x509.ParseCertificate(intDER)
		if err != nil {
			t.Fatalf("ParseCertificate intermediate: %v", err)
		}
		leafKey, err := stdrsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatalf("GenerateKey: %v", err)
		}
		leafDER, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
			SerialNumber: big.NewInt(12),
			Subject:      pkix.Name{CommonName: "leaf"},
			NotBefore:    time.Now().Add(-time.Hour),
			NotAfter:     time.Now().Add(time.Hour),
			KeyUsage:     x509.KeyUsageDigitalSignature,
		}, intCert, leafKey.Public(), intKey)
		if err != nil {
			t.Fatalf("CreateCertificate leaf: %v", err)
		}
		leafCert, err := x509.ParseCertificate(leafDER)
		if err != nil {
			t.Fatalf("ParseCertificate leaf: %v", err)
		}
		err = x509util.VerifyPath(
			[]*x509util.Certificate{wrap(t, leafCert)},
			pool(root.cert),
			x509util.VerifyOptions{Intermediates: []*x509util.Certificate{wrap(t, intCert)}},
		)
		if err != nil {
			t.Errorf("VerifyPath: got %v, want nil", err)
		}
	})
}

// TestVerifyPathNegative covers the path-validation failure modes:
// unknown authority, expiry, wrong EKU, misconfiguration, and tampered
// signatures. Standard library error types must survive wrapping.
func TestVerifyPathNegative(t *testing.T) {
	t.Run("self-signed without matching root", func(t *testing.T) {
		key, err := stdrsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatalf("GenerateKey: %v", err)
		}
		otherKey, err := stdrsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatalf("GenerateKey: %v", err)
		}
		trusted := newTestCA(t, key, "trusted CA")
		other := newTestCA(t, otherKey, "other CA")
		err = x509util.VerifyPath([]*x509util.Certificate{wrap(t, other.cert)}, pool(trusted.cert), x509util.VerifyOptions{})
		if err == nil {
			t.Fatal("VerifyPath: got nil error, want unknown authority")
		}
		var unknown x509.UnknownAuthorityError
		if !errors.As(err, &unknown) {
			t.Errorf("VerifyPath: got %v, want errors.As x509.UnknownAuthorityError", err)
		}
	})

	t.Run("expired leaf", func(t *testing.T) {
		key, err := stdrsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatalf("GenerateKey: %v", err)
		}
		ca := newTestCA(t, key, "exp CA")
		leaf := ca.issue(t, key.Public(), 13, time.Now().Add(-2*time.Hour), time.Now().Add(-time.Hour), nil, 0)
		err = x509util.VerifyPath([]*x509util.Certificate{wrap(t, leaf)}, pool(ca.cert), x509util.VerifyOptions{})
		var inval x509.CertificateInvalidError
		if !errors.As(err, &inval) {
			t.Fatalf("VerifyPath: got %v, want errors.As x509.CertificateInvalidError", err)
		}
		if inval.Reason != x509.Expired {
			t.Errorf("reason: got %v, want Expired", inval.Reason)
		}
	})

	t.Run("wrong EKU", func(t *testing.T) {
		key, err := stdrsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatalf("GenerateKey: %v", err)
		}
		ca := newTestCA(t, key, "eku CA")
		leaf := ca.issue(t, key.Public(), 14, time.Now().Add(-time.Hour), time.Now().Add(time.Hour),
			[]x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, 0)
		err = x509util.VerifyPath(
			[]*x509util.Certificate{wrap(t, leaf)},
			pool(ca.cert),
			x509util.VerifyOptions{KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}},
		)
		var inval x509.CertificateInvalidError
		if !errors.As(err, &inval) {
			t.Fatalf("VerifyPath: got %v, want errors.As x509.CertificateInvalidError", err)
		}
		if inval.Reason != x509.IncompatibleUsage {
			t.Errorf("reason: got %v, want IncompatibleUsage", inval.Reason)
		}
	})

	t.Run("tampered leaf signature", func(t *testing.T) {
		key, err := stdrsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatalf("GenerateKey: %v", err)
		}
		ca := newTestCA(t, key, "tamper CA")
		leaf := ca.issue(t, key.Public(), 15, time.Now().Add(-time.Hour), time.Now().Add(time.Hour), nil, 0)
		der := append([]byte(nil), leaf.Raw...)
		der[len(der)-1] ^= 0xFF
		w, err := x509util.ParseCertificate(der)
		if err != nil {
			t.Fatalf("ParseCertificate tampered: %v", err)
		}
		err = x509util.VerifyPath([]*x509util.Certificate{w}, pool(ca.cert), x509util.VerifyOptions{})
		if err == nil {
			t.Fatal("VerifyPath: got nil error, want signature failure")
		}
		var unknown x509.UnknownAuthorityError
		if !errors.As(err, &unknown) {
			t.Errorf("VerifyPath: got %v, want errors.As x509.UnknownAuthorityError", err)
		}
	})

	t.Run("nil roots", func(t *testing.T) {
		ca := mustStdParse(t, rfc5280C1)
		err := x509util.VerifyPath([]*x509util.Certificate{wrap(t, ca)}, nil, x509util.VerifyOptions{})
		if !errors.Is(err, x509util.ErrNilRoots) {
			t.Errorf("VerifyPath: got %v, want ErrNilRoots", err)
		}
	})

	t.Run("empty chain", func(t *testing.T) {
		ca := mustStdParse(t, rfc5280C1)
		err := x509util.VerifyPath(nil, pool(ca), x509util.VerifyOptions{})
		if !errors.Is(err, x509util.ErrEmptyChain) {
			t.Errorf("VerifyPath: got %v, want ErrEmptyChain", err)
		}
	})

	t.Run("nil certificate in chain", func(t *testing.T) {
		ca := mustStdParse(t, rfc5280C1)
		err := x509util.VerifyPath([]*x509util.Certificate{nil}, pool(ca), x509util.VerifyOptions{})
		if !errors.Is(err, x509util.ErrNilCertificate) {
			t.Errorf("VerifyPath: got %v, want ErrNilCertificate", err)
		}
	})

	t.Run("zero-value certificate in intermediates", func(t *testing.T) {
		ca := mustStdParse(t, rfc5280C1)
		leaf := mustStdParse(t, rfc5280C2)
		err := x509util.VerifyPath(
			[]*x509util.Certificate{wrap(t, leaf)},
			pool(ca),
			x509util.VerifyOptions{Intermediates: []*x509util.Certificate{{}}},
		)
		if !errors.Is(err, x509util.ErrNilCertificate) {
			t.Errorf("VerifyPath: got %v, want ErrNilCertificate", err)
		}
	})
}

// TestVerifyPathSHA1ChainRejected verifies that the [RFC 5280] C.2
// under C.1 chain — signed with SHA-1 — is rejected by path validation.
// Modern Go rejects SHA-1 signatures in certification paths as
// insecure, so the 2004-era sample vectors cannot form a valid path
// today; they remain valid parsing and policy vectors.
func TestVerifyPathSHA1ChainRejected(t *testing.T) {
	ca := mustStdParse(t, rfc5280C1)
	leaf := mustParse(t, rfc5280C2)
	err := x509util.VerifyPath(
		[]*x509util.Certificate{leaf},
		pool(ca),
		x509util.VerifyOptions{CurrentTime: time.Date(2005, 1, 1, 0, 0, 0, 0, time.UTC)},
	)
	if err == nil {
		t.Fatal("VerifyPath: got nil error, want SHA-1 rejection")
	}
}

// TestVerifyPathCRL covers caller-supplied revocation lists: revoked
// serials, clean lists, stale windows, unauthenticated issuers, and
// tampered CRL signatures.
func TestVerifyPathCRL(t *testing.T) {
	caKey, err := stdrsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	ca := newTestCA(t, caKey, "crl CA")
	leaf := ca.issue(t, caKey.Public(), 42, time.Now().Add(-time.Hour), time.Now().Add(time.Hour), nil, 0)
	wrapped := wrap(t, leaf)
	thisUpdate := time.Now().Add(-time.Minute)
	nextUpdate := time.Now().Add(time.Hour)

	t.Run("revoked leaf", func(t *testing.T) {
		crl := newTestCRL(t, ca, []*big.Int{big.NewInt(42)}, thisUpdate, nextUpdate)
		err := x509util.VerifyPath([]*x509util.Certificate{wrapped}, pool(ca.cert),
			x509util.VerifyOptions{CRLs: []*x509.RevocationList{crl}})
		if !errors.Is(err, x509util.ErrCertificateRevoked) {
			t.Errorf("VerifyPath: got %v, want errors.Is ErrCertificateRevoked", err)
		}
	})

	t.Run("clean leaf", func(t *testing.T) {
		crl := newTestCRL(t, ca, []*big.Int{big.NewInt(999)}, thisUpdate, nextUpdate)
		err := x509util.VerifyPath([]*x509util.Certificate{wrapped}, pool(ca.cert),
			x509util.VerifyOptions{CRLs: []*x509.RevocationList{crl}})
		if err != nil {
			t.Errorf("VerifyPath: got %v, want nil", err)
		}
	})

	t.Run("stale CRL window", func(t *testing.T) {
		crl := newTestCRL(t, ca, nil, time.Now().Add(-2*time.Hour), time.Now().Add(-time.Hour))
		err := x509util.VerifyPath([]*x509util.Certificate{wrapped}, pool(ca.cert),
			x509util.VerifyOptions{CRLs: []*x509.RevocationList{crl}})
		if !errors.Is(err, x509util.ErrCRLOutsideValidity) {
			t.Errorf("VerifyPath: got %v, want errors.Is ErrCRLOutsideValidity", err)
		}
	})

	t.Run("CRL issuer not in path", func(t *testing.T) {
		otherKey, err := stdrsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatalf("GenerateKey: %v", err)
		}
		other := newTestCA(t, otherKey, "other CA")
		crl := newTestCRL(t, other, []*big.Int{big.NewInt(42)}, thisUpdate, nextUpdate)
		err = x509util.VerifyPath([]*x509util.Certificate{wrapped}, pool(ca.cert),
			x509util.VerifyOptions{CRLs: []*x509.RevocationList{crl}})
		if !errors.Is(err, x509util.ErrCRLIssuerNotFound) {
			t.Errorf("VerifyPath: got %v, want errors.Is ErrCRLIssuerNotFound", err)
		}
	})

	t.Run("tampered CRL signature", func(t *testing.T) {
		crl := newTestCRL(t, ca, []*big.Int{big.NewInt(42)}, thisUpdate, nextUpdate)
		der := append([]byte(nil), crl.Raw...)
		der[len(der)-1] ^= 0xFF
		tampered, err := x509.ParseRevocationList(der)
		if err != nil {
			t.Fatalf("ParseRevocationList tampered: %v", err)
		}
		err = x509util.VerifyPath([]*x509util.Certificate{wrapped}, pool(ca.cert),
			x509util.VerifyOptions{CRLs: []*x509.RevocationList{tampered}})
		if !errors.Is(err, x509util.ErrCRLSignatureInvalid) {
			t.Errorf("VerifyPath: got %v, want errors.Is ErrCRLSignatureInvalid", err)
		}
	})
}

// TestVerifyPathRFC5280CRL verifies the [RFC 5280] Appendix C.4 CRL
// parses and is recognized as issued by the C.1 CA, revoking the C.2
// serial. Full path validation of the SHA-1 chain is rejected by the
// standard library (see TestVerifyPathSHA1ChainRejected), so this
// checks the CRL object itself.
func TestVerifyPathRFC5280CRL(t *testing.T) {
	crl, err := x509.ParseRevocationList(mustDER(t, rfc5280C4))
	if err != nil {
		t.Fatalf("ParseRevocationList(C.4): %v", err)
	}
	ca := mustStdParse(t, rfc5280C1)
	if err := crl.CheckSignatureFrom(ca); err != nil {
		t.Fatalf("CheckSignatureFrom(C.1 CA): %v", err)
	}
	if got := len(crl.RevokedCertificateEntries); got != 1 {
		t.Fatalf("revoked entries: got %d, want 1", got)
	}
	if got := crl.RevokedCertificateEntries[0].SerialNumber.Int64(); got != 18 {
		t.Errorf("revoked serial: got %d, want 18 (the C.2 certificate)", got)
	}
}

// TestVerifyPathClock verifies the injectable validation clock: a leaf
// that is expired at wall-clock time validates when CurrentTime is set
// inside its validity window, and fails with the default clock.
func TestVerifyPathClock(t *testing.T) {
	key, err := stdrsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	ca := newTestCA(t, key, "clock CA")
	notBefore := time.Now().Add(-2 * time.Hour)
	notAfter := time.Now().Add(-time.Hour)
	leaf := ca.issue(t, key.Public(), 16, notBefore, notAfter, nil, 0)
	wrapped := wrap(t, leaf)

	if err := x509util.VerifyPath([]*x509util.Certificate{wrapped}, pool(ca.cert), x509util.VerifyOptions{}); err == nil {
		t.Fatal("VerifyPath default clock: got nil error, want expired")
	}
	err = x509util.VerifyPath([]*x509util.Certificate{wrapped}, pool(ca.cert), x509util.VerifyOptions{
		CurrentTime: notBefore.Add(30 * time.Minute),
	})
	if err != nil {
		t.Errorf("VerifyPath pinned clock: got %v, want nil", err)
	}
}

// TestCertificateRawCopies verifies Raw, RawSubjectPublicKeyInfo, and
// Extensions return copies: mutating the returned values must not
// affect the certificate.
func TestCertificateRawCopies(t *testing.T) {
	cert := mustParse(t, rfc5280C1)
	raw := cert.Raw()
	raw[0] = 0xFF
	if got := cert.Raw()[0]; got != 0x30 {
		t.Errorf("Raw not a copy: got first byte %#x, want 0x30", got)
	}
	spki := cert.RawSubjectPublicKeyInfo()
	spki[0] = 0xFF
	if got := cert.RawSubjectPublicKeyInfo()[0]; got != 0x30 {
		t.Errorf("RawSubjectPublicKeyInfo not a copy: got first byte %#x, want 0x30", got)
	}
	exts := cert.Extensions()
	exts[0].Value[0] = 0xFF
	if bytes.Equal(exts[0].Value, cert.Extensions()[0].Value) {
		t.Error("Extensions not a copy: mutation changed the certificate")
	}
}

// TestCertificateNilAccessors verifies every accessor fails closed
// (zero values) on a nil receiver instead of panicking.
func TestCertificateNilAccessors(t *testing.T) {
	var cert *x509util.Certificate
	cert.Subject()
	cert.Issuer()
	cert.NotBefore()
	cert.NotAfter()
	cert.SerialNumber()
	cert.KeyUsage()
	cert.ExtKeyUsage()
	cert.PublicKeyAlgorithm()
	cert.SignatureAlgorithm()
	cert.IsCA()
	cert.Extensions()
	if cert.Raw() != nil {
		t.Error("Raw: got non-nil, want nil")
	}
	if cert.RawSubjectPublicKeyInfo() != nil {
		t.Error("RawSubjectPublicKeyInfo: got non-nil, want nil")
	}
}

// TestNoAuthChainImports verifies the dependency rule: the x509 package
// source must not import the auth or chain modules. trust must never
// depend on auth or chain.
func TestNoAuthChainImports(t *testing.T) {
	// The test runs with the working directory set to the package
	// directory, so x509.go is a sibling file.
	src, err := os.ReadFile("x509.go")
	if err != nil {
		t.Fatalf("cannot read x509.go: %v", err)
	}
	if bytes.Contains(src, []byte("bperin/auth")) {
		t.Errorf("x509.go imports auth module (dependency rule violation)")
	}
	if bytes.Contains(src, []byte("bperin/chain")) {
		t.Errorf("x509.go imports chain module (dependency rule violation)")
	}
}
