package x509util

import (
	"bytes"
	"crypto"
	stdecdsa "crypto/ecdsa"
	stded25519 "crypto/ed25519"
	"crypto/elliptic"
	stdrsa "crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/bperin/trust/crypto/ecdsa"
	"github.com/bperin/trust/crypto/ed25519"
	"github.com/bperin/trust/crypto/rsa"
)

// Sentinel errors returned by this package. Check with errors.Is.
var (
	// ErrEmptyChain is returned when VerifyPath is called with an empty
	// certificate chain.
	ErrEmptyChain = errors.New("x509util: empty certificate chain")
	// ErrEmptyInput is returned when ParseCertificate is called with a
	// nil or zero-length DER slice.
	ErrEmptyInput = errors.New("x509util: empty input")
	// ErrNilCertificate is returned when a nil *Certificate is passed
	// to PublicKey or found in a chain or intermediates list.
	ErrNilCertificate = errors.New("x509util: nil certificate")
	// ErrNilRoots is returned when VerifyPath is called with a nil
	// root pool; trust anchors must be supplied explicitly.
	ErrNilRoots = errors.New("x509util: nil root pool")
	// ErrMalformedCertificate is returned when the DER input cannot be
	// parsed as an X.509 certificate.
	ErrMalformedCertificate = errors.New("x509util: malformed certificate")
	// ErrUnsupportedPublicKeyAlgorithm is returned when a certificate
	// carries a public key that is not RSA, ECDSA, or Ed25519.
	ErrUnsupportedPublicKeyAlgorithm = errors.New("x509util: unsupported public-key algorithm")
	// ErrUnsupportedSignatureAlgorithm is returned when PublicKey is
	// asked to derive an RSA scheme from a certificate whose signature
	// algorithm is not an RSA family algorithm (unknown, or signed
	// with DSA, ECDSA, or Ed25519).
	ErrUnsupportedSignatureAlgorithm = errors.New("x509util: unsupported signature algorithm")
	// ErrCRLIssuerNotFound is returned when a supplied CRL is issued by
	// a CA that is not present in the chain or the intermediates, so
	// the CRL cannot be authenticated.
	ErrCRLIssuerNotFound = errors.New("x509util: CRL issuer not found in chain or intermediates")
	// ErrCRLSignatureInvalid is returned when a supplied CRL's signature
	// does not verify against its issuing certificate.
	ErrCRLSignatureInvalid = errors.New("x509util: CRL signature invalid")
	// ErrCRLOutsideValidity is returned when a supplied CRL is outside
	// its thisUpdate/nextUpdate window at the validation time.
	ErrCRLOutsideValidity = errors.New("x509util: CRL outside thisUpdate/nextUpdate window")
	// ErrCertificateRevoked is returned when a certificate in the path
	// is listed on an applicable, authenticated CRL.
	ErrCertificateRevoked = errors.New("x509util: certificate revoked")
)

// Certificate is a parsed X.509 certificate ([RFC 5280]). Its
// accessors return zero values when the receiver is nil. Use
// ParseCertificate to construct one.
type Certificate struct {
	cert *x509.Certificate
}

// supportedPublicKeyAlgorithm reports whether alg is RSA, ECDSA, or
// Ed25519.
func supportedPublicKeyAlgorithm(alg x509.PublicKeyAlgorithm) bool {
	switch alg {
	case x509.RSA, x509.ECDSA, x509.Ed25519:
		return true
	default:
		return false
	}
}

// ParseCertificate parses a DER-encoded X.509 certificate ([RFC
// 5280]). The subject public-key algorithm must be RSA, ECDSA, or
// Ed25519; anything else returns ErrUnsupportedPublicKeyAlgorithm and
// malformed DER returns ErrMalformedCertificate.
func ParseCertificate(der []byte) (*Certificate, error) {
	if len(der) == 0 {
		return nil, ErrEmptyInput
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMalformedCertificate, err)
	}
	if !supportedPublicKeyAlgorithm(cert.PublicKeyAlgorithm) {
		return nil, fmt.Errorf("%w: %s", ErrUnsupportedPublicKeyAlgorithm, cert.PublicKeyAlgorithm)
	}
	return &Certificate{cert: cert}, nil
}

// PublicKey returns cert's subject public key as a trust wrapper type
// (*rsa.PSSPublicKey, *rsa.PKCS1PublicKey, *ecdsa.PublicKey, or
// *ed25519.PublicKey). Returns ErrNilCertificate when cert is nil.
func PublicKey(cert *Certificate) (crypto.PublicKey, error) {
	if cert == nil {
		return nil, ErrNilCertificate
	}
	return cert.PublicKey()
}

// PublicKey returns the certificate's subject public key as a trust
// wrapper type: *rsa.PSSPublicKey or *rsa.PKCS1PublicKey for RSA keys
// (scheme and hash derived from the certificate's signature
// algorithm), *ecdsa.PublicKey for ECDSA keys (hash matched to the
// curve), and *ed25519.PublicKey for Ed25519 keys. For a
// non-self-signed certificate the signature algorithm describes the
// issuer's signature, which may not match the intended use of the
// subject key. The trust constructors enforce the platform key-size
// and hash policy.
func (c *Certificate) PublicKey() (crypto.PublicKey, error) {
	if c == nil || c.cert == nil {
		return nil, ErrNilCertificate
	}
	switch c.cert.PublicKeyAlgorithm {
	case x509.RSA:
		return c.rsaPublicKey()
	case x509.ECDSA:
		return c.ecdsaPublicKey()
	case x509.Ed25519:
		return c.ed25519PublicKey()
	default:
		return nil, fmt.Errorf("%w: %s", ErrUnsupportedPublicKeyAlgorithm, c.cert.PublicKeyAlgorithm)
	}
}

// rsaPublicKey constructs the trust RSA wrapper for the subject key,
// deriving the scheme and hash from the certificate's signature
// algorithm.
func (c *Certificate) rsaPublicKey() (crypto.PublicKey, error) {
	key, ok := c.cert.PublicKey.(*stdrsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("%w: RSA algorithm with non-RSA public key", ErrMalformedCertificate)
	}
	switch c.cert.SignatureAlgorithm {
	case x509.SHA256WithRSA:
		return rsa.NewPKCS1PublicKey(key, crypto.SHA256)
	case x509.SHA384WithRSA:
		return rsa.NewPKCS1PublicKey(key, crypto.SHA384)
	case x509.SHA512WithRSA:
		return rsa.NewPKCS1PublicKey(key, crypto.SHA512)
	case x509.SHA256WithRSAPSS:
		return rsa.NewPSSPublicKey(key, crypto.SHA256)
	case x509.SHA384WithRSAPSS:
		return rsa.NewPSSPublicKey(key, crypto.SHA384)
	case x509.SHA512WithRSAPSS:
		return rsa.NewPSSPublicKey(key, crypto.SHA512)
	case x509.SHA1WithRSA:
		// Routed to the constructor so the hash policy rejects it with
		// the rsa package's own sentinel rather than a parse-time
		// special case.
		return rsa.NewPKCS1PublicKey(key, crypto.SHA1)
	case x509.MD5WithRSA:
		return rsa.NewPKCS1PublicKey(key, crypto.MD5)
	default:
		return nil, fmt.Errorf("%w: %s on RSA key", ErrUnsupportedSignatureAlgorithm, c.cert.SignatureAlgorithm)
	}
}

// ecdsaPublicKey constructs the trust ECDSA wrapper with the hash
// matched to the subject key's curve.
func (c *Certificate) ecdsaPublicKey() (crypto.PublicKey, error) {
	key, ok := c.cert.PublicKey.(*stdecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("%w: ECDSA algorithm with non-ECDSA public key", ErrMalformedCertificate)
	}
	var hash crypto.Hash
	switch key.Curve {
	case elliptic.P256():
		hash = crypto.SHA256
	case elliptic.P384():
		hash = crypto.SHA384
	default:
		// The constructor rejects the curve with ErrUnsupportedCurve.
	}
	return ecdsa.NewPublicKey(key, hash)
}

// ed25519PublicKey constructs the trust Ed25519 wrapper.
func (c *Certificate) ed25519PublicKey() (crypto.PublicKey, error) {
	key, ok := c.cert.PublicKey.(stded25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("%w: Ed25519 algorithm with non-Ed25519 public key", ErrMalformedCertificate)
	}
	return ed25519.NewPublicKey(key)
}

// VerifyOptions configures VerifyPath. The zero value is valid: the
// clock defaults to the current time and the key usage defaults to
// server authentication. The system certificate pool is never
// consulted and no revocation data is fetched over the network.
type VerifyOptions struct {
	// CurrentTime is the validation time used for expiry and CRL
	// window checks. The zero value means time.Now, captured once at
	// the start of the call so a single validation run is consistent.
	// Supply an explicit time for reproducible decisions.
	CurrentTime time.Time
	// DNSName, when non-empty, is checked against the leaf
	// certificate's SANs per [RFC 5280] §4.2.1.6.
	DNSName string
	// Intermediates are additional untrusted intermediate
	// certificates, as trust wrapper types, used for chain building
	// and for authenticating supplied CRLs.
	Intermediates []*Certificate
	// KeyUsages are the extended key usages accepted for the leaf.
	// Empty means server authentication only.
	KeyUsages []x509.ExtKeyUsage
	// CRLs are caller-supplied parsed revocation lists. When empty,
	// revocation is not checked. When non-empty, every CRL must be
	// authenticated and current, and every non-anchor certificate in
	// the accepted path is checked against every CRL issued by its
	// issuer.
	CRLs []*x509.RevocationList
}

// VerifyPath validates the certification path in certs against roots
// per [RFC 5280] §6.1, using the standard library: chain building,
// expiry, signature checks, key usage, and name constraints. certs[0]
// is the end-entity certificate; the rest are pooled with
// opts.Intermediates. An empty chain returns ErrEmptyChain, a nil
// entry ErrNilCertificate, and nil roots ErrNilRoots; trust anchors
// must be supplied explicitly. Standard library errors are wrapped
// and their types preserved for errors.As.
//
// When opts.CRLs is non-empty, each CRL is authenticated and checked
// for currency (ErrCRLIssuerNotFound, ErrCRLSignatureInvalid,
// ErrCRLOutsideValidity), and any non-anchor path certificate listed
// on an applicable CRL fails with ErrCertificateRevoked.
func VerifyPath(certs []*Certificate, roots *x509.CertPool, opts VerifyOptions) error {
	if len(certs) == 0 {
		return fmt.Errorf("%w: got 0 certificates", ErrEmptyChain)
	}
	if roots == nil {
		return ErrNilRoots
	}
	for i, cert := range certs {
		if cert == nil || cert.cert == nil {
			return fmt.Errorf("%w: chain position %d", ErrNilCertificate, i)
		}
	}
	for i, cert := range opts.Intermediates {
		if cert == nil || cert.cert == nil {
			return fmt.Errorf("%w: intermediates position %d", ErrNilCertificate, i)
		}
	}
	now := opts.CurrentTime
	if now.IsZero() {
		now = time.Now()
	}
	keyUsages := opts.KeyUsages
	if len(keyUsages) == 0 {
		keyUsages = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	}
	pool := x509.NewCertPool()
	for _, cert := range certs[1:] {
		pool.AddCert(cert.cert)
	}
	for _, cert := range opts.Intermediates {
		pool.AddCert(cert.cert)
	}
	chains, err := certs[0].cert.Verify(x509.VerifyOptions{
		DNSName:       opts.DNSName,
		Intermediates: pool,
		Roots:         roots,
		CurrentTime:   now,
		KeyUsages:     keyUsages,
	})
	if err != nil {
		return fmt.Errorf("x509util: verify %q: %w", certs[0].cert.Subject.String(), err)
	}
	if len(opts.CRLs) == 0 {
		return nil
	}
	// Authenticate every supplied CRL before consulting it: the issuer
	// must be present in the path, the intermediates, or the verified
	// chains (the verified chains include the root from the pool, so
	// root-issued CRLs can be authenticated without the caller
	// supplying the root twice); the signature must verify; and the
	// list must be current at the validation time.
	issuers := make(map[string]*x509.Certificate)
	for _, cert := range certs {
		issuers[string(cert.cert.RawSubject)] = cert.cert
	}
	for _, cert := range opts.Intermediates {
		issuers[string(cert.cert.RawSubject)] = cert.cert
	}
	for _, chain := range chains {
		for _, cert := range chain {
			issuers[string(cert.RawSubject)] = cert
		}
	}
	for _, crl := range opts.CRLs {
		issuer, ok := issuers[string(crl.RawIssuer)]
		if !ok {
			return fmt.Errorf("%w: %q", ErrCRLIssuerNotFound, crl.Issuer.String())
		}
		if err := crl.CheckSignatureFrom(issuer); err != nil {
			return fmt.Errorf("%w: %v", ErrCRLSignatureInvalid, err)
		}
		if now.Before(crl.ThisUpdate) || now.After(crl.NextUpdate) {
			return fmt.Errorf("%w: now=%s thisUpdate=%s nextUpdate=%s",
				ErrCRLOutsideValidity, now.UTC(), crl.ThisUpdate.UTC(), crl.NextUpdate.UTC())
		}
	}
	// A path is acceptable when any verified chain is also clean under
	// revocation. Report the first chain's failure when none is clean.
	var firstErr error
	for _, chain := range chains {
		if err := checkRevocation(chain, opts.CRLs); err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		return nil
	}
	return firstErr
}

// checkRevocation reports whether any non-anchor certificate in chain
// is listed on an applicable CRL.
func checkRevocation(chain []*x509.Certificate, crls []*x509.RevocationList) error {
	for i, cert := range chain {
		if i == len(chain)-1 {
			break
		}
		for _, crl := range crls {
			if !bytes.Equal(cert.RawIssuer, crl.RawIssuer) {
				continue
			}
			for _, entry := range crl.RevokedCertificateEntries {
				if entry.SerialNumber.Cmp(cert.SerialNumber) == 0 {
					return fmt.Errorf("%w: serial %s at chain position %d (%q)",
						ErrCertificateRevoked, cert.SerialNumber, i, cert.Subject.String())
				}
			}
		}
	}
	return nil
}

// Subject returns the subject distinguished name.
func (c *Certificate) Subject() pkix.Name {
	if c == nil || c.cert == nil {
		return pkix.Name{}
	}
	return c.cert.Subject
}

// Issuer returns the issuer distinguished name.
func (c *Certificate) Issuer() pkix.Name {
	if c == nil || c.cert == nil {
		return pkix.Name{}
	}
	return c.cert.Issuer
}

// NotBefore returns the start of the validity period.
func (c *Certificate) NotBefore() time.Time {
	if c == nil || c.cert == nil {
		return time.Time{}
	}
	return c.cert.NotBefore
}

// NotAfter returns the end of the validity period.
func (c *Certificate) NotAfter() time.Time {
	if c == nil || c.cert == nil {
		return time.Time{}
	}
	return c.cert.NotAfter
}

// SerialNumber returns the certificate serial number.
func (c *Certificate) SerialNumber() *big.Int {
	if c == nil || c.cert == nil || c.cert.SerialNumber == nil {
		return new(big.Int)
	}
	return new(big.Int).Set(c.cert.SerialNumber)
}

// KeyUsage returns the key usage bits.
func (c *Certificate) KeyUsage() x509.KeyUsage {
	if c == nil || c.cert == nil {
		return 0
	}
	return c.cert.KeyUsage
}

// ExtKeyUsage returns the extended key usages. An empty result means
// the certificate is unrestricted.
func (c *Certificate) ExtKeyUsage() []x509.ExtKeyUsage {
	if c == nil || c.cert == nil {
		return nil
	}
	out := make([]x509.ExtKeyUsage, len(c.cert.ExtKeyUsage))
	copy(out, c.cert.ExtKeyUsage)
	return out
}

// PublicKeyAlgorithm returns the subject public-key algorithm family.
func (c *Certificate) PublicKeyAlgorithm() x509.PublicKeyAlgorithm {
	if c == nil || c.cert == nil {
		return x509.UnknownPublicKeyAlgorithm
	}
	return c.cert.PublicKeyAlgorithm
}

// SignatureAlgorithm returns the algorithm the issuer used to sign
// this certificate.
func (c *Certificate) SignatureAlgorithm() x509.SignatureAlgorithm {
	if c == nil || c.cert == nil {
		return x509.UnknownSignatureAlgorithm
	}
	return c.cert.SignatureAlgorithm
}

// IsCA reports whether the basic constraints extension marks this
// certificate as a CA.
func (c *Certificate) IsCA() bool {
	if c == nil || c.cert == nil {
		return false
	}
	return c.cert.IsCA
}

// Extensions returns copies of the raw certificate extensions;
// mutating them does not affect the certificate.
func (c *Certificate) Extensions() []pkix.Extension {
	if c == nil || c.cert == nil {
		return nil
	}
	out := make([]pkix.Extension, len(c.cert.Extensions))
	for i, ext := range c.cert.Extensions {
		out[i] = ext
		out[i].Value = bytes.Clone(ext.Value)
	}
	return out
}

// Raw returns a copy of the complete DER-encoded certificate.
func (c *Certificate) Raw() []byte {
	if c == nil || c.cert == nil {
		return nil
	}
	return bytes.Clone(c.cert.Raw)
}

// RawSubjectPublicKeyInfo returns a copy of the DER-encoded
// SubjectPublicKeyInfo.
func (c *Certificate) RawSubjectPublicKeyInfo() []byte {
	if c == nil || c.cert == nil {
		return nil
	}
	return bytes.Clone(c.cert.RawSubjectPublicKeyInfo)
}
