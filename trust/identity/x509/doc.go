// Package x509util implements [RFC 5280] X.509 certificate parsing and
// certification-path validation for the trust key types. It wraps the Go
// standard library crypto/x509 parser — the package does not implement
// any new cryptographic primitives — and adds the trust platform's
// policy: a whitelist of supported public-key algorithms, public keys
// returned as the concrete trust wrapper types from trust/crypto/*, and
// fail-closed path validation with caller-supplied trust anchors.
//
// The package name is x509util (rather than x509) to avoid colliding
// with the standard library crypto/x509 that this package imports.
//
// # Standards
//
//   - [RFC 5280] — Internet X.509 Public Key Infrastructure Certificate
//     and Certificate Revocation List (CRL) Profile. Parsing follows
//     §4 (certificate and CRL profile); path validation follows §6.1
//     (basic path validation) as implemented by the standard library,
//     including expiry (§4.1.2.5), key usage and extended key usage
//     (§4.2.1.3, §4.2.1.12), and name constraints (§4.2.1.10).
//   - [RFC 5280] Appendix C.1–C.4 — the RSA self-signed CA, RSA end
//     entity, DSA end entity, and CRL sample objects used as known
//     test vectors (identical objects are distributed by NIST PKI
//     Testing).
//
// # Public-key policy
//
// ParseCertificate accepts only certificates whose subject public key is
// RSA, ECDSA, or Ed25519. DSA and unknown algorithms are rejected with
// ErrUnsupportedPublicKeyAlgorithm. X25519 keys never appear as X.509
// subject public keys in this profile and are not supported.
//
// PublicKey returns the subject public key as a trust wrapper type:
//
//   - RSA keys become *rsa.PSSPublicKey or *rsa.PKCS1PublicKey, with
//     the scheme and hash derived from the certificate's own signature
//     algorithm (see PublicKey for the rule and its limits).
//   - ECDSA keys become *ecdsa.PublicKey with the curve-matched hash
//     (P-256 with SHA-256, P-384 with SHA-384).
//   - Ed25519 keys become *ed25519.PublicKey.
//
// The trust constructors enforce the platform key policy — RSA keys
// must be at least 2048 bits and bound to SHA-256, SHA-384, or SHA-512,
// and ECDSA keys must use P-256 or P-384. Certificates that predate
// that policy (for example the [RFC 5280] Appendix C samples, which use
// 1024-bit RSA and SHA-1) parse successfully but PublicKey returns
// the constructor's policy error. This is deliberate: parsing a
// certificate must not silently downgrade the platform's key policy.
//
// # Path validation policy
//
// VerifyPath fails closed. Trust anchors are never implicit: the
// system certificate pool is never consulted, a nil root pool is an
// error (ErrNilRoots), and the validation clock is injectable so
// decisions are reproducible. Revocation checking uses only
// caller-supplied CRLs — the package never fetches CRLs, OCSP, or any
// other revocation data over the network. Each supplied CRL must be
// signed by a certificate present in the path or the intermediates
// (ErrCRLIssuerNotFound otherwise), must carry a valid signature
// (ErrCRLSignatureInvalid), and must be within its thisUpdate/nextUpdate
// window at the validation time (ErrCRLOutsideValidity). A certificate
// listed by an applicable CRL fails validation (ErrCertificateRevoked).
package x509util
