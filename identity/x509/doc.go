// Package x509util implements X.509 certificate parsing and
// certification-path validation ([RFC 5280]) for the trust key types.
// It wraps the standard library crypto/x509 parser and returns public
// keys as the concrete trust wrapper types from trust/crypto/*.
//
// The package name is x509util (rather than x509) to avoid colliding
// with the standard library crypto/x509.
//
// ParseCertificate accepts only RSA, ECDSA, and Ed25519 subject public
// keys. PublicKey returns the key as a trust wrapper type, with the RSA
// scheme and hash derived from the certificate's signature algorithm.
// The trust constructors enforce the platform key policy, so
// certificates with undersized keys or weak hashes parse successfully
// but fail at PublicKey.
//
// VerifyPath never consults the system certificate pool: trust anchors
// must be supplied explicitly and the validation clock is injectable.
// Revocation checking uses only caller-supplied CRLs, each of which
// must be signed by a certificate in the path or intermediates and be
// within its thisUpdate/nextUpdate window.
package x509util
