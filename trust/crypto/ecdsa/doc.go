// Package ecdsa implements [FIPS 186-4] ECDSA P-256 and P-384
// digital signatures. Provides key generation, signing, and
// verification using the Go stdlib crypto/ecdsa package.
//
// The hash is bound to the curve at construction: SHA-256 for P-256
// (ES256), SHA-384 for P-384 (ES384), per [FIPS 186-4] and JOSE.
// Signatures are DER-encoded via ecdsa.SignASN1/VerifyASN1.
//
// Go's crypto/ecdsa uses randomized nonces with entropy mixed from
// the private key and message — NOT RFC 6979 deterministic. This
// provides equivalent security against nonce-reuse in case of RNG
// failure. Signatures are not deterministic.
//
// Private keys expose Redact() for logging, never
// String()/Format()/GoString().
package ecdsa
