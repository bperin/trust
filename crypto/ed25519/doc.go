// Package ed25519 implements [RFC 8037] and [FIPS 186-5] Ed25519
// digital signatures. Provides key generation, signing, and
// verification using the twisted Edwards form of Curve25519.
//
// Private keys are 64 bytes (seed || public key, per the Go stdlib
// representation). Public keys are 32 bytes. Signatures are 64 bytes.
// Signing is deterministic per [RFC 8032] §2.6 — no nonce RNG is
// required, which eliminates the catastrophic nonce-reuse failure
// mode present in ECDSA. All private-key operations use constant-time
// scalar multiplication.
package ed25519
