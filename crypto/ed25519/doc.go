// Package ed25519 implements Ed25519 digital signatures per [RFC 8037].
// Provides key generation, signing, and verification.
//
// Private keys are 64 bytes (seed || public key, per the Go stdlib
// representation). Public keys are 32 bytes. Signatures are 64 bytes.
// Signing is deterministic — no nonce RNG is required, which eliminates
// the nonce-reuse failure mode present in ECDSA.
package ed25519
