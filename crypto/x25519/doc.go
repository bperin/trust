// Package x25519 implements X25519 ECDH key agreement per [RFC 7748].
// Provides key generation, public key derivation, and shared secret
// computation.
//
// Private keys are 32 bytes. Public keys are 32 bytes. Shared secrets
// are 32 bytes.
package x25519
