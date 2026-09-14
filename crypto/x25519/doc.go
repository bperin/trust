// Package x25519 implements [RFC 7748] — Elliptic Curve Diffie-Hellman
// key agreement using Curve25519. Provides key generation, public key
// derivation, and shared secret computation.
//
// Private keys are 32 bytes. Public keys are 32 bytes. Shared secrets
// are 32 bytes. All operations use constant-time scalar multiplication
// via the Montgomery ladder.
package x25519
