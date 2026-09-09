// Package envelope implements [RFC 3394] AES Key Wrap and [RFC 9180]
// HPKE hybrid public key encryption. These are composition-layer
// protocols built from the primitive wrappers in trust/crypto.
//
// AES-KW wraps symmetric keys using an AES key-encryption key (KEK).
// It is deterministic, nonce-free, with integrity via the ICV.
//
// HPKE combines X25519 key agreement, HKDF-SHA256 key schedule, and
// AEAD encryption for public-key envelope encryption. Base mode only.
package envelope
