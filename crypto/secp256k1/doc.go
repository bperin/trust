// Package secp256k1 implements secp256k1 ECDSA signing and verification
// with [RFC 6979] deterministic nonces and [EIP-2] low-s canonicalization.
// secp256k1 is the curve used by Bitcoin and Ethereum for transaction
// signing.
//
// Private keys are 32 bytes. Public keys are 33 bytes (compressed).
// Signatures are 64 bytes (r || s). Sign and Verify operate on a
// 32-byte pre-computed hash — the caller chooses the hash algorithm
// (SHA-256 or Keccak-256).
package secp256k1
