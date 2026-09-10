// Package secp256k1 implements [SEC 2 v2] secp256k1 ECDSA signing
// and verification with [RFC 6979] deterministic nonces and [EIP-2]
// low-s canonicalization. secp256k1 is the curve used by Bitcoin and
// Ethereum for transaction signing.
//
// Private keys are 32 bytes. Public keys are 33 bytes (compressed).
// Signatures are 64 bytes (r || s). Sign and Verify operate on a
// 32-byte pre-computed hash — the caller chooses the hash algorithm
// (SHA-256 or Keccak-256). This keeps the primitive pure and
// composable with any hashing scheme.
//
// RFC 6979 deterministic nonces eliminate the catastrophic nonce-reuse
// failure mode that leaks private keys. EIP-2 low-s canonicalization
// rejects malleable signatures where s > n/2.
package secp256k1
