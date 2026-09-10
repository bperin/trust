// Package hash provides wrappers for cryptographic hash functions with a
// consistent API. Each wrapper cites its governing standard in Godoc.
//
// All hash functions in this package are deterministic — the same input
// always produces the same output. Hashes are not encryption: the output
// cannot be reversed to recover the input.
//
// Standards referenced:
//   - [FIPS 180-4] — SHA-256 (SHA-2 family)
//   - [FIPS 202] — SHA-3 (sponge construction)
//   - [EIP-191] — Keccak-256 (Ethereum's pre-FIPS Keccak variant)
//   - [BLAKE3 Spec, 2020] — BLAKE3
package hash
