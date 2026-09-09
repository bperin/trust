// Package hkdf implements [RFC 5869] — HMAC-based Extract-and-Expand Key
// Derivation Function. HKDF derives scoped child keys from a root secret
// using a two-step process: extract (concentrate entropy) then expand
// (generate derived keys).
//
// This package wraps golang.org/x/crypto/hkdf over SHA-256.
package hkdf
