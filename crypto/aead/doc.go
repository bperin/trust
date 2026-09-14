// Package aead provides authenticated encryption with associated data
// (AEAD) primitives. AES-256-GCM implements [SP 800-38D] and
// XChaCha20-Poly1305 implements [draft-irtf-cfrg-xchacha]; [RFC 8439].
// Nonces are managed internally — callers never touch nonces. A
// version/type identifier is bound as AAD to prevent ciphertext replay
// across object types.
//
// Ciphertext format: nonce || ciphertext || tag
package aead
