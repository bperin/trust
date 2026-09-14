package hkdf

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"
)

// MaxExpandLength is the maximum output length for HKDF-Expand per
// [RFC 5869] §2.3: 255 * HashLen. For SHA-256, HashLen = sha256.Size.
const MaxExpandLength = 255 * sha256.Size

// ErrInvalidLength is returned by [RFC 5869] functions when the requested
// output length is invalid (<= 0 or > MaxExpandLength).
var ErrInvalidLength = errors.New("hkdf: invalid length")

// ErrEmptySecret is returned by [RFC 5869] functions when the input
// keying material is empty. An empty secret yields a PRK dependent only
// on the salt, which is cryptographically weak.
var ErrEmptySecret = errors.New("hkdf: empty secret")

// ErrInvalidPRK is returned by [RFC 5869] Expand when the pseudorandom
// key is shorter than HashLen. [RFC 5869] §2.2 requires PRK to be at
// least HashLen bytes (sha256.Size for SHA-256).
var ErrInvalidPRK = errors.New("hkdf: invalid pseudorandom key")

// DeriveKey implements [RFC 5869] — performs extract-then-expand in one
// call. Returns length bytes of derived key material.
//
// Returns an error if secret is empty, if length <= 0, or if length >
// MaxExpandLength. Nil salt is treated as a string of HashLen zero bytes
// per [RFC 5869] §2.2.
func DeriveKey(secret, salt, info []byte, length int) ([]byte, error) {
	if len(secret) == 0 {
		return nil, ErrEmptySecret
	}
	if length <= 0 || length > MaxExpandLength {
		return nil, ErrInvalidLength
	}
	r := hkdf.New(sha256.New, secret, salt, info)
	out := make([]byte, length)
	if _, err := io.ReadFull(r, out); err != nil {
		return nil, fmt.Errorf("hkdf: derive failed: %w", err)
	}
	return out, nil
}

// Extract implements [RFC 5869] §2.2 — extracts a pseudorandom key (PRK)
// from the input keying material. Returns a 32-byte PRK.
//
// Returns ErrEmptySecret if secret is empty. Nil salt is treated as a
// string of HashLen zero bytes per [RFC 5869] §2.2.
func Extract(secret, salt []byte) ([]byte, error) {
	if len(secret) == 0 {
		return nil, ErrEmptySecret
	}
	return hkdf.Extract(sha256.New, secret, salt), nil
}

// Expand implements [RFC 5869] §2.3 — expands a PRK into length bytes of
// output keying material.
//
// Returns an error if prk is shorter than HashLen (sha256.Size for
// SHA-256), if length <= 0, or if length > MaxExpandLength. The PRK must
// be a value produced by Extract or an equivalent uniformly random key
// of at least HashLen bytes per [RFC 5869] §2.2.
func Expand(prk, info []byte, length int) ([]byte, error) {
	if len(prk) < sha256.Size {
		return nil, ErrInvalidPRK
	}
	if length <= 0 || length > MaxExpandLength {
		return nil, ErrInvalidLength
	}
	r := hkdf.Expand(sha256.New, prk, info)
	out := make([]byte, length)
	if _, err := io.ReadFull(r, out); err != nil {
		return nil, fmt.Errorf("hkdf: expand failed: %w", err)
	}
	return out, nil
}
