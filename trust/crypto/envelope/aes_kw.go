package envelope

import (
	"crypto/aes"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/bperin/trust/crypto/rand"
)

// Errors returned by AES-KW.
var (
	// ErrInvalidKEK is returned when the KEK is not 16, 24, or 32 bytes.
	ErrInvalidKEK = errors.New("envelope: invalid KEK size (want 16, 24, or 32)")
	// ErrInvalidKey is returned when the plaintext key is not a multiple of 8 bytes or too short.
	ErrInvalidKey = errors.New("envelope: invalid key size")
	// ErrInvalidWrapped is returned when the wrapped key is malformed or too short.
	ErrInvalidWrapped = errors.New("envelope: invalid wrapped key")
	// ErrICVMismatch is returned when the ICV check fails on unwrap.
	ErrICVMismatch = errors.New("envelope: ICV mismatch — wrong KEK or tampered wrapped key")
)

// icv is the 8-byte integrity check value per [RFC 3394] §2.2.1.
var icv = [8]byte{0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6}

// Wrap implements [RFC 3394] §2.2.1 — wraps plaintextKey using the AES
// key-encryption key (KEK). The KEK must be 16, 24, or 32 bytes
// (AES-128/192/256). The plaintext key must be a multiple of 8 bytes
// and at least 16 bytes (2 semiblocks). Returns the wrapped key
// (plaintext length + 8 bytes for the ICV).
func Wrap(kek, plaintextKey []byte) ([]byte, error) {
	if err := validateKEK(kek); err != nil {
		return nil, err
	}
	if err := validatePlaintextKey(plaintextKey); err != nil {
		return nil, err
	}

	cipher, err := aes.NewCipher(kek)
	if err != nil {
		return nil, fmt.Errorf("envelope: AES cipher creation failed: %w", err)
	}

	n := len(plaintextKey) / 8 // number of semiblocks
	// A = ICV (8 bytes), R = plaintext key semiblocks
	a := make([]byte, 8)
	copy(a, icv[:])
	r := make([][]byte, n)
	for i := 0; i < n; i++ {
		r[i] = make([]byte, 8)
		copy(r[i], plaintextKey[i*8:(i+1)*8])
	}

	for j := 0; j < 6; j++ {
		for i := 0; i < n; i++ {
			// B = AES(K, A | R[i])
			var block [16]byte
			copy(block[:8], a)
			copy(block[8:], r[i])
			var out [16]byte
			cipher.Encrypt(out[:], block[:])
			// A = MSB(64, B) ^ t
			t := uint64(j*n + i + 1)
			for k := 0; k < 8; k++ {
				a[k] = out[k]
			}
			xorUint64(a, t)
			// R[i] = LSB(64, B)
			copy(r[i], out[8:])
		}
	}

	// Output: A || R[0] || ... || R[n-1]
	result := make([]byte, 8*(n+1))
	copy(result[:8], a)
	for i := 0; i < n; i++ {
		copy(result[(i+1)*8:(i+2)*8], r[i])
	}
	return result, nil
}

// Unwrap implements [RFC 3394] §2.2.2 — unwraps wrappedKey using the
// AES key-encryption key (KEK). The KEK must be 16, 24, or 32 bytes.
// The wrapped key must be a multiple of 8 bytes and at least 24 bytes
// (3 semiblocks). Returns the unwrapped key, or ErrICVMismatch if the
// ICV check fails (wrong KEK or tampered input).
func Unwrap(kek, wrappedKey []byte) ([]byte, error) {
	if err := validateKEK(kek); err != nil {
		return nil, err
	}
	if err := validateWrappedKey(wrappedKey); err != nil {
		return nil, err
	}

	cipher, err := aes.NewCipher(kek)
	if err != nil {
		return nil, fmt.Errorf("envelope: AES cipher creation failed: %w", err)
	}

	n := len(wrappedKey)/8 - 1 // number of semiblocks (excluding ICV)
	// A = wrappedKey[:8], R = wrappedKey[8:]
	a := make([]byte, 8)
	copy(a, wrappedKey[:8])
	r := make([][]byte, n)
	for i := 0; i < n; i++ {
		r[i] = make([]byte, 8)
		copy(r[i], wrappedKey[(i+1)*8:(i+2)*8])
	}

	for j := 5; j >= 0; j-- {
		for i := n - 1; i >= 0; i-- {
			// A = A ^ t
			t := uint64(j*n + i + 1)
			xorUint64(a, t)
			// B = AES-1(K, A | R[i])
			var block [16]byte
			copy(block[:8], a)
			copy(block[8:], r[i])
			var out [16]byte
			cipher.Decrypt(out[:], block[:])
			// A = MSB(64, B)
			copy(a, out[:8])
			// R[i] = LSB(64, B)
			copy(r[i], out[8:])
		}
	}

	// Verify ICV in constant time
	if subtle.ConstantTimeCompare(a, icv[:]) != 1 {
		return nil, ErrICVMismatch
	}

	// Output: R[0] || ... || R[n-1]
	result := make([]byte, 8*n)
	for i := 0; i < n; i++ {
		copy(result[i*8:(i+1)*8], r[i])
	}
	return result, nil
}

// GenerateKEK generates a 256-bit AES key-encryption key using the OS
// CSPRNG via trust/crypto/rand. Use this to create a KEK for [RFC 3394]
// AES Key Wrap.
func GenerateKEK() ([]byte, error) {
	return rand.Bytes(32)
}

// validateKEK returns ErrInvalidKEK if the KEK is not 16, 24, or 32 bytes.
func validateKEK(kek []byte) error {
	switch len(kek) {
	case 16, 24, 32:
		return nil
	default:
		return fmt.Errorf("%w: got %d bytes", ErrInvalidKEK, len(kek))
	}
}

// validatePlaintextKey returns ErrInvalidKey if the key is not a
// multiple of 8 bytes or less than 16 bytes.
func validatePlaintextKey(key []byte) error {
	if len(key) < 16 {
		return fmt.Errorf("%w: got %d bytes, want >= 16", ErrInvalidKey, len(key))
	}
	if len(key)%8 != 0 {
		return fmt.Errorf("%w: got %d bytes, want multiple of 8", ErrInvalidKey, len(key))
	}
	return nil
}

// validateWrappedKey returns ErrInvalidWrapped if the wrapped key is
// not a multiple of 8 bytes or less than 24 bytes.
func validateWrappedKey(key []byte) error {
	if len(key) < 24 {
		return fmt.Errorf("%w: got %d bytes, want >= 24", ErrInvalidWrapped, len(key))
	}
	if len(key)%8 != 0 {
		return fmt.Errorf("%w: got %d bytes, want multiple of 8", ErrInvalidWrapped, len(key))
	}
	return nil
}

// xorUint64 XORs an 8-byte big-endian uint64 value into an 8-byte slice in place.
func xorUint64(b []byte, v uint64) {
	for i := 0; i < 8; i++ {
		b[7-i] ^= byte(v >> (uint(i) * 8))
	}
}

// putUint64BE writes a uint64 to an 8-byte big-endian slice.
func putUint64BE(b []byte, v uint64) {
	binary.BigEndian.PutUint64(b, v)
}

// getUint64BE reads a uint64 from an 8-byte big-endian slice.
func getUint64BE(b []byte) uint64 {
	return binary.BigEndian.Uint64(b)
}

// constantTimeCompare wraps subtle.ConstantTimeCompare for 8-byte blocks.
func constantTimeCompare(a, b []byte) bool {
	return subtle.ConstantTimeCompare(a, b) == 1
}
