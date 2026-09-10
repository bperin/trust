package aead

import (
	"crypto/cipher"
	"fmt"

	"github.com/bperin/trust/crypto/rand"
	"golang.org/x/crypto/chacha20poly1305"
)

// xNonceSize is the XChaCha20-Poly1305 nonce length in bytes (192 bits).
const xNonceSize = 24

// XChaCha20Poly1305 implements [draft-irtf-cfrg-xchacha]; [RFC 8439] —
// XChaCha20-Poly1305 authenticated encryption with a 192-bit nonce.
// The extended nonce means random nonces are safe — no nonce tracking
// needed, no nonce-reuse risk.
//
// A version/type identifier must be supplied as AAD on both Encrypt and
// Decrypt. The serialized blob is: nonce (24 bytes) || ciphertext || tag
// (16 bytes).
type XChaCha20Poly1305 struct {
	aead cipher.AEAD
}

// NewXChaCha20Poly1305 creates a new [draft-irtf-cfrg-xchacha];
// [RFC 8439] cipher from a 32-byte key. Returns ErrInvalidKey if the
// key is not 32 bytes.
func NewXChaCha20Poly1305(key []byte) (*XChaCha20Poly1305, error) {
	if len(key) != 32 {
		return nil, ErrInvalidKey
	}
	a, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, fmt.Errorf("aead: XChaCha20-Poly1305 creation failed: %w", err)
	}
	return &XChaCha20Poly1305{aead: a}, nil
}

// Encrypt implements [draft-irtf-cfrg-xchacha]; [RFC 8439] — encrypts
// plaintext with a random 24-byte nonce and binds versionType as AAD.
// Returns nonce || ciphertext || tag.
//
// The 192-bit nonce means random nonces are safe: 2^96 messages before
// birthday collision, which is effectively never.
func (x *XChaCha20Poly1305) Encrypt(plaintext, versionType []byte) ([]byte, error) {
	nonce, err := rand.Bytes(xNonceSize)
	if err != nil {
		return nil, fmt.Errorf("aead: nonce generation failed: %w", err)
	}
	ciphertext := x.aead.Seal(nil, nonce, plaintext, versionType)
	return append(nonce, ciphertext...), nil
}

// Decrypt implements [draft-irtf-cfrg-xchacha]; [RFC 8439] — decrypts
// a blob produced by Encrypt. Expects nonce (24 bytes) || ciphertext ||
// tag (16 bytes). The same versionType must be supplied as was used on
// Encrypt.
//
// Fails closed on any error.
func (x *XChaCha20Poly1305) Decrypt(ciphertext, versionType []byte) ([]byte, error) {
	if len(ciphertext) < xNonceSize+tagSize {
		return nil, ErrCiphertextTooShort
	}
	nonce := ciphertext[:xNonceSize]
	ct := ciphertext[xNonceSize:]
	plaintext, err := x.aead.Open(nil, nonce, ct, versionType)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrDecrypt, err)
	}
	return plaintext, nil
}
