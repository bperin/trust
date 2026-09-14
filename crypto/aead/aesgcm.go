package aead

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
)

// ErrInvalidKey is returned when the key is not 32 bytes.
var ErrInvalidKey = errors.New("aead: key must be 32 bytes")

// ErrCiphertextTooShort is returned when the ciphertext is shorter than
// the nonce length.
var ErrCiphertextTooShort = errors.New("aead: ciphertext too short")

// ErrDecrypt is returned when AEAD authentication fails during Decrypt.
// Tampered ciphertext, wrong key, or wrong AAD all produce this error.
var ErrDecrypt = errors.New("aead: decryption failed")

// nonceSize is the GCM standard nonce length in bytes.
const nonceSize = 12

// tagSize is the GCM authentication tag length in bytes.
const tagSize = 16

// AES256GCM provides AES-256-GCM authenticated encryption per [SP 800-38D].
// Nonces are generated internally per Encrypt call using the OS CSPRNG and
// prefixed to the ciphertext. The caller never manages nonces.
//
// A version/type identifier must be supplied as AAD on both Encrypt and
// Decrypt. This prevents ciphertext replay against a different object type.
// The serialized blob is: nonce (12 bytes) || ciphertext || tag (16 bytes).
type AES256GCM struct {
	gcm cipher.AEAD
}

// NewAES256GCM creates a new AES-256-GCM cipher from a 32-byte key.
// Returns ErrInvalidKey if the key is not 32 bytes.
func NewAES256GCM(key []byte) (*AES256GCM, error) {
	if len(key) != 32 {
		return nil, ErrInvalidKey
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("aead: AES cipher creation failed: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("aead: GCM mode creation failed: %w", err)
	}
	return &AES256GCM{gcm: gcm}, nil
}

// Encrypt encrypts plaintext with a random nonce and binds versionType
// as AAD. Returns nonce || ciphertext || tag. versionType must match on
// Decrypt.
func (a *AES256GCM) Encrypt(plaintext, versionType []byte) ([]byte, error) {
	nonce := make([]byte, nonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("aead: nonce generation failed: %w", err)
	}
	ciphertext := a.gcm.Seal(nil, nonce, plaintext, versionType)
	return append(nonce, ciphertext...), nil
}

// Decrypt decrypts a blob produced by Encrypt. Expects nonce (12 bytes)
// || ciphertext || tag (16 bytes). The same versionType must be supplied
// as was used on Encrypt. Fails closed on any error.
func (a *AES256GCM) Decrypt(ciphertext, versionType []byte) ([]byte, error) {
	if len(ciphertext) < nonceSize+tagSize {
		return nil, ErrCiphertextTooShort
	}
	nonce := ciphertext[:nonceSize]
	ct := ciphertext[nonceSize:]
	plaintext, err := a.gcm.Open(nil, nonce, ct, versionType)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrDecrypt, err)
	}
	return plaintext, nil
}
