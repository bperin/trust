package token

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

// DefaultBytes is the recommended token length in bytes (256 bits of
// entropy).
const DefaultBytes = 32

// Generate returns a hex-encoded token of nBytes cryptographically
// random bytes. Use DefaultBytes unless a different length is required.
func Generate(nBytes int) (string, error) {
	if nBytes < 0 {
		return "", fmt.Errorf("token: negative length")
	}
	b := make([]byte, nBytes)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("token: failed to generate random bytes: %w", err)
	}
	return hex.EncodeToString(b), nil
}

// HashForStorage returns the SHA-256 hex hash of a raw token for storage
// and lookup; raw tokens should never be stored.
func HashForStorage(token string) string {
	h := sha256.Sum256([]byte(token))
	return hex.EncodeToString(h[:])
}
