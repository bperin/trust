package token

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"github.com/bperin/trust/crypto/rand"
)

// DefaultBytes is the recommended number of random bytes for token
// generation. 32 bytes (256 bits) provides sufficient entropy for
// session, refresh, and authorization-code tokens.
const DefaultBytes = 32

// Generate produces a cryptographically secure random token, hex-encoded,
// from nBytes of CSPRNG output. Use DefaultBytes (32) unless a different
// length is required. Returns an empty string for nBytes == 0 and an error
// for nBytes < 0.
//
// Uses [SP 800-90A] CSPRNG via trust's crypto/rand package.
func Generate(nBytes int) (string, error) {
	b, err := rand.Bytes(nBytes)
	if err != nil {
		return "", fmt.Errorf("token: failed to generate random bytes: %w", err)
	}
	return hex.EncodeToString(b), nil
}

// HashForStorage returns the SHA-256 hex hash of a raw token. Store
// this hash in the database and look up tokens by their hash — never
// store the raw token. The hash is deterministic: the same input always
// produces the same output.
//
// Implements [FIPS 180-4] SHA-256 via trust's crypto/hash package.
func HashForStorage(token string) string {
	h := sha256.Sum256([]byte(token))
	return hex.EncodeToString(h[:])
}
