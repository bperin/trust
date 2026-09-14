package ed25519

import (
	stded25519 "crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
)

// ErrInvalidKey is returned when an Ed25519 key is not the expected size.
var ErrInvalidKey = errors.New("ed25519: invalid key length")

// PrivateKey is an Ed25519 private key per [RFC 8037]. It wraps the Go
// stdlib crypto/ed25519.PrivateKey (64 bytes: seed || public key). It
// must never be exposed via String(), Format(), GoString(),
// MarshalText(), or MarshalJSON(). Use Redact() for logging.
type PrivateKey struct {
	key stded25519.PrivateKey
}

// PublicKey is an Ed25519 public key per [RFC 8037]. It wraps the Go
// stdlib crypto/ed25519.PublicKey (32 bytes).
type PublicKey struct {
	key stded25519.PublicKey
}

// GenerateKey generates a new Ed25519 keypair using the OS CSPRNG.
func GenerateKey() (*PrivateKey, *PublicKey, error) {
	seed := make([]byte, stded25519.SeedSize)
	if _, err := rand.Read(seed); err != nil {
		return nil, nil, err
	}

	priv := stded25519.NewKeyFromSeed(seed)
	pub := priv.Public().(stded25519.PublicKey)

	return &PrivateKey{key: priv}, &PublicKey{key: pub}, nil
}

// NewPrivateKey wraps an existing 64-byte Ed25519 private key (seed ||
// public key, the Go stdlib representation). Returns ErrInvalidKey if
// the input is not 64 bytes.
func NewPrivateKey(key []byte) (*PrivateKey, error) {
	if len(key) != stded25519.PrivateKeySize {
		return nil, fmt.Errorf("%w: got %d bytes, want %d", ErrInvalidKey, len(key), stded25519.PrivateKeySize)
	}
	priv := make(stded25519.PrivateKey, stded25519.PrivateKeySize)
	copy(priv, key)
	return &PrivateKey{key: priv}, nil
}

// NewPublicKey wraps an existing 32-byte Ed25519 public key. Returns
// ErrInvalidKey if the input is not 32 bytes.
func NewPublicKey(key []byte) (*PublicKey, error) {
	if len(key) != stded25519.PublicKeySize {
		return nil, fmt.Errorf("%w: got %d bytes, want %d", ErrInvalidKey, len(key), stded25519.PublicKeySize)
	}
	pub := make(stded25519.PublicKey, stded25519.PublicKeySize)
	copy(pub, key)
	return &PublicKey{key: pub}, nil
}

// StdKey returns the underlying stdlib crypto/ed25519.PrivateKey for
// interop with libraries that consume stdlib key types. The returned
// key is a copy. Returns nil if the underlying key is nil.
func (priv *PrivateKey) StdKey() stded25519.PrivateKey {
	if len(priv.key) == 0 {
		return nil
	}
	out := make(stded25519.PrivateKey, len(priv.key))
	copy(out, priv.key)
	return out
}

// Public derives the Ed25519 public key from this private key.
func (priv *PrivateKey) Public() *PublicKey {
	pub := priv.key.Public().(stded25519.PublicKey)
	return &PublicKey{key: pub}
}

// Sign produces a deterministic Ed25519 signature over message. Ed25519
// hashes internally — do NOT pre-hash the message. The signature is 64
// bytes. This method cannot fail for a valid private key.
func (priv *PrivateKey) Sign(message []byte) []byte {
	return stded25519.Sign(priv.key, message)
}

// Verify checks an Ed25519 signature against message using this public
// key. Returns true if valid, false otherwise.
func (pub *PublicKey) Verify(signature, message []byte) bool {
	return stded25519.Verify(pub.key, message, signature)
}

// Redact returns a truncated private-key fingerprint safe for logging.
// Returns the first 8 hex characters of the SHA-256 digest followed by
// "...". No raw key material is exposed.
func (priv *PrivateKey) Redact() string {
	sum := sha256.Sum256(priv.key)
	return hex.EncodeToString(sum[:4]) + "..."
}

// Bytes returns the raw 32-byte public key.
func (pub *PublicKey) Bytes() [32]byte {
	var out [32]byte
	copy(out[:], pub.key)
	return out
}

// Redact returns a truncated public-key fingerprint for logging.
// Returns the first 8 hex characters of the SHA-256 digest followed by
// "...".
func (pub *PublicKey) Redact() string {
	sum := sha256.Sum256(pub.key)
	return hex.EncodeToString(sum[:4]) + "..."
}

// Equal reports whether two public keys are equal in constant time.
// Returns false if other is nil.
func (pub *PublicKey) Equal(other *PublicKey) bool {
	if other == nil {
		return false
	}
	return subtle.ConstantTimeCompare(pub.key, other.key) == 1
}
