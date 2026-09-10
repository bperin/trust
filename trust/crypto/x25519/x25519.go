package x25519

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/bperin/trust/crypto/rand"
	"golang.org/x/crypto/curve25519"
)

// ErrInvalidKey is returned by [RFC 7748] key parsing functions when a
// key is not 32 bytes.
var ErrInvalidKey = errors.New("x25519: key must be 32 bytes")

// PrivateKey is a Curve25519 private key for [RFC 7748] ECDH.
// It is 32 bytes and must never be exposed via String(), Format(),
// GoString(), MarshalText(), or MarshalJSON(). Use Redact() for
// logging.
type PrivateKey struct {
	key [32]byte
}

// PublicKey is a Curve25519 public key for [RFC 7748] ECDH.
type PublicKey struct {
	key [32]byte
}

// GenerateKey generates a new [RFC 7748] X25519 keypair using the OS
// CSPRNG via trust/crypto/rand.
func GenerateKey() (*PrivateKey, *PublicKey, error) {
	privBytes, err := rand.Bytes(32)
	if err != nil {
		return nil, nil, err
	}

	var priv PrivateKey
	copy(priv.key[:], privBytes)

	pub := priv.Public()
	return &priv, pub, nil
}

// NewPrivateKey wraps an existing 32-byte private key for [RFC 7748].
// Returns ErrInvalidKey if the input is not 32 bytes.
func NewPrivateKey(key []byte) (*PrivateKey, error) {
	if len(key) != 32 {
		return nil, ErrInvalidKey
	}
	var priv PrivateKey
	copy(priv.key[:], key)
	return &priv, nil
}

// NewPublicKey wraps an existing 32-byte public key for [RFC 7748].
// Returns ErrInvalidKey if the input is not 32 bytes.
func NewPublicKey(key []byte) (*PublicKey, error) {
	if len(key) != 32 {
		return nil, ErrInvalidKey
	}
	var pub PublicKey
	copy(pub.key[:], key)
	return &pub, nil
}

// Public derives the [RFC 7748] public key from this private key via
// scalar multiplication with the Curve25519 basepoint.
func (priv *PrivateKey) Public() *PublicKey {
	pub, err := curve25519.X25519(priv.key[:], curve25519.Basepoint)
	if err != nil {
		// X25519 with the basepoint never errors for a 32-byte scalar.
		// If it does, something is fundamentally broken.
		panic(fmt.Sprintf("x25519: basepoint multiplication failed: %v", err))
	}
	var out PublicKey
	copy(out.key[:], pub)
	return &out
}

// Bytes returns the raw 32-byte [RFC 7748] private key. This is the
// value carried in the JWK "d" member per [RFC 8037] §2. The returned
// array is a copy so the caller may not mutate the key material. This
// is a read-only serialization accessor — it does not perform any
// crypto operation.
func (priv *PrivateKey) Bytes() [32]byte {
	var out [32]byte
	copy(out[:], priv.key[:])
	return out
}

// SharedSecret computes the [RFC 7748] ECDH shared secret using this
// private key and the peer's public key. Returns a 32-byte shared
// secret.
//
// Per [RFC 7748] §6, an all-zero shared secret (resulting from a
// low-order peer point) is rejected and returns an error. Returns
// ErrInvalidKey if peer is nil.
func (priv *PrivateKey) SharedSecret(peer *PublicKey) ([]byte, error) {
	if peer == nil {
		return nil, ErrInvalidKey
	}
	shared, err := curve25519.X25519(priv.key[:], peer.key[:])
	if err != nil {
		return nil, err
	}
	return shared, nil
}

// Redact returns a truncated [RFC 7748] private-key fingerprint safe for
// logging. It hashes the key with SHA-256 and returns the first 8 hex
// characters (4 bytes of the digest) followed by "...". No raw key
// material is ever exposed.
func (priv *PrivateKey) Redact() string {
	sum := sha256.Sum256(priv.key[:])
	return hex.EncodeToString(sum[:4]) + "..."
}

// Bytes returns the raw 32-byte [RFC 7748] public key.
func (pub *PublicKey) Bytes() [32]byte {
	return pub.key
}

// Redact returns a truncated [RFC 7748] public-key fingerprint for
// logging. Public keys are not secret, but a SHA-256 prefix keeps
// logs readable and consistent with the private key fingerprint.
// Returns the first 8 hex characters (4 bytes of the digest) followed
// by "...".
func (pub *PublicKey) Redact() string {
	sum := sha256.Sum256(pub.key[:])
	return hex.EncodeToString(sum[:4]) + "..."
}

// Equal reports whether two public keys are equal in constant time
// per [RFC 7748] security best practices. Returns false if other is
// nil.
func (pub *PublicKey) Equal(other *PublicKey) bool {
	if other == nil {
		return false
	}
	return subtle.ConstantTimeCompare(pub.key[:], other.key[:]) == 1
}
