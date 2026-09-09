package ed25519

import (
	stded25519 "crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/bperin/trust/crypto/rand"
)

// ErrInvalidKey is returned when an [RFC 8037]; [FIPS 186-5] Ed25519
// key is not the expected size.
var ErrInvalidKey = errors.New("ed25519: invalid key length")

// PrivateKey is an [RFC 8037]; [FIPS 186-5] Ed25519 private key. It
// wraps the Go stdlib [crypto/ed25519.PrivateKey] (64 bytes: seed ||
// public key). It must never be exposed via String(), Format(),
// GoString(), MarshalText(), or MarshalJSON(). Use Redact() for
// logging.
type PrivateKey struct {
	key stded25519.PrivateKey
}

// PublicKey is an [RFC 8037]; [FIPS 186-5] Ed25519 public key. It wraps
// the Go stdlib [crypto/ed25519.PublicKey] (32 bytes).
type PublicKey struct {
	key stded25519.PublicKey
}

// GenerateKey generates a new [RFC 8037]; [FIPS 186-5] Ed25519 keypair
// using the OS CSPRNG via trust/crypto/rand.
func GenerateKey() (*PrivateKey, *PublicKey, error) {
	seed, err := rand.Bytes(stded25519.SeedSize)
	if err != nil {
		return nil, nil, err
	}

	priv := stded25519.NewKeyFromSeed(seed)
	pub := priv.Public().(stded25519.PublicKey)

	return &PrivateKey{key: priv}, &PublicKey{key: pub}, nil
}

// NewPrivateKey wraps an existing 64-byte [RFC 8037]; [FIPS 186-5]
// Ed25519 private key (seed || public key, the Go stdlib
// representation). Returns ErrInvalidKey if the input is not 64 bytes.
func NewPrivateKey(key []byte) (*PrivateKey, error) {
	if len(key) != stded25519.PrivateKeySize {
		return nil, fmt.Errorf("%w: got %d bytes, want %d", ErrInvalidKey, len(key), stded25519.PrivateKeySize)
	}
	priv := make(stded25519.PrivateKey, stded25519.PrivateKeySize)
	copy(priv, key)
	return &PrivateKey{key: priv}, nil
}

// NewPublicKey wraps an existing 32-byte [RFC 8037]; [FIPS 186-5]
// Ed25519 public key. Returns ErrInvalidKey if the input is not 32
// bytes.
func NewPublicKey(key []byte) (*PublicKey, error) {
	if len(key) != stded25519.PublicKeySize {
		return nil, fmt.Errorf("%w: got %d bytes, want %d", ErrInvalidKey, len(key), stded25519.PublicKeySize)
	}
	pub := make(stded25519.PublicKey, stded25519.PublicKeySize)
	copy(pub, key)
	return &PublicKey{key: pub}, nil
}

// Public derives the [RFC 8037]; [FIPS 186-5] Ed25519 public key from
// this private key. The stdlib PrivateKey.Public() returns a
// crypto.PublicKey interface; this method type-asserts it to
// ed25519.PublicKey.
func (priv *PrivateKey) Public() *PublicKey {
	pub := priv.key.Public().(stded25519.PublicKey)
	return &PublicKey{key: pub}
}

// Sign produces a deterministic [RFC 8037]; [FIPS 186-5] Ed25519
// signature over message. Ed25519 hashes internally per [RFC 8032]
// §2.6 — do NOT pre-hash the message. The signature is 64 bytes.
// Signing is deterministic: the same key and message always produce
// the same signature. This method cannot fail for a valid private key.
func (priv *PrivateKey) Sign(message []byte) []byte {
	return stded25519.Sign(priv.key, message)
}

// Verify checks an [RFC 8037]; [FIPS 186-5] Ed25519 signature against
// message using this public key. Returns true if the signature is
// valid, false otherwise. The stdlib ed25519.Verify is already
// constant-time.
func (pub *PublicKey) Verify(signature, message []byte) bool {
	return stded25519.Verify(pub.key, message, signature)
}

// Redact returns a truncated [RFC 8037]; [FIPS 186-5] private-key
// fingerprint safe for logging. It hashes the key with SHA-256 and
// returns the first 8 hex characters (4 bytes of the digest) followed
// by "...". No raw key material is ever exposed.
func (priv *PrivateKey) Redact() string {
	sum := sha256.Sum256(priv.key)
	return hex.EncodeToString(sum[:4]) + "..."
}

// Bytes returns the raw 32-byte [RFC 8037]; [FIPS 186-5] public key.
func (pub *PublicKey) Bytes() [32]byte {
	var out [32]byte
	copy(out[:], pub.key)
	return out
}

// Redact returns a truncated [RFC 8037]; [FIPS 186-5] public-key
// fingerprint for logging. Public keys are not secret, but a SHA-256
// prefix keeps logs readable and consistent with the private key
// fingerprint. Returns the first 8 hex characters (4 bytes of the
// digest) followed by "...".
func (pub *PublicKey) Redact() string {
	sum := sha256.Sum256(pub.key)
	return hex.EncodeToString(sum[:4]) + "..."
}

// Equal reports whether two public keys are equal in constant time
// per [RFC 8037]; [FIPS 186-5] security best practices. Returns false
// if other is nil.
func (pub *PublicKey) Equal(other *PublicKey) bool {
	if other == nil {
		return false
	}
	return subtle.ConstantTimeCompare(pub.key, other.key) == 1
}
