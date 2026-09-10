package secp256k1

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/bperin/trust/crypto/rand"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
)

// ErrInvalidKey is returned by [SEC 2 v2]; [RFC 6979]; [EIP-2] key
// parsing functions when a key is not the expected size.
var ErrInvalidKey = errors.New("secp256k1: invalid key length")

// ErrInvalidSignature is returned by [SEC 2 v2]; [RFC 6979]; [EIP-2]
// signature parsing or verification when a signature is malformed or
// violates [EIP-2] low-s canonicalization.
var ErrInvalidSignature = errors.New("secp256k1: invalid signature")

// PrivateKey is a [SEC 2 v2]; [RFC 6979]; [EIP-2] secp256k1 ECDSA
// private key. It wraps the decred dcrd v4 [*secp256k1.PrivateKey]. It
// must never be exposed via String(), Format(), GoString(),
// MarshalText(), or MarshalJSON(). Use Redact() for logging.
type PrivateKey struct {
	key *secp256k1.PrivateKey
}

// PublicKey is a [SEC 2 v2]; [RFC 6979]; [EIP-2] secp256k1 ECDSA public
// key. It wraps the decred dcrd v4 [*secp256k1.PublicKey] in compressed
// (33-byte) form.
type PublicKey struct {
	key *secp256k1.PublicKey
}

// GenerateKey generates a new [SEC 2 v2]; [RFC 6979]; [EIP-2]
// secp256k1 keypair using the OS CSPRNG via trust/crypto/rand.
func GenerateKey() (*PrivateKey, *PublicKey, error) {
	seed, err := rand.Bytes(32)
	if err != nil {
		return nil, nil, err
	}

	priv := secp256k1.PrivKeyFromBytes(seed)
	pub := priv.PubKey()

	return &PrivateKey{key: priv}, &PublicKey{key: pub}, nil
}

// NewPrivateKey wraps an existing 32-byte [SEC 2 v2]; [RFC 6979];
// [EIP-2] secp256k1 private key. Returns ErrInvalidKey if the input
// is not 32 bytes.
func NewPrivateKey(key []byte) (*PrivateKey, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("%w: got %d bytes, want 32", ErrInvalidKey, len(key))
	}
	priv := secp256k1.PrivKeyFromBytes(key)
	return &PrivateKey{key: priv}, nil
}

// NewPublicKey wraps an existing 33-byte compressed [SEC 2 v2];
// [RFC 6979]; [EIP-2] secp256k1 public key. Uncompressed (65-byte)
// keys are rejected. Returns ErrInvalidKey if the input is not 33
// bytes or cannot be parsed as a compressed public key.
func NewPublicKey(key []byte) (*PublicKey, error) {
	if len(key) != 33 {
		return nil, fmt.Errorf("%w: got %d bytes, want 33 (compressed)", ErrInvalidKey, len(key))
	}
	pub, err := secp256k1.ParsePubKey(key)
	if err != nil {
		return nil, fmt.Errorf("%w: parse failed: %v", ErrInvalidKey, err)
	}
	return &PublicKey{key: pub}, nil
}

// Public derives the [SEC 2 v2]; [RFC 6979]; [EIP-2] secp256k1 public
// key from this private key.
func (priv *PrivateKey) Public() *PublicKey {
	return &PublicKey{key: priv.key.PubKey()}
}

// Bytes returns the raw 32-byte [SEC 2 v2]; [RFC 6979]; [EIP-2]
// secp256k1 private key scalar. This is the value carried in the JWK
// "d" member per [RFC 8812] §3.1. The returned slice is a copy so the
// caller may not mutate the key material. This is a read-only
// serialization accessor — it does not perform any crypto operation.
func (priv *PrivateKey) Bytes() []byte {
	raw := priv.key.Serialize()
	out := make([]byte, len(raw))
	copy(out, raw)
	return out
}

// Sign produces a deterministic [SEC 2 v2]; [RFC 6979] secp256k1
// ECDSA signature over a 32-byte pre-computed hash. The caller
// chooses the hash algorithm (SHA-256 or Keccak-256) — this method
// does not hash the input. RFC 6979 deterministic nonces eliminate
// the catastrophic nonce-reuse failure. The dcrd library produces
// low-s canonical signatures per [EIP-2] automatically (BIP0062).
// The signature is 64 bytes: r (32 bytes) || s (32 bytes). No
// recovery id byte — public-key recovery is in PLAN-002.
func (priv *PrivateKey) Sign(hash []byte) ([]byte, error) {
	if len(hash) != 32 {
		return nil, fmt.Errorf("%w: hash must be 32 bytes, got %d", ErrInvalidSignature, len(hash))
	}

	sig := ecdsa.Sign(priv.key, hash)

	rVal := sig.R()
	sVal := sig.S()
	r := rVal.Bytes()
	s := sVal.Bytes()

	out := make([]byte, 64)
	copy(out[:32], r[:])
	copy(out[32:], s[:])

	return out, nil
}

// Verify checks a 64-byte [SEC 2 v2]; [RFC 6979] secp256k1 ECDSA
// signature against a 32-byte pre-computed hash using this public
// key. Returns true if the signature is valid and [EIP-2] low-s
// canonical, false otherwise. High-s signatures (s > n/2) are
// rejected as malleable per [EIP-2].
func (pub *PublicKey) Verify(signature, hash []byte) bool {
	if len(signature) != 64 || len(hash) != 32 {
		return false
	}

	var rBytes, sBytes [32]byte
	copy(rBytes[:], signature[:32])
	copy(sBytes[:], signature[32:])

	var r, s secp256k1.ModNScalar
	r.SetBytes(&rBytes)
	s.SetBytes(&sBytes)

	// Reject high-s per [EIP-2] — malleability defense.
	if s.IsOverHalfOrder() {
		return false
	}

	sig := ecdsa.NewSignature(&r, &s)
	return sig.Verify(hash, pub.key)
}

// Redact returns a truncated [SEC 2 v2]; [RFC 6979]; [EIP-2]
// private-key fingerprint safe for logging. It hashes the key with
// SHA-256 and returns the first 8 hex characters (4 bytes of the
// digest) followed by "...". No raw key material is ever exposed.
func (priv *PrivateKey) Redact() string {
	sum := sha256.Sum256(priv.key.Serialize())
	return hex.EncodeToString(sum[:4]) + "..."
}

// Bytes returns the raw 33-byte compressed [SEC 2 v2]; [RFC 6979];
// [EIP-2] public key.
func (pub *PublicKey) Bytes() []byte {
	return pub.key.SerializeCompressed()
}

// Redact returns a truncated [SEC 2 v2]; [RFC 6979]; [EIP-2]
// public-key fingerprint for logging. Public keys are not secret, but
// a SHA-256 prefix keeps logs readable and consistent with the
// private key fingerprint. Returns the first 8 hex characters (4
// bytes of the digest) followed by "...".
func (pub *PublicKey) Redact() string {
	sum := sha256.Sum256(pub.key.SerializeCompressed())
	return hex.EncodeToString(sum[:4]) + "..."
}

// Equal reports whether two public keys are equal in constant time
// per [SEC 2 v2]; [RFC 6979]; [EIP-2] security best practices. Returns
// false if other is nil.
func (pub *PublicKey) Equal(other *PublicKey) bool {
	if other == nil {
		return false
	}
	a := pub.key.SerializeCompressed()
	b := other.key.SerializeCompressed()
	return subtle.ConstantTimeCompare(a, b) == 1
}
