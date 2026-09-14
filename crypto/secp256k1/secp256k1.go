package secp256k1

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
)

// ErrInvalidKey is returned by key parsing functions when a key is not
// the expected size.
var ErrInvalidKey = errors.New("secp256k1: invalid key length")

// ErrInvalidSignature is returned by signature parsing or verification
// when a signature is malformed or violates [EIP-2] low-s
// canonicalization.
var ErrInvalidSignature = errors.New("secp256k1: invalid signature")

// ErrInvalidScalar is returned by NewPrivateKey when the 32-byte private
// key is zero or greater than or equal to the secp256k1 group order n.
// The input is rejected before any modular reduction so an out-of-range
// value can never be silently mapped onto a valid key.
var ErrInvalidScalar = errors.New("secp256k1: private key scalar out of range [1, n-1]")

// PrivateKey is a secp256k1 ECDSA private key. It wraps the decred dcrd
// v4 *secp256k1.PrivateKey. It must never be exposed via String(),
// Format(), GoString(), MarshalText(), or MarshalJSON(). Use Redact()
// for logging.
type PrivateKey struct {
	key *secp256k1.PrivateKey
}

// PublicKey is a secp256k1 ECDSA public key. It wraps the decred dcrd
// v4 *secp256k1.PublicKey in compressed (33-byte) form.
type PublicKey struct {
	key *secp256k1.PublicKey
}

// GenerateKey generates a new secp256k1 keypair using the OS CSPRNG
// with rejection sampling: a 32-byte candidate is drawn and resampled
// until it is a valid private scalar in [1, n-1]. The chance of a
// single rejection is roughly 2^-128, so the loop effectively runs once.
func GenerateKey() (*PrivateKey, *PublicKey, error) {
	for {
		var seed [32]byte
		if _, err := rand.Read(seed[:]); err != nil {
			return nil, nil, fmt.Errorf("secp256k1: generate key: %w", err)
		}
		var scalar secp256k1.ModNScalar
		overflow := scalar.SetBytes(&seed)
		// SetBytes reports whether the candidate was >= n; a zero
		// scalar is likewise invalid. Resample on either.
		if overflow == 0 && !scalar.IsZero() {
			priv := secp256k1.NewPrivateKey(&scalar)
			return &PrivateKey{key: priv}, &PublicKey{key: priv.PubKey()}, nil
		}
	}
}

// NewPrivateKey wraps an existing 32-byte secp256k1 private key.
// Returns ErrInvalidKey if the input is not 32 bytes. Returns
// ErrInvalidScalar if the scalar is zero or greater than or equal to
// the group order n.
func NewPrivateKey(key []byte) (*PrivateKey, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("%w: got %d bytes, want 32", ErrInvalidKey, len(key))
	}
	var b [32]byte
	copy(b[:], key)
	var scalar secp256k1.ModNScalar
	if scalar.SetBytes(&b) != 0 {
		return nil, fmt.Errorf("%w: scalar >= group order n", ErrInvalidScalar)
	}
	if scalar.IsZero() {
		return nil, fmt.Errorf("%w: scalar is zero", ErrInvalidScalar)
	}
	return &PrivateKey{key: secp256k1.NewPrivateKey(&scalar)}, nil
}

// NewPublicKey wraps an existing 33-byte compressed secp256k1 public
// key. Uncompressed (65-byte) keys are rejected. Returns ErrInvalidKey
// if the input is not 33 bytes or cannot be parsed.
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

// Public derives the secp256k1 public key from this private key.
func (priv *PrivateKey) Public() *PublicKey {
	return &PublicKey{key: priv.key.PubKey()}
}

// Bytes returns the raw 32-byte private key scalar. This is the value
// carried in the JWK "d" member per [RFC 8812] §3.1. The returned slice
// is a copy.
func (priv *PrivateKey) Bytes() []byte {
	raw := priv.key.Serialize()
	out := make([]byte, len(raw))
	copy(out, raw)
	return out
}

// Sign produces a deterministic secp256k1 ECDSA signature over a 32-byte
// pre-computed hash per [RFC 6979]. The caller chooses the hash algorithm
// (SHA-256 or Keccak-256) — this method does not hash the input. The
// signature is 64 bytes: r (32 bytes) || s (32 bytes), low-s canonical
// per [EIP-2].
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

// Verify checks a 64-byte secp256k1 ECDSA signature against a 32-byte
// pre-computed hash. Returns true if the signature is valid and low-s
// canonical per [EIP-2], false otherwise. High-s signatures (s > n/2)
// are rejected as malleable.
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

// Redact returns a truncated private-key fingerprint safe for logging.
// Returns the first 8 hex characters of the SHA-256 digest followed by
// "...". No raw key material is exposed.
func (priv *PrivateKey) Redact() string {
	sum := sha256.Sum256(priv.key.Serialize())
	return hex.EncodeToString(sum[:4]) + "..."
}

// Bytes returns the raw 33-byte compressed public key.
func (pub *PublicKey) Bytes() []byte {
	return pub.key.SerializeCompressed()
}

// BytesUncompressed returns the 65-byte uncompressed encoding of the
// public key per [SEC 1 v2] §2.3.3: 0x04 || X || Y. This is the form
// Ethereum uses for address derivation — Keccak-256 is taken over the
// 64-byte X || Y (the 0x04 prefix is stripped by the caller). The
// returned slice is a copy.
func (pub *PublicKey) BytesUncompressed() []byte {
	raw := pub.key.SerializeUncompressed()
	out := make([]byte, len(raw))
	copy(out, raw)
	return out
}

// Redact returns a truncated public-key fingerprint for logging.
// Returns the first 8 hex characters of the SHA-256 digest followed by
// "...".
func (pub *PublicKey) Redact() string {
	sum := sha256.Sum256(pub.key.SerializeCompressed())
	return hex.EncodeToString(sum[:4]) + "..."
}

// Equal reports whether two public keys are equal in constant time.
// Returns false if other is nil.
func (pub *PublicKey) Equal(other *PublicKey) bool {
	if other == nil {
		return false
	}
	a := pub.key.SerializeCompressed()
	b := other.key.SerializeCompressed()
	return subtle.ConstantTimeCompare(a, b) == 1
}
