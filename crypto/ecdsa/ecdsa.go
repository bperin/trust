package ecdsa

import (
	"crypto"
	stdecdsa "crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
)

// Errors returned by this package.
var (
	// ErrUnsupportedCurve is returned when the curve is not P-256 or P-384.
	ErrUnsupportedCurve = errors.New("ecdsa: unsupported curve (want P-256 or P-384)")
	// ErrUnsupportedHash is returned when the hash does not match the
	// curve (SHA-256 for P-256, SHA-384 for P-384).
	ErrUnsupportedHash = errors.New("ecdsa: hash does not match curve (want SHA-256 for P-256, SHA-384 for P-384)")
	// ErrNilKey is returned when a nil key is passed to a constructor.
	ErrNilKey = errors.New("ecdsa: nil key")
)

// validateCurveHash returns an error if the curve is not P-256 or P-384,
// or if the hash does not match the curve.
func validateCurveHash(curve elliptic.Curve, hash crypto.Hash) error {
	switch curve {
	case elliptic.P256():
		if hash != crypto.SHA256 {
			return fmt.Errorf("%w: got %s for P-256", ErrUnsupportedHash, hash)
		}
	case elliptic.P384():
		if hash != crypto.SHA384 {
			return fmt.Errorf("%w: got %s for P-384", ErrUnsupportedHash, hash)
		}
	default:
		return ErrUnsupportedCurve
	}
	if !hash.Available() {
		return fmt.Errorf("%w: hash not available", ErrUnsupportedHash)
	}
	return nil
}

// PrivateKey is an ECDSA private key per [FIPS 186-4]. The curve
// (P-256 or P-384) and hash (SHA-256 or SHA-384) are bound at
// construction. Must never be exposed via String(), Format(),
// GoString(), MarshalText(), or MarshalJSON(). Use Redact() for logging.
type PrivateKey struct {
	key  *stdecdsa.PrivateKey
	hash crypto.Hash
}

// PublicKey is an ECDSA public key per [FIPS 186-4]. The curve and hash
// are bound at construction.
type PublicKey struct {
	key  *stdecdsa.PublicKey
	hash crypto.Hash
}

// GenerateKey generates a new ECDSA keypair on the given curve using
// the OS CSPRNG. The hash is bound to the curve: SHA-256 for P-256
// (ES256), SHA-384 for P-384 (ES384). Returns ErrUnsupportedCurve if
// the curve is not P-256 or P-384, and ErrUnsupportedHash if the hash
// does not match the curve.
func GenerateKey(curve elliptic.Curve, hash crypto.Hash) (*PrivateKey, *PublicKey, error) {
	if err := validateCurveHash(curve, hash); err != nil {
		return nil, nil, err
	}
	key, err := stdecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("ecdsa: key generation failed: %w", err)
	}
	priv := &PrivateKey{key: key, hash: hash}
	return priv, priv.Public(), nil
}

// NewPrivateKey wraps an existing stdlib *ecdsa.PrivateKey for signing.
// Validates the curve is P-256 or P-384 and the hash matches the curve.
// Returns ErrNilKey if key is nil.
func NewPrivateKey(key *stdecdsa.PrivateKey, hash crypto.Hash) (*PrivateKey, error) {
	if key == nil {
		return nil, ErrNilKey
	}
	if err := validateCurveHash(key.Curve, hash); err != nil {
		return nil, err
	}
	return &PrivateKey{key: key, hash: hash}, nil
}

// NewPublicKey wraps an existing stdlib *ecdsa.PublicKey for verification.
// Validates the curve is P-256 or P-384 and the hash matches the curve.
// Returns ErrNilKey if key is nil.
func NewPublicKey(key *stdecdsa.PublicKey, hash crypto.Hash) (*PublicKey, error) {
	if key == nil {
		return nil, ErrNilKey
	}
	if err := validateCurveHash(key.Curve, hash); err != nil {
		return nil, err
	}
	return &PublicKey{key: key, hash: hash}, nil
}

// Public derives the public key from this private key. Returns nil if
// the underlying key is nil.
func (priv *PrivateKey) Public() *PublicKey {
	if priv.key == nil {
		return nil
	}
	return &PublicKey{key: &priv.key.PublicKey, hash: priv.hash}
}

// Sign produces an ECDSA signature over message. The message is hashed
// with the bound hash, then signed using ecdsa.SignASN1 with
// crypto/rand.Reader. Signatures are randomized (not deterministic) and
// DER-encoded. Returns ErrNilKey if the underlying key is nil.
func (priv *PrivateKey) Sign(message []byte) ([]byte, error) {
	if priv.key == nil {
		return nil, ErrNilKey
	}
	h := priv.hash.New()
	h.Write(message)
	digest := h.Sum(nil)
	sig, err := stdecdsa.SignASN1(rand.Reader, priv.key, digest)
	if err != nil {
		return nil, fmt.Errorf("ecdsa: sign failed: %w", err)
	}
	return sig, nil
}

// Verify checks an ECDSA signature against message using this public
// key. Returns true if valid, false otherwise. The message is hashed
// with the bound hash. Signature must be DER-encoded. Returns false if
// the underlying key is nil.
func (pub *PublicKey) Verify(signature, message []byte) bool {
	if pub.key == nil {
		return false
	}
	h := pub.hash.New()
	h.Write(message)
	digest := h.Sum(nil)
	return stdecdsa.VerifyASN1(pub.key, digest, signature)
}

// Curve returns the elliptic curve (P-256 or P-384). Returns nil if
// the underlying key is nil.
func (priv *PrivateKey) Curve() elliptic.Curve {
	if priv.key == nil {
		return nil
	}
	return priv.key.Curve
}

// StdKey returns the underlying stdlib *crypto/ecdsa.PrivateKey for
// interop with libraries that consume stdlib key types. The returned
// key is a copy. Returns nil if the underlying key is nil.
func (priv *PrivateKey) StdKey() *stdecdsa.PrivateKey {
	if priv.key == nil {
		return nil
	}
	return &stdecdsa.PrivateKey{
		PublicKey: stdecdsa.PublicKey{
			Curve: priv.key.Curve,
			X:     new(big.Int).Set(priv.key.X),
			Y:     new(big.Int).Set(priv.key.Y),
		},
		D: new(big.Int).Set(priv.key.D),
	}
}

// Curve returns the elliptic curve (P-256 or P-384). Returns nil if
// the underlying key is nil.
func (pub *PublicKey) Curve() elliptic.Curve {
	if pub.key == nil {
		return nil
	}
	return pub.key.Curve
}

// X returns the public key x-coordinate. This is the value carried in
// the JWK "x" member per [RFC 7518] §6.2.1. Returns nil if the underlying
// key is nil.
func (pub *PublicKey) X() *big.Int {
	if pub.key == nil {
		return nil
	}
	return new(big.Int).Set(pub.key.X)
}

// Y returns the public key y-coordinate. This is the value carried in
// the JWK "y" member per [RFC 7518] §6.2.1. Returns nil if the underlying
// key is nil.
func (pub *PublicKey) Y() *big.Int {
	if pub.key == nil {
		return nil
	}
	return new(big.Int).Set(pub.key.Y)
}

// Redact returns a truncated private-key fingerprint safe for logging.
// Returns "nil..." if the underlying key is nil.
func (priv *PrivateKey) Redact() string {
	if priv.key == nil {
		return "nil..."
	}
	sum := sha256.Sum256(priv.key.D.Bytes())
	return hex.EncodeToString(sum[:4]) + "..."
}

// Redact returns a truncated public-key fingerprint for logging.
// Returns "nil..." if the underlying key is nil.
func (pub *PublicKey) Redact() string {
	if pub.key == nil {
		return "nil..."
	}
	enc := elliptic.Marshal(pub.key.Curve, pub.key.X, pub.key.Y)
	sum := sha256.Sum256(enc)
	return hex.EncodeToString(sum[:4]) + "..."
}

// Equal reports whether two public keys are equal in constant time.
// Returns false if either key is nil or if other is nil.
func (pub *PublicKey) Equal(other *PublicKey) bool {
	if other == nil {
		return false
	}
	if pub.key == nil || other.key == nil {
		return false
	}
	a := elliptic.Marshal(pub.key.Curve, pub.key.X, pub.key.Y)
	b := elliptic.Marshal(other.key.Curve, other.key.X, other.key.Y)
	return subtle.ConstantTimeCompare(a, b) == 1
}
