package rsa

import (
	"crypto"
	stdrsa "crypto/rsa"
	"crypto/sha256"
	_ "crypto/sha512" // register SHA-384 and SHA-512 so hash.Available() returns true
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"

	"github.com/bperin/trust/crypto/rand"
)

// Minimum key size enforced at construction.
const minKeyBits = 2048

// Errors returned by this package.
var (
	// ErrKeyTooSmall is returned when an [RFC 8017] RSA key is smaller
	// than 2048 bits.
	ErrKeyTooSmall = errors.New("rsa: key size below 2048 bits")
	// ErrUnsupportedHash is returned when the hash is not SHA-256,
	// SHA-384, or SHA-512.
	ErrUnsupportedHash = errors.New("rsa: unsupported hash (want SHA-256, SHA-384, or SHA-512)")
	// ErrNilKey is returned when a nil key or nil key component (modulus
	// or private exponent) is passed to a constructor.
	ErrNilKey = errors.New("rsa: nil key")
)

// rsaPrivateKey is an unexported holder for the stdlib private key and
// the bound hash. PSS and PKCS1v1.5 exported types embed this.
type rsaPrivateKey struct {
	key  *stdrsa.PrivateKey
	hash crypto.Hash
}

// rsaPublicKey is an unexported holder for the stdlib public key and
// the bound hash.
type rsaPublicKey struct {
	key  *stdrsa.PublicKey
	hash crypto.Hash
}

// validateHash returns ErrUnsupportedHash if the hash is not SHA-256,
// SHA-384, or SHA-512, or if it is not available.
func validateHash(hash crypto.Hash) error {
	switch hash {
	case crypto.SHA256, crypto.SHA384, crypto.SHA512:
		if !hash.Available() {
			return fmt.Errorf("%w: hash not available", ErrUnsupportedHash)
		}
		return nil
	default:
		return ErrUnsupportedHash
	}
}

// validateKeySize returns ErrKeyTooSmall if the key is below 2048 bits.
func validateKeySize(bits int) error {
	if bits < minKeyBits {
		return fmt.Errorf("%w: got %d bits, want >= %d", ErrKeyTooSmall, bits, minKeyBits)
	}
	return nil
}

// constantTimeIntEqual compares two ints in constant time using
// crypto/subtle.ConstantTimeCompare on fixed-size big-endian bytes.
// This avoids == on key components per the project security rules.
func constantTimeIntEqual(a, b int) bool {
	var ab, bb [8]byte
	binary.BigEndian.PutUint64(ab[:], uint64(a))
	binary.BigEndian.PutUint64(bb[:], uint64(b))
	return subtle.ConstantTimeCompare(ab[:], bb[:]) == 1
}

// validatePrivateKey checks for nil key, nil modulus, and nil private
// exponent. Returns ErrNilKey (wrapped with a detail message) on failure.
func validatePrivateKey(key *stdrsa.PrivateKey) error {
	if key == nil {
		return fmt.Errorf("%w: nil private key", ErrNilKey)
	}
	if key.N == nil {
		return fmt.Errorf("%w: nil modulus", ErrNilKey)
	}
	if key.D == nil {
		return fmt.Errorf("%w: nil private exponent", ErrNilKey)
	}
	return nil
}

// validatePublicKey checks for nil key and nil modulus. Returns
// ErrNilKey (wrapped with a detail message) on failure.
func validatePublicKey(key *stdrsa.PublicKey) error {
	if key == nil {
		return fmt.Errorf("%w: nil public key", ErrNilKey)
	}
	if key.N == nil {
		return fmt.Errorf("%w: nil modulus", ErrNilKey)
	}
	return nil
}

// N returns the [RFC 8017] RSA public modulus. This is the value
// carried in the JWK "n" member per [RFC 7518] §6.3.1. The returned
// value is a copy so the caller may not mutate the key material. This
// is a read-only serialization accessor — it does not perform any
// crypto operation. The method is promoted to PSSPublicKey and
// PKCS1PublicKey.
func (r rsaPublicKey) N() *big.Int {
	return new(big.Int).Set(r.key.N)
}

// E returns the [RFC 8017] RSA public exponent. This is the value
// carried in the JWK "e" member per [RFC 7518] §6.3.1. This is a
// read-only serialization accessor — it does not perform any crypto
// operation. The method is promoted to PSSPublicKey and
// PKCS1PublicKey.
func (r rsaPublicKey) E() int {
	return r.key.E
}

// Hash returns the [RFC 8017] hash bound to this key at construction.
// The JWK "alg" member is derived from the scheme (PSS or PKCS1v1.5,
// determined by the concrete type) and this hash. This is a read-only
// serialization accessor. The method is promoted to PSSPublicKey and
// PKCS1PublicKey.
func (r rsaPublicKey) Hash() crypto.Hash {
	return r.hash
}

// D returns the [RFC 8017] RSA private exponent. This is the value
// carried in the JWK "d" member per [RFC 7518] §6.3.2. The returned
// value is a copy so the caller may not mutate the key material. This
// is a read-only serialization accessor — it does not perform any
// crypto operation. The method is promoted to PSSPrivateKey and
// PKCS1PrivateKey.
func (r rsaPrivateKey) D() *big.Int {
	return new(big.Int).Set(r.key.D)
}

// Hash returns the [RFC 8017] hash bound to this key at construction.
// The JWK "alg" member is derived from the scheme (PSS or PKCS1v1.5,
// determined by the concrete type) and this hash. This is a read-only
// serialization accessor. The method is promoted to PSSPrivateKey and
// PKCS1PrivateKey.
func (r rsaPrivateKey) Hash() crypto.Hash {
	return r.hash
}

// --- PSS ---

// PSSPrivateKey is an [RFC 8017] (PKCS#1 v2.2, PSS) RSA private key.
// The hash is bound at construction; Sign uses that hash. PSS salt
// length is fixed to the hash output length. Must never be exposed via
// String(), Format(), GoString(), MarshalText(), or MarshalJSON().
// Use Redact() for logging.
type PSSPrivateKey struct {
	rsaPrivateKey
}

// PSSPublicKey is an [RFC 8017] (PKCS#1 v2.2, PSS) RSA public key.
// The hash is bound at construction; Verify uses that hash.
type PSSPublicKey struct {
	rsaPublicKey
}

// GeneratePSSKey generates a new [RFC 8017] (PKCS#1 v2.2, PSS) RSA
// keypair of the given bit size using the OS CSPRNG via
// trust/crypto/rand. The hash is bound to the key for all signing
// and verification. Returns ErrKeyTooSmall if bits < 2048, and
// ErrUnsupportedHash if the hash is not SHA-256, SHA-384, or SHA-512.
func GeneratePSSKey(bits int, hash crypto.Hash) (*PSSPrivateKey, *PSSPublicKey, error) {
	if err := validateKeySize(bits); err != nil {
		return nil, nil, err
	}
	if err := validateHash(hash); err != nil {
		return nil, nil, err
	}
	key, err := stdrsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, nil, fmt.Errorf("rsa: key generation failed: %w", err)
	}
	priv := &PSSPrivateKey{rsaPrivateKey{key: key, hash: hash}}
	return priv, priv.Public(), nil
}

// NewPSSPrivateKey wraps an existing stdlib *rsa.PrivateKey for
// [RFC 8017] (PKCS#1 v2.2, PSS) signing. Validates key size >= 2048
// bits and hash is SHA-256/384/512. The hash is bound for all signing.
func NewPSSPrivateKey(key *stdrsa.PrivateKey, hash crypto.Hash) (*PSSPrivateKey, error) {
	if err := validatePrivateKey(key); err != nil {
		return nil, err
	}
	if err := validateKeySize(key.N.BitLen()); err != nil {
		return nil, err
	}
	if err := validateHash(hash); err != nil {
		return nil, err
	}
	return &PSSPrivateKey{rsaPrivateKey{key: key, hash: hash}}, nil
}

// NewPSSPublicKey wraps an existing stdlib *rsa.PublicKey for
// [RFC 8017] (PKCS#1 v2.2, PSS) verification. Validates key size >=
// 2048 bits and hash is SHA-256/384/512. The hash is bound for all
// verification.
func NewPSSPublicKey(key *stdrsa.PublicKey, hash crypto.Hash) (*PSSPublicKey, error) {
	if err := validatePublicKey(key); err != nil {
		return nil, err
	}
	if err := validateKeySize(key.N.BitLen()); err != nil {
		return nil, err
	}
	if err := validateHash(hash); err != nil {
		return nil, err
	}
	return &PSSPublicKey{rsaPublicKey{key: key, hash: hash}}, nil
}

// Public derives the [RFC 8017] (PKCS#1 v2.2, PSS) public key from
// this private key.
func (priv *PSSPrivateKey) Public() *PSSPublicKey {
	return &PSSPublicKey{rsaPublicKey{key: &priv.key.PublicKey, hash: priv.hash}}
}

// Sign produces an [RFC 8017] (PKCS#1 v2.2, PSS) signature over
// message. The message is hashed with the bound hash, then signed
// with PSS using salt length equal to the hash output length. The
// randomness for the salt comes from trust/crypto/rand.Reader.
func (priv *PSSPrivateKey) Sign(message []byte) ([]byte, error) {
	h := priv.hash.New()
	h.Write(message)
	digest := h.Sum(nil)
	sig, err := stdrsa.SignPSS(rand.Reader, priv.key, priv.hash, digest, &stdrsa.PSSOptions{
		SaltLength: stdrsa.PSSSaltLengthEqualsHash,
	})
	if err != nil {
		return nil, fmt.Errorf("rsa: PSS sign failed: %w", err)
	}
	return sig, nil
}

// Verify checks an [RFC 8017] (PKCS#1 v2.2, PSS) signature against
// message using this public key. Returns true if valid, false
// otherwise. The message is hashed with the bound hash; PSS salt
// length is set to PSSSaltLengthEqualsHash for verification.
func (pub *PSSPublicKey) Verify(signature, message []byte) bool {
	h := pub.hash.New()
	h.Write(message)
	digest := h.Sum(nil)
	err := stdrsa.VerifyPSS(pub.key, pub.hash, digest, signature, &stdrsa.PSSOptions{
		SaltLength: stdrsa.PSSSaltLengthEqualsHash,
	})
	return err == nil
}

// Redact returns a truncated [RFC 8017] (PKCS#1 v2.2, PSS) private-key
// fingerprint safe for logging. It hashes the private exponent D with
// SHA-256 and returns the first 8 hex characters (4 bytes of the digest)
// followed by "...". No raw key material is ever exposed — SHA-256 is
// one-way. This matches the ed25519 pattern where the private key
// fingerprint hashes secret material, distinct from the public key
// fingerprint which hashes the public modulus.
func (priv *PSSPrivateKey) Redact() string {
	sum := sha256.Sum256(priv.key.D.Bytes())
	return hex.EncodeToString(sum[:4]) + "..."
}

// Redact returns a truncated [RFC 8017] (PKCS#1 v2.2, PSS) public-key
// fingerprint for logging. SHA-256 prefix, 8 hex chars + "...".
func (pub *PSSPublicKey) Redact() string {
	sum := sha256.Sum256(pub.key.N.Bytes())
	return hex.EncodeToString(sum[:4]) + "..."
}

// Equal reports whether two [RFC 8017] (PKCS#1 v2.2, PSS) public keys
// are equal in constant time. Returns false if other is nil.
func (pub *PSSPublicKey) Equal(other *PSSPublicKey) bool {
	if other == nil {
		return false
	}
	return subtle.ConstantTimeCompare(pub.key.N.Bytes(), other.key.N.Bytes()) == 1 &&
		constantTimeIntEqual(pub.key.E, other.key.E)
}

// --- PKCS1v1.5 ---

// PKCS1PrivateKey is an [RFC 8017] §8.2 (PKCS1v1.5) RSA private key.
// The hash is bound at construction; Sign uses that hash. Must never
// be exposed via String(), Format(), GoString(), MarshalText(), or
// MarshalJSON(). Use Redact() for logging.
type PKCS1PrivateKey struct {
	rsaPrivateKey
}

// PKCS1PublicKey is an [RFC 8017] §8.2 (PKCS1v1.5) RSA public key.
// The hash is bound at construction; Verify uses that hash.
type PKCS1PublicKey struct {
	rsaPublicKey
}

// GeneratePKCS1Key generates a new [RFC 8017] §8.2 (PKCS1v1.5) RSA
// keypair of the given bit size using the OS CSPRNG via
// trust/crypto/rand. The hash is bound to the key. Returns
// ErrKeyTooSmall if bits < 2048, and ErrUnsupportedHash if the hash
// is not SHA-256, SHA-384, or SHA-512.
func GeneratePKCS1Key(bits int, hash crypto.Hash) (*PKCS1PrivateKey, *PKCS1PublicKey, error) {
	if err := validateKeySize(bits); err != nil {
		return nil, nil, err
	}
	if err := validateHash(hash); err != nil {
		return nil, nil, err
	}
	key, err := stdrsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, nil, fmt.Errorf("rsa: key generation failed: %w", err)
	}
	priv := &PKCS1PrivateKey{rsaPrivateKey{key: key, hash: hash}}
	return priv, priv.Public(), nil
}

// NewPKCS1PrivateKey wraps an existing stdlib *rsa.PrivateKey for
// [RFC 8017] §8.2 (PKCS1v1.5) signing. Validates key size >= 2048
// bits and hash is SHA-256/384/512.
func NewPKCS1PrivateKey(key *stdrsa.PrivateKey, hash crypto.Hash) (*PKCS1PrivateKey, error) {
	if err := validatePrivateKey(key); err != nil {
		return nil, err
	}
	if err := validateKeySize(key.N.BitLen()); err != nil {
		return nil, err
	}
	if err := validateHash(hash); err != nil {
		return nil, err
	}
	return &PKCS1PrivateKey{rsaPrivateKey{key: key, hash: hash}}, nil
}

// NewPKCS1PublicKey wraps an existing stdlib *rsa.PublicKey for
// [RFC 8017] §8.2 (PKCS1v1.5) verification. Validates key size >=
// 2048 bits and hash is SHA-256/384/512.
func NewPKCS1PublicKey(key *stdrsa.PublicKey, hash crypto.Hash) (*PKCS1PublicKey, error) {
	if err := validatePublicKey(key); err != nil {
		return nil, err
	}
	if err := validateKeySize(key.N.BitLen()); err != nil {
		return nil, err
	}
	if err := validateHash(hash); err != nil {
		return nil, err
	}
	return &PKCS1PublicKey{rsaPublicKey{key: key, hash: hash}}, nil
}

// Public derives the [RFC 8017] §8.2 (PKCS1v1.5) public key from this
// private key.
func (priv *PKCS1PrivateKey) Public() *PKCS1PublicKey {
	return &PKCS1PublicKey{rsaPublicKey{key: &priv.key.PublicKey, hash: priv.hash}}
}

// Sign produces an [RFC 8017] §8.2 (PKCS1v1.5) signature over message.
// The message is hashed with the bound hash, then signed with
// PKCS1v1.5. PKCS1v1.5 is deterministic: same key + message always
// produces the same signature.
func (priv *PKCS1PrivateKey) Sign(message []byte) ([]byte, error) {
	h := priv.hash.New()
	h.Write(message)
	digest := h.Sum(nil)
	sig, err := stdrsa.SignPKCS1v15(rand.Reader, priv.key, priv.hash, digest)
	if err != nil {
		return nil, fmt.Errorf("rsa: PKCS1v1.5 sign failed: %w", err)
	}
	return sig, nil
}

// Verify checks an [RFC 8017] §8.2 (PKCS1v1.5) signature against
// message using this public key. Returns true if valid, false
// otherwise. The message is hashed with the bound hash.
func (pub *PKCS1PublicKey) Verify(signature, message []byte) bool {
	h := pub.hash.New()
	h.Write(message)
	digest := h.Sum(nil)
	err := stdrsa.VerifyPKCS1v15(pub.key, pub.hash, digest, signature)
	return err == nil
}

// Redact returns a truncated [RFC 8017] §8.2 (PKCS1v1.5) private-key
// fingerprint safe for logging. It hashes the private exponent D with
// SHA-256 and returns the first 8 hex characters (4 bytes of the digest)
// followed by "...". No raw key material is ever exposed — SHA-256 is
// one-way. This matches the ed25519 pattern where the private key
// fingerprint hashes secret material, distinct from the public key
// fingerprint which hashes the public modulus.
func (priv *PKCS1PrivateKey) Redact() string {
	sum := sha256.Sum256(priv.key.D.Bytes())
	return hex.EncodeToString(sum[:4]) + "..."
}

// Redact returns a truncated [RFC 8017] §8.2 (PKCS1v1.5) public-key
// fingerprint for logging. SHA-256 prefix, 8 hex chars + "...".
func (pub *PKCS1PublicKey) Redact() string {
	sum := sha256.Sum256(pub.key.N.Bytes())
	// Ensure we don't accidentally match raw key bytes by taking sha256 sum
	// and truncating, which already hashes N.
	return hex.EncodeToString(sum[:4]) + "..."
}

// Equal reports whether two [RFC 8017] §8.2 (PKCS1v1.5) public keys
// are equal in constant time. Returns false if other is nil.
func (pub *PKCS1PublicKey) Equal(other *PKCS1PublicKey) bool {
	if other == nil {
		return false
	}
	return subtle.ConstantTimeCompare(pub.key.N.Bytes(), other.key.N.Bytes()) == 1 &&
		constantTimeIntEqual(pub.key.E, other.key.E)
}
