package signature

import (
	"context"
	"crypto"
	"fmt"

	"github.com/bperin/trust/crypto/ecdsa"
	"github.com/bperin/trust/crypto/ed25519"
	"github.com/bperin/trust/crypto/rsa"
	"github.com/bperin/trust/crypto/secp256k1"
	"github.com/bperin/trust/crypto/x25519"
)

// Signer is the consumer-side signing abstraction shared by local
// in-process keys and remote KMS-backed keys. It is defined in the
// signature package — not in a consumer — because both the authority
// and kms packages consume it, and placing it in either would create
// an import cycle.
//
// A Signer produces signatures over a caller-supplied digest through
// one of the registered algorithms: Ed25519 [RFC 8032], secp256k1
// [RFC 8812], ECDSA P-256/P-384 [FIPS 186-4], or RSA-PSS /
// RSA-PKCS1v1.5 [RFC 8017]. Implementations must be safe for
// concurrent use by multiple goroutines.
type Signer interface {
	// PublicKey returns the public half of the signing key as a
	// trust crypto public-key type (e.g. *ed25519.PublicKey). The
	// returned key resolves to the signer's algorithm via
	// AlgorithmForPublicKey.
	PublicKey(ctx context.Context) (crypto.PublicKey, error)

	// Sign produces a signature over digest. The digest is passed
	// through to the registered algorithm's sign closure unchanged —
	// per-algorithm pre-hashing (if any) happens inside the closure,
	// not here. Returns ctx.Err() if the context is canceled.
	Sign(ctx context.Context, digest []byte) ([]byte, error)
}

// compile-time check that LocalSigner satisfies Signer.
var _ Signer = (*LocalSigner)(nil)

// LocalSigner is a Signer backed by an in-process private key. It
// wraps one of the trust crypto private-key types and dispatches
// through the per-algorithm registry: Ed25519 [RFC 8032], secp256k1
// [RFC 8812], ECDSA P-256/P-384 [FIPS 186-4], RSA-PSS and
// RSA-PKCS1v1.5 [RFC 8017].
//
// The resolved Algorithm and derived public key are cached at
// construction, so PublicKey and Sign do no repeated derivation work.
// LocalSigner performs no pre-hashing itself — Sign delegates to the
// registry, whose closures pre-hash per algorithm. LocalSigner is
// immutable after construction and safe for concurrent use.
type LocalSigner struct {
	key crypto.PrivateKey
	pub crypto.PublicKey
	alg Algorithm
}

// NewLocalSigner constructs a LocalSigner for the given trust
// private-key type. The key's Algorithm is resolved via
// AlgorithmForPrivateKey and its public half via
// publicKeyForPrivateKey; both are cached on the signer. Returns an
// error for a nil key, a non-signing key (*x25519.PrivateKey), or any
// unrecognized key type — the latter two wrap
// ErrUnsupportedAlgorithm.
func NewLocalSigner(key crypto.PrivateKey) (*LocalSigner, error) {
	if key == nil {
		return nil, fmt.Errorf("signature: NewLocalSigner: nil private key")
	}
	alg, err := AlgorithmForPrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("signature: NewLocalSigner: %w", err)
	}
	pub, err := publicKeyForPrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("signature: NewLocalSigner: %w", err)
	}
	return &LocalSigner{key: key, pub: pub, alg: alg}, nil
}

// PublicKey returns the public key derived at construction. The
// concrete type matches the private key's trust public-key type
// (*ed25519.PublicKey, *secp256k1.PublicKey, *ecdsa.PublicKey,
// *rsa.PSSPublicKey, or *rsa.PKCS1PublicKey). Returns ctx.Err() if
// the context is canceled.
func (s *LocalSigner) PublicKey(ctx context.Context) (crypto.PublicKey, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return s.pub, nil
}

// Sign produces a signature over digest by delegating to
// signature.Sign(s.alg, s.key, digest). The digest is passed through
// unchanged — the registered sign closure performs any pre-hashing
// the algorithm requires (Ed25519 hashes internally per [RFC 8032];
// ECDSA [FIPS 186-4] and RSA [RFC 8017] pre-hash; secp256k1
// [RFC 8812] signs the digest as-is). Returns ctx.Err() if the
// context is canceled.
func (s *LocalSigner) Sign(ctx context.Context, digest []byte) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return Sign(s.alg, s.key, digest)
}

// publicKeyForPrivateKey derives the trust public key for a trust
// private key by calling each key type's Public method. It mirrors
// AlgorithmForPrivateKey's accepted key set: *x25519.PrivateKey is
// rejected (x25519 is not a signing key) even though it exposes a
// Public method, and unknown types are rejected. Both failures wrap
// ErrUnsupportedAlgorithm. Package-private — this is internal key
// derivation, not a public API.
func publicKeyForPrivateKey(key crypto.PrivateKey) (crypto.PublicKey, error) {
	switch k := key.(type) {
	case *ed25519.PrivateKey:
		return k.Public(), nil
	case *secp256k1.PrivateKey:
		return k.Public(), nil
	case *ecdsa.PrivateKey:
		return k.Public(), nil
	case *rsa.PSSPrivateKey:
		return k.Public(), nil
	case *rsa.PKCS1PrivateKey:
		return k.Public(), nil
	case *x25519.PrivateKey:
		return nil, fmt.Errorf("%w: x25519 is not a signing key", ErrUnsupportedAlgorithm)
	default:
		return nil, fmt.Errorf("%w: key type %T", ErrUnsupportedAlgorithm, key)
	}
}
