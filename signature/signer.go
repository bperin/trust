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

// Signer is the signing abstraction shared by local in-process keys
// and remote KMS-backed keys. It is defined here rather than in a
// consumer because both the authority and kms packages consume it,
// and placing it in either would create an import cycle.
//
// Implementations must be safe for concurrent use.
type Signer interface {
	// PublicKey returns the public half of the signing key as a
	// trust crypto public-key type (e.g. *ed25519.PublicKey).
	PublicKey(ctx context.Context) (crypto.PublicKey, error)

	// Sign produces a signature over digest. It returns ctx.Err()
	// if the context is canceled.
	Sign(ctx context.Context, digest []byte) ([]byte, error)
}

// compile-time check that LocalSigner satisfies Signer.
var _ Signer = (*LocalSigner)(nil)

// LocalSigner is a Signer backed by an in-process private key. It
// dispatches through the per-algorithm registry and is safe for
// concurrent use.
type LocalSigner struct {
	key crypto.PrivateKey
	pub crypto.PublicKey
	alg Algorithm
}

// NewLocalSigner constructs a LocalSigner for the given trust
// private-key type. It returns an error for a nil key, a
// non-signing key, or any unrecognized key type.
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

// PublicKey returns the public key derived at construction. It
// returns ctx.Err() if the context is canceled.
func (s *LocalSigner) PublicKey(ctx context.Context) (crypto.PublicKey, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return s.pub, nil
}

// Sign produces a signature over digest. It returns ctx.Err() if
// the context is canceled.
func (s *LocalSigner) Sign(ctx context.Context, digest []byte) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return Sign(s.alg, s.key, digest)
}

// publicKeyForPrivateKey derives the trust public key for a trust
// private key. It returns ErrUnsupportedAlgorithm for non-signing
// and unrecognized key types.
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
