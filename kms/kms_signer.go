package kms

import (
	"context"
	"crypto"
	"crypto/sha256"
	"fmt"

	"github.com/bperin/trust/crypto/hash"
	"github.com/bperin/trust/signature"
)

// compile-time check that KMSSigner satisfies signature.Signer.
var _ signature.Signer = (*KMSSigner)(nil)

// KMSSigner adapts a RemoteSigner to the signature.Signer interface.
// The remote KMS signs a 32-byte digest, not a message — pre-hashing
// is the adapter's responsibility, performed in Sign according to the
// configured SignPath:
//
//   - SignPathJOSE: SHA-256 pre-hash.
//   - SignPathEVM:  Keccak-256 pre-hash.
//
// KMSSigner is immutable after construction and safe for concurrent use.
type KMSSigner struct {
	remote RemoteSigner
	path   SignPath
}

// NewKMSSigner constructs a KMSSigner wrapping remote. The path selects
// the pre-hash function and wire format (SignPathJOSE → SHA-256, 64-byte
// r||s; SignPathEVM → Keccak-256, 65-byte r||s||v). remote must be
// non-nil — a nil remote surfaces as a nil-pointer panic on first use.
func NewKMSSigner(remote RemoteSigner, path SignPath) *KMSSigner {
	return &KMSSigner{remote: remote, path: path}
}

// PublicKey returns the secp256k1 public key for the KMS key, delegated
// to the wrapped RemoteSigner.
func (s *KMSSigner) PublicKey(ctx context.Context) (crypto.PublicKey, error) {
	return s.remote.PublicKey(ctx)
}

// Sign produces a signature over digest by pre-hashing it, then
// delegating to the wrapped RemoteSigner. Pre-hashing happens here so
// callers can pass the plain message, matching signature.Signer
// semantics:
//
//   - SignPathJOSE: SHA-256 pre-hash.
//   - SignPathEVM:  Keccak-256 pre-hash.
//
// Returns ctx.Err() if the context is canceled before the remote call.
// Returns an error for an unrecognized SignPath.
func (s *KMSSigner) Sign(ctx context.Context, digest []byte) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	var preHash [32]byte
	switch s.path {
	case SignPathJOSE:
		preHash = sha256.Sum256(digest)
	case SignPathEVM:
		preHash = hash.NewKeccak256().Sum(digest)
	default:
		return nil, fmt.Errorf("kms: KMSSigner.Sign: unknown sign path %d", s.path)
	}
	return s.remote.Sign(ctx, preHash[:], SignOptions{Path: s.path})
}
