// Package kms defines the RemoteSigner interface and supporting types
// for signing digests with a secp256k1 key held in a remote KMS (AWS
// KMS, GCP KMS). The signer receives a 32-byte pre-computed digest and
// returns either a 64-byte r||s signature (JOSE/COSE ES256K path,
// [RFC 8812] §3.1) or a 65-byte r||s||v signature (EVM path, [EIP-2]).
//
// No private key material ever enters the process — the signer struct
// holds only a key reference (key ID string). The public key is
// fetched and cached before signing so the recovery id can be computed
// by trying recID 0–3 per [SEC 1 v2] §4.3.3.
package kms

import (
	"context"

	"github.com/bperin/trust/trust/crypto/secp256k1"
)

// SignPath selects the wire format the signer produces.
//
//   - SignPathJOSE produces a 64-byte r||s signature for JOSE/COSE
//     ES256K ([RFC 8812] §3.1). The caller pre-hashes the message with
//     SHA-256 before calling Sign.
//   - SignPathEVM produces a 65-byte r||s||v signature for the EVM,
//     where v is the [SEC 1 v2] §4.3.3 recovery id. The caller pre-hashes
//     the message with Keccak-256 before calling Sign.
type SignPath int

const (
	// SignPathJOSE is the JOSE/COSE ES256K signing path. The signer
	// returns a 64-byte r||s signature. Pair with SHA-256 pre-hashing
	// and signature.Verify(AlgorithmES256K, ...) on the verifier side.
	SignPathJOSE SignPath = 0

	// SignPathEVM is the Ethereum signing path. The signer returns a
	// 65-byte r||s||v signature where v is the recovery id. Pair with
	// Keccak-256 pre-hashing and secp256k1.RecoverPubKey on the
	// verifier side.
	SignPathEVM SignPath = 1
)

// SignOptions configures a Sign call. The Path field selects the wire
// format the signer produces.
type SignOptions struct {
	// Path is the signing path (SignPathJOSE or SignPathEVM).
	Path SignPath
}

// RemoteSigner signs a 32-byte pre-computed digest with a secp256k1
// key held in a remote KMS. No private key material is present in any
// implementation — only a key reference (key ID string).
//
// Sign receives a 32-byte digest (the caller pre-hashes: SHA-256 for
// JOSE, Keccak-256 for EVM) and returns:
//
//   - JOSE path: 64-byte r||s.
//   - EVM path:  65-byte r||s||v, where v is the [SEC 1 v2] §4.3.3
//     recovery id. The recovery id is computed by trying recID 0–3 and
//     comparing the recovered public key to PublicKey().
//
// PublicKey returns the secp256k1 public key for the KMS key. It is
// fetched and cached before signing so the recovery id can be
// computed.
type RemoteSigner interface {
	// Sign signs a 32-byte pre-computed digest. The SignOptions.Path
	// field selects the output wire format (JOSE 64-byte r||s or EVM
	// 65-byte r||s||v).
	Sign(ctx context.Context, digest []byte, opts SignOptions) ([]byte, error)

	// PublicKey returns the secp256k1 public key for the KMS key. The
	// returned key is in 33-byte compressed form.
	PublicKey(ctx context.Context) (*secp256k1.PublicKey, error)
}
