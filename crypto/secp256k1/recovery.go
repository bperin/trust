package secp256k1

import (
	"errors"
	"fmt"

	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
)

// ErrInvalidRecoveryID is returned by RecoverPubKey when the recovery
// ID is not in the range [0, 3] per [SEC 1 v2] §4.3.3.
var ErrInvalidRecoveryID = errors.New("secp256k1: invalid recovery ID (want 0-3)")

// RecoverPubKey recovers the public key from a 64-byte [SEC 1 v2]
// §4.3.3 signature (r || s), a 32-byte digest, and a recovery ID in
// the range [0, 3]. The recovery ID encodes which of the four
// candidate public keys is correct — it is the value produced by the
// signer alongside the signature.
//
// Returns the recovered public key, or an error if the inputs are
// malformed or recovery fails (e.g. the signature does not match any
// valid public key for the given digest).
func RecoverPubKey(signature, digest []byte, recID byte) (*PublicKey, error) {
	if len(signature) != 64 {
		return nil, fmt.Errorf("%w: signature must be 64 bytes, got %d", ErrInvalidSignature, len(signature))
	}
	if len(digest) != 32 {
		return nil, fmt.Errorf("%w: digest must be 32 bytes, got %d", ErrInvalidSignature, len(digest))
	}
	if recID > 3 {
		return nil, fmt.Errorf("%w: got %d", ErrInvalidRecoveryID, recID)
	}

	// Construct compact signature: recovery byte || r(32) || s(32).
	// The recovery byte is 27 + recID + compressed flag (4).
	// We use compressed keys (flag = 4) to match our PublicKey.Bytes()
	// which returns 33-byte compressed form.
	compact := make([]byte, 65)
	compact[0] = 27 + recID + 4
	copy(compact[1:33], signature[:32])
	copy(compact[33:65], signature[32:])

	pub, wasCompressed, err := ecdsa.RecoverCompact(compact, digest)
	if err != nil {
		return nil, fmt.Errorf("secp256k1: recovery failed: %w", err)
	}
	if !wasCompressed {
		// RecoverCompact with the compressed flag should return
		// compressed=true. If not, something is wrong.
		return nil, fmt.Errorf("secp256k1: recovery returned uncompressed key unexpectedly")
	}

	return &PublicKey{key: pub}, nil
}

// SignRecoverable produces a [SEC 1 v2] §4.3.3 signature and recovery
// ID over a 32-byte pre-computed hash. The signature is 64 bytes
// (r || s) and the recovery ID is in [0, 3]. Use RecoverPubKey with
// the returned signature, digest, and recovery ID to recover the
// public key.
//
// This uses the dcrd SignCompact API internally, which produces RFC
// 6979 deterministic signatures with low-s canonicalization per
// [EIP-2].
func (priv *PrivateKey) SignRecoverable(hash []byte) (signature []byte, recID byte, err error) {
	if len(hash) != 32 {
		return nil, 0, fmt.Errorf("%w: hash must be 32 bytes, got %d", ErrInvalidSignature, len(hash))
	}

	compact := ecdsa.SignCompact(priv.key, hash, true)
	if len(compact) != 65 {
		return nil, 0, fmt.Errorf("secp256k1: unexpected compact signature length %d", len(compact))
	}

	// Extract recovery ID: compact[0] = 27 + recID + 4 (compressed).
	// Strip the magic offset (27) and compressed flag (4).
	recID = compact[0] - 27 - 4
	if recID > 3 {
		return nil, 0, fmt.Errorf("secp256k1: invalid recovery ID %d in compact signature", recID)
	}

	// Return r || s (64 bytes).
	sig := make([]byte, 64)
	copy(sig[:32], compact[1:33])
	copy(sig[32:], compact[33:65])

	return sig, recID, nil
}
