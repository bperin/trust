package authority

import (
	"context"
	"crypto"
	"errors"
	"fmt"

	"github.com/bperin/trust/signature"
)

// Sentinel errors returned by SignAuthority and VerifyAuthorityProof.
// Check them with errors.Is.
var (
	// ErrTamperedAuthority is returned by VerifyAuthorityProof when
	// the stored Proof.Signature does not verify against the
	// recomputed canonical hash under the supplied key.
	ErrTamperedAuthority = errors.New("authority: tampered or signature mismatch")

	// ErrWrongKey is returned by VerifyAuthorityProof when the
	// supplied public key's algorithm does not match Proof.Algorithm.
	ErrWrongKey = errors.New("authority: key does not match proof algorithm")
)

// SignAuthority signs auth with signer and stores the result in
// auth.Proof: it sets Proof.Algorithm from the signer's public key and
// Proof.KeyID from keyID, then signs the canonical hash of the
// unsigned authority.
//
// Proof.Algorithm and Proof.KeyID are set before hashing so the
// signature commits to the signing key identity. Any signature.Signer
// implementation (in-process key, KMS-backed key) works.
//
// SignAuthority returns an error if auth or signer is nil, or if
// signing fails.
func SignAuthority(ctx context.Context, auth *Authority, signer signature.Signer, keyID string) error {
	if auth == nil {
		return ErrNilAuthority
	}
	if signer == nil {
		return fmt.Errorf("authority sign: nil signer")
	}
	pub, err := signer.PublicKey(ctx)
	if err != nil {
		return fmt.Errorf("authority sign: public key: %w", err)
	}
	alg, err := signature.AlgorithmForPublicKey(pub)
	if err != nil {
		return fmt.Errorf("authority sign: %w", err)
	}
	// Commit the proof metadata before hashing so the signature binds
	// the key identity. Any stale signature is cleared so a failed
	// Sign cannot leave an inconsistent proof behind.
	auth.Proof.Algorithm = alg
	auth.Proof.KeyID = keyID
	auth.Proof.Signature = nil
	h, err := CanonicalHash(auth)
	if err != nil {
		return fmt.Errorf("authority sign: %w", err)
	}
	sig, err := signer.Sign(ctx, h[:])
	if err != nil {
		return fmt.Errorf("authority sign: %w", err)
	}
	auth.Proof.Signature = sig
	return nil
}

// VerifyAuthorityProof verifies auth's proof against pubKey, the
// public counterpart of the key referenced by auth.Proof.KeyID.
//
// The key's algorithm must match auth.Proof.Algorithm — a mismatch or
// an unresolvable key type returns ErrWrongKey. On a match,
// auth.Proof.Signature is verified against the recomputed canonical
// hash; a failure returns ErrTamperedAuthority.
func VerifyAuthorityProof(auth *Authority, pubKey crypto.PublicKey) error {
	if auth == nil {
		return ErrNilAuthority
	}
	// Algorithm-confusion defense: the verifier's key type must match
	// the proof's declared algorithm. Never trust Proof.Algorithm
	// alone — resolve the algorithm from the supplied key.
	alg, err := signature.AlgorithmForPublicKey(pubKey)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrWrongKey, err)
	}
	if alg != auth.Proof.Algorithm {
		return ErrWrongKey
	}
	h, err := CanonicalHash(auth)
	if err != nil {
		return fmt.Errorf("authority verify: %w", err)
	}
	ok, err := signature.Verify(auth.Proof.Algorithm, pubKey, auth.Proof.Signature, h[:])
	if err != nil || !ok {
		return ErrTamperedAuthority
	}
	return nil
}
