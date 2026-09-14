package attestation

import (
	"context"
	"crypto"
	"errors"
	"fmt"

	"github.com/bperin/trust/signature"
)

// Sentinel errors returned by SignAttestation and VerifySignature.
// Check them with errors.Is.
var (
	// ErrTamperedAttestation is returned by VerifySignature when the
	// stored Signature does not verify against the recomputed
	// canonical hash under the supplied leaf public key.
	ErrTamperedAttestation = errors.New("attestation: tampered or signature mismatch")

	// ErrWrongKey is returned by VerifySignature when the supplied
	// public key's algorithm does not match Attestation.Algorithm.
	ErrWrongKey = errors.New("attestation: key does not match attestation algorithm")
)

// SignAttestation signs att with signer and stores the result in
// att.Signature: it derives att.Algorithm from the signer's public
// key — never from att.Algorithm, which is untrusted input — sets
// att.SigningKeyID to keyID when keyID is non-empty, clears any stale
// signature, then signs the canonical hash of the unsigned
// attestation.
//
// att.Algorithm and att.SigningKeyID are set before hashing so the
// signature commits to the signing key identity. Any
// signature.Signer implementation (in-process key, KMS-backed key)
// works; this package holds no key custody and never imports kms/.
//
// SignAttestation returns ErrNilAttestation if att is nil, an error
// if signer is nil, and an error if key resolution or signing fails.
func SignAttestation(ctx context.Context, att *Attestation, signer signature.Signer, keyID string) error {
	if att == nil {
		return ErrNilAttestation
	}
	if signer == nil {
		return fmt.Errorf("attestation sign: nil signer")
	}
	pub, err := signer.PublicKey(ctx)
	if err != nil {
		return fmt.Errorf("attestation sign: public key: %w", err)
	}
	// Algorithm-confusion defense: resolve the algorithm from the
	// signing key, not from att.Algorithm.
	alg, err := signature.AlgorithmForPublicKey(pub)
	if err != nil {
		return fmt.Errorf("attestation sign: %w", err)
	}
	if keyID != "" {
		att.SigningKeyID = keyID
	}
	att.Algorithm = alg
	// Clear any stale signature so re-signing is deterministic in
	// content and a failed Sign cannot leave an inconsistent
	// attestation behind. Signature is excluded from the hash, but
	// clearing it first keeps re-signing idempotent.
	att.Signature = nil
	h, err := CanonicalHash(att)
	if err != nil {
		return fmt.Errorf("attestation sign: %w", err)
	}
	sig, err := signer.Sign(ctx, h[:])
	if err != nil {
		return fmt.Errorf("attestation sign: %w", err)
	}
	att.Signature = sig
	return nil
}

// VerifySignature verifies att's signature against leafPub, the
// public counterpart of the leaf key referenced by
// att.SigningKeyID. It is pure: no I/O, no clock, no globals.
//
// The key's algorithm must match att.Algorithm — a mismatch or an
// unresolvable key type returns ErrWrongKey. On a match,
// att.Signature is verified against the recomputed canonical hash; a
// failure returns ErrTamperedAttestation.
func VerifySignature(att *Attestation, leafPub crypto.PublicKey) error {
	if att == nil {
		return ErrNilAttestation
	}
	// Algorithm-confusion defense: the verifier's key type must match
	// the attestation's declared algorithm. Never trust
	// att.Algorithm alone — resolve the algorithm from the supplied
	// key.
	alg, err := signature.AlgorithmForPublicKey(leafPub)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrWrongKey, err)
	}
	if alg != att.Algorithm {
		return ErrWrongKey
	}
	h, err := CanonicalHash(att)
	if err != nil {
		return fmt.Errorf("attestation verify: %w", err)
	}
	ok, err := signature.Verify(att.Algorithm, leafPub, att.Signature, h[:])
	if err != nil || !ok {
		return ErrTamperedAttestation
	}
	return nil
}
