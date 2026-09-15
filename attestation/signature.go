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
	ErrTamperedAttestation = errors.New("attestation: tampered or signature mismatch")
	ErrWrongKey            = errors.New("attestation: key does not match attestation algorithm")
)

// SignAttestation signs the canonical hash of att with signer and
// stores the result in att.Signature. Works with any signature.Signer
// (in-process or KMS); this package holds no key custody.
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
	// Algorithm-confusion defense: resolve from the key, never from
	// att.Algorithm (untrusted input).
	alg, err := signature.AlgorithmForPublicKey(pub)
	if err != nil {
		return fmt.Errorf("attestation sign: %w", err)
	}
	if keyID != "" {
		att.SigningKeyID = keyID
	}
	att.Algorithm = alg
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

// VerifySignature verifies att's signature against leafPub, the public
// counterpart of the key referenced by att.SigningKeyID.
func VerifySignature(att *Attestation, leafPub crypto.PublicKey) error {
	if att == nil {
		return ErrNilAttestation
	}
	// Algorithm-confusion defense: the key type must match the
	// declared algorithm; never trust att.Algorithm alone.
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
