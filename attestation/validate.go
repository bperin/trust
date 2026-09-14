package attestation

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/bperin/trust/authority"
	"github.com/bperin/trust/claim"
	"github.com/bperin/trust/evidence"
)

// Sentinel errors returned by Validate. Check them with errors.Is.
var (
	// ErrEmptyIssuer is returned by Validate when Attestation.Issuer
	// is empty — an attestation must name its issuer.
	ErrEmptyIssuer = errors.New("attestation: empty issuer")

	// ErrEmptySigningKeyID is returned by Validate when
	// Attestation.SigningKeyID is empty — an attestation must name
	// the leaf key that signed it.
	ErrEmptySigningKeyID = errors.New("attestation: empty signing key id")

	// ErrEmptyAuthorityRef is returned by Validate when
	// Attestation.AuthorityRef is empty — an attestation must name
	// the authority that authorizes it.
	ErrEmptyAuthorityRef = errors.New("attestation: empty authority reference")

	// ErrEmptyCapabilityNamespace is returned by Validate when
	// Attestation.Capability.Namespace is empty.
	ErrEmptyCapabilityNamespace = errors.New("attestation: empty capability namespace")

	// ErrEmptyCapabilityName is returned by Validate when
	// Attestation.Capability.Name is empty.
	ErrEmptyCapabilityName = errors.New("attestation: empty capability name")

	// ErrInvalidClaim is returned by Validate when the embedded
	// claim.Claim fails claim.Validate. The claim's own error is
	// wrapped inside it.
	ErrInvalidClaim = errors.New("attestation: invalid claim")

	// ErrInvalidEvidence is returned by Validate when an
	// evidence.Evidence entry fails evidence.ValidateEvidence or
	// cannot be canonically hashed. The evidence's own error is
	// wrapped inside it.
	ErrInvalidEvidence = errors.New("attestation: invalid evidence")

	// ErrUnknownStatus is returned by Validate when
	// Attestation.Status is not one of the defined authority.Status
	// constants.
	ErrUnknownStatus = errors.New("attestation: unknown status")

	// ErrZeroIssuedAt is returned by Validate when
	// Attestation.IssuedAt is the zero time — an attestation must
	// record when it was produced.
	ErrZeroIssuedAt = errors.New("attestation: zero issued-at time")

	// ErrEmptyValidity is returned by Validate when both bounds of
	// Attestation.Validity are the zero time — an attestation must
	// carry a bounded validity window.
	ErrEmptyValidity = errors.New("attestation: empty validity window")

	// ErrUnsortedEvidence is returned by Validate when the Evidence
	// slice is not sorted strictly ascending by
	// evidence.CanonicalHash — unsorted or containing duplicates.
	// Sorted, dedup-free order is the canonical form; an unsorted
	// input is a construction error, not normalized.
	ErrUnsortedEvidence = errors.New("attestation: evidence not sorted ascending by canonical hash")
)

// Validate checks an attestation for structural validity: a non-nil
// attestation with a non-empty Issuer, SigningKeyID, AuthorityRef, and
// Capability; a structurally valid embedded claim; structurally valid
// evidence references sorted strictly ascending by
// evidence.CanonicalHash; a known Status; a non-zero IssuedAt; and a
// non-empty Validity window.
//
// Validation is structural only: it performs no signature verification,
// no authorization check, no temporal checks against Validity, and no
// hash recomputation against AuthorityRef — those are the concerns of
// signature and authorization verification, not of Validate.
func Validate(att *Attestation) error {
	if att == nil {
		return ErrNilAttestation
	}
	if att.Issuer == "" {
		return ErrEmptyIssuer
	}
	if att.SigningKeyID == "" {
		return ErrEmptySigningKeyID
	}
	if att.AuthorityRef == "" {
		return ErrEmptyAuthorityRef
	}
	if att.Capability.Namespace == "" {
		return ErrEmptyCapabilityNamespace
	}
	if att.Capability.Name == "" {
		return ErrEmptyCapabilityName
	}
	if err := claim.Validate(&att.Claim); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidClaim, err)
	}
	hashes := make([][32]byte, len(att.Evidence))
	for i := range att.Evidence {
		if err := evidence.ValidateEvidence(&att.Evidence[i]); err != nil {
			return fmt.Errorf("%w at index %d: %w", ErrInvalidEvidence, i, err)
		}
		h, err := evidence.CanonicalHash(&att.Evidence[i])
		if err != nil {
			return fmt.Errorf("%w at index %d: %w", ErrInvalidEvidence, i, err)
		}
		hashes[i] = h
	}
	switch att.Status {
	case authority.StatusActive, authority.StatusRevoked,
		authority.StatusSuperseded, authority.StatusExpired:
	default:
		return fmt.Errorf("%w: %d", ErrUnknownStatus, att.Status)
	}
	if att.IssuedAt.IsZero() {
		return ErrZeroIssuedAt
	}
	if att.Validity.NotBefore.IsZero() && att.Validity.NotAfter.IsZero() {
		return ErrEmptyValidity
	}
	for i := 1; i < len(hashes); i++ {
		if bytes.Compare(hashes[i-1][:], hashes[i][:]) >= 0 {
			return fmt.Errorf("%w at index %d", ErrUnsortedEvidence, i)
		}
	}
	return nil
}
