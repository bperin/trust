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
	ErrEmptyIssuer              = errors.New("attestation: empty issuer")
	ErrEmptySigningKeyID        = errors.New("attestation: empty signing key id")
	ErrEmptyAuthorityRef        = errors.New("attestation: empty authority reference")
	ErrEmptyCapabilityNamespace = errors.New("attestation: empty capability namespace")
	ErrEmptyCapabilityName      = errors.New("attestation: empty capability name")
	ErrInvalidClaim             = errors.New("attestation: invalid claim")
	ErrInvalidEvidence          = errors.New("attestation: invalid evidence")
	ErrUnknownStatus            = errors.New("attestation: unknown status")
	ErrZeroIssuedAt             = errors.New("attestation: zero issued-at time")
	ErrEmptyValidity            = errors.New("attestation: empty validity window")
	ErrUnsortedEvidence         = errors.New("attestation: evidence not sorted ascending by canonical hash")
)

// Validate checks structural validity only: no signature, authorization,
// temporal, or hash-recomputation checks.
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
