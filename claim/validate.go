package claim

import (
	"errors"
	"fmt"

	"github.com/bperin/trust/authority"
)

// Sentinel errors returned by Validate. Check them with errors.Is.
var (
	// ErrEmptyIssuer is returned by Validate when Claim.Issuer is
	// empty — a claim must name its issuer.
	ErrEmptyIssuer = errors.New("claim: empty issuer")

	// ErrEmptySubject is returned by Validate when Claim.Subject is
	// empty — a claim must name its subject.
	ErrEmptySubject = errors.New("claim: empty subject")

	// ErrEmptyClaimTypeNamespace is returned by Validate when
	// Claim.Type.Namespace is empty.
	ErrEmptyClaimTypeNamespace = errors.New("claim: empty claim type namespace")

	// ErrEmptyClaimTypeName is returned by Validate when
	// Claim.Type.Name is empty.
	ErrEmptyClaimTypeName = errors.New("claim: empty claim type name")

	// ErrNilValue is returned by Validate when Claim.Value is nil —
	// a claim must carry a payload.
	ErrNilValue = errors.New("claim: nil value")
)

// Validate checks a claim for structural validity: a non-nil claim
// with a non-empty Issuer, a non-empty Subject, a ClaimType with both
// fields set, a non-nil Value, and a canonically sorted Scope. Scope
// validation is delegated to authority.ValidateScope; its error is
// returned wrapped so authority.ErrUnsortedScope survives errors.Is.
//
// Validation is structural only — no temporal checks against
// Validity, no network access, no content fetch.
func Validate(c *Claim) error {
	if c == nil {
		return ErrNilClaim
	}
	if c.Issuer == "" {
		return ErrEmptyIssuer
	}
	if c.Subject == "" {
		return ErrEmptySubject
	}
	if c.Type.Namespace == "" {
		return ErrEmptyClaimTypeNamespace
	}
	if c.Type.Name == "" {
		return ErrEmptyClaimTypeName
	}
	if c.Value == nil {
		return ErrNilValue
	}
	if err := authority.ValidateScope(c.Scope); err != nil {
		return fmt.Errorf("claim: %w", err)
	}
	return nil
}
