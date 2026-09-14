package attestation

import (
	"crypto"
	"encoding/hex"
	"errors"
	"time"

	"github.com/bperin/trust/authority"
)

// Sentinel errors returned by VerifyAuthorization and VerifyAttestation.
// Check them with errors.Is.
var (
	ErrMissingAuthorityRef   = errors.New("attestation: missing authority reference")
	ErrAuthorityMismatch     = errors.New("attestation: authority does not match reference")
	ErrSubjectMismatch       = errors.New("attestation: issuer is not the authority subject")
	ErrCapabilityNotGranted  = errors.New("attestation: capability not granted by authority")
	ErrAuthorityNotActive    = errors.New("attestation: authority is not active")
	ErrAttestationNotActive  = errors.New("attestation: attestation is not active")
	ErrAttestationNotCurrent = errors.New("attestation: attestation is not current")
	ErrAuthorizationScope    = errors.New("attestation: claim scope exceeds authority scope")
	ErrAuthorizationValidity = errors.New("attestation: validity not within authority validity")
)

// VerifyAuthorization checks that the referenced authority grants the
// attestation's issuer the exercised capability, with scope and validity
// contained in the authority's. Single-hop: the authority's own proof
// and any delegation chain are the caller's concern.
func VerifyAuthorization(att *Attestation, auth *authority.Authority) error {
	if att == nil {
		return ErrNilAttestation
	}
	if auth == nil {
		return authority.ErrNilAuthority
	}
	if att.AuthorityRef == "" {
		return ErrMissingAuthorityRef
	}
	h, err := authority.CanonicalHash(auth)
	if err != nil {
		return err
	}
	if hex.EncodeToString(h[:]) != att.AuthorityRef {
		return ErrAuthorityMismatch
	}
	if att.Issuer != auth.Subject {
		return ErrSubjectMismatch
	}
	if !capabilityGranted(auth.Capabilities, att.Capability) {
		return ErrCapabilityNotGranted
	}
	if auth.Status != authority.StatusActive {
		return ErrAuthorityNotActive
	}
	if att.Status != authority.StatusActive {
		return ErrAttestationNotActive
	}
	if !validityContains(att.Validity, time.Now()) {
		return ErrAttestationNotCurrent
	}
	if !scopeSubset(att.Claim.Scope, auth.Scope) {
		return ErrAuthorizationScope
	}
	if !validitySubset(att.Claim.Validity, auth.Validity) || !validitySubset(att.Validity, auth.Validity) {
		return ErrAuthorizationValidity
	}
	return nil
}

// VerifyAttestation returns nil only when both the signature and
// authorization halves pass; the signature check runs first.
func VerifyAttestation(att *Attestation, leafPub crypto.PublicKey, auth *authority.Authority) error {
	if err := VerifySignature(att, leafPub); err != nil {
		return err
	}
	return VerifyAuthorization(att, auth)
}

func capabilityGranted(caps []authority.Capability, c authority.Capability) bool {
	for _, granted := range caps {
		if granted == c {
			return true
		}
	}
	return false
}

func stringSliceSubset(sub, super []string) bool {
	if len(sub) > len(super) {
		return false
	}
	for _, s := range sub {
		found := false
		for _, v := range super {
			if v == s {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

// scopeSubset mirrors authority.ValidateScope: an empty authority
// dimension is unconstrained; a non-empty authority dimension with an
// empty claim dimension is not a subset.
func scopeSubset(sub, super authority.Scope) bool {
	if !stringSliceSubset(sub.Resources, super.Resources) ||
		!stringSliceSubset(sub.Subjects, super.Subjects) ||
		!stringSliceSubset(sub.Actions, super.Actions) ||
		!stringSliceSubset(sub.Organizations, super.Organizations) ||
		!stringSliceSubset(sub.Geography, super.Geography) ||
		!stringSliceSubset(sub.Channels, super.Channels) {
		return false
	}
	if super.TimeWindow != nil {
		if sub.TimeWindow == nil ||
			sub.TimeWindow.Start.Before(super.TimeWindow.Start) ||
			sub.TimeWindow.End.After(super.TimeWindow.End) {
			return false
		}
	}
	if super.Quantity != nil {
		if sub.Quantity == nil || sub.Quantity.Unit != super.Quantity.Unit || sub.Quantity.Limit > super.Quantity.Limit {
			return false
		}
	}
	if super.Monetary != nil {
		if sub.Monetary == nil || sub.Monetary.Currency != super.Monetary.Currency || sub.Monetary.Limit > super.Monetary.Limit {
			return false
		}
	}
	return true
}

func validitySubset(sub, super authority.Validity) bool {
	return !sub.NotBefore.Before(super.NotBefore) && !sub.NotAfter.After(super.NotAfter)
}

func validityContains(v authority.Validity, now time.Time) bool {
	return !now.Before(v.NotBefore) && !now.After(v.NotAfter)
}
