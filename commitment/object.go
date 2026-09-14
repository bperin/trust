package commitment

import (
	"github.com/bperin/trust/attestation"
	"github.com/bperin/trust/authority"
	"github.com/bperin/trust/claim"
	"github.com/bperin/trust/evidence"
)

// TrustObject is a trust object that contributes a leaf to a commitment; its sole method returns the object's canonical hash.
type TrustObject interface {
	LeafHash() ([32]byte, error)
}

// LeafHash returns the canonical hash of obj, rejecting a nil interface with ErrNilObject and otherwise delegating to obj.LeafHash so a typed-nil adapter surfaces the underlying package's nil sentinel.
func LeafHash(obj TrustObject) ([32]byte, error) {
	if obj == nil {
		return [32]byte{}, ErrNilObject
	}
	return obj.LeafHash()
}

// AuthorityObject adapts an authority.Authority to TrustObject.
type AuthorityObject struct {
	*authority.Authority
}

// NewAuthorityObject returns an AuthorityObject wrapping a.
func NewAuthorityObject(a *authority.Authority) AuthorityObject {
	return AuthorityObject{Authority: a}
}

// LeafHash returns authority.CanonicalHash(o.Authority).
func (o AuthorityObject) LeafHash() ([32]byte, error) {
	return authority.CanonicalHash(o.Authority)
}

// ClaimObject adapts a claim.Claim to TrustObject.
type ClaimObject struct {
	*claim.Claim
}

// NewClaimObject returns a ClaimObject wrapping c.
func NewClaimObject(c *claim.Claim) ClaimObject {
	return ClaimObject{Claim: c}
}

// LeafHash returns claim.CanonicalHash(o.Claim).
func (o ClaimObject) LeafHash() ([32]byte, error) {
	return claim.CanonicalHash(o.Claim)
}

// AttestationObject adapts an attestation.Attestation to TrustObject.
type AttestationObject struct {
	*attestation.Attestation
}

// NewAttestationObject returns an AttestationObject wrapping a.
func NewAttestationObject(a *attestation.Attestation) AttestationObject {
	return AttestationObject{Attestation: a}
}

// LeafHash returns attestation.CanonicalHash(o.Attestation).
func (o AttestationObject) LeafHash() ([32]byte, error) {
	return attestation.CanonicalHash(o.Attestation)
}

// EvidenceObject adapts an evidence.Evidence to TrustObject.
type EvidenceObject struct {
	*evidence.Evidence
}

// NewEvidenceObject returns an EvidenceObject wrapping e.
func NewEvidenceObject(e *evidence.Evidence) EvidenceObject {
	return EvidenceObject{Evidence: e}
}

// LeafHash returns evidence.CanonicalHash(o.Evidence).
func (o EvidenceObject) LeafHash() ([32]byte, error) {
	return evidence.CanonicalHash(o.Evidence)
}
