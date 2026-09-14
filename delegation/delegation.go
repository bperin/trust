package delegation

import (
	"encoding/hex"
	"fmt"
	"slices"

	"github.com/bperin/trust/authority"
)

// DelegationSpec describes the child authority to derive from a
// parent. Every field must be a strict subset of the parent's
// corresponding dimension: Derive rejects any escalation rather than
// silently narrowing the request.
type DelegationSpec struct {
	// Subject identifies the entity the child authority is granted
	// to — a DID.
	Subject string

	// Capabilities is the set of capabilities the child claims. Every
	// element must be present in the parent's Capabilities.
	Capabilities []authority.Capability

	// Scope narrows where the child's capabilities may be exercised.
	// Each dimension must be a subset of the parent's.
	Scope authority.Scope

	// Validity bounds the child in time. The window must sit inside
	// the parent's Validity.
	Validity authority.Validity

	// DelegationConstraints bound further delegation of the child.
	// Under a non-nil parent MaxDepth N the child must declare a
	// MaxDepth strictly less than N.
	DelegationConstraints authority.DelegationConstraints
}

// Derive builds an unsigned child authority from parent per spec. The
// spec must be a strict subset of the parent: capabilities present in
// the parent, every scope dimension narrowed, validity inside the
// parent's window, and delegation depth strictly below the parent's
// MaxDepth. Any escalation returns the matching sentinel error —
// ErrCapabilityEscalation, ErrScopeEscalation, ErrValidityEscalation,
// or ErrDepthEscalation — and nothing is clamped.
//
// On success the returned child's Parent is the hex encoding of the
// parent's canonical hash (authority.CanonicalHash), so the child is
// content-addressed to its parent. Status is authority.StatusActive
// and Proof is zeroed — the child is unsigned; signing is the
// caller's responsibility. The parent is not mutated.
func Derive(parent *authority.Authority, spec DelegationSpec) (*authority.Authority, error) {
	if parent == nil {
		return nil, fmt.Errorf("delegation: derive: %w", authority.ErrNilAuthority)
	}

	child := &authority.Authority{
		Subject:               spec.Subject,
		Capabilities:          spec.Capabilities,
		Scope:                 spec.Scope,
		Validity:              spec.Validity,
		DelegationConstraints: spec.DelegationConstraints,
		Status:                authority.StatusActive,
	}
	if err := VerifySubset(child, parent); err != nil {
		return nil, err
	}

	ph, err := authority.CanonicalHash(parent)
	if err != nil {
		return nil, fmt.Errorf("delegation: canonical hash of parent: %w", err)
	}
	parentRef := hex.EncodeToString(ph[:])
	child.Parent = &parentRef

	return child, nil
}

// VerifySubset checks that child is a strict subset of parent across
// capabilities, scope, validity, and delegation depth. It returns nil
// when every check passes and the first detected violation as a typed
// sentinel — ErrCapabilityEscalation, ErrScopeEscalation,
// ErrValidityEscalation, or ErrDepthEscalation — matched with
// errors.Is. A nil child or parent returns an error.
//
// VerifySubset is pure: no I/O, no global state, no re-derivation. It
// checks the pair as presented; it does not verify the child's Parent
// reference or proof.
func VerifySubset(child, parent *authority.Authority) error {
	if child == nil || parent == nil {
		return fmt.Errorf("delegation: verify subset: %w", authority.ErrNilAuthority)
	}
	if !capabilitySubset(parent.Capabilities, child.Capabilities) {
		return ErrCapabilityEscalation
	}
	if !scopeSubset(parent.Scope, child.Scope) {
		return ErrScopeEscalation
	}
	if !validitySubset(parent.Validity, child.Validity) {
		return ErrValidityEscalation
	}
	if !delegationDepthOK(parent.DelegationConstraints, child.DelegationConstraints) {
		return ErrDepthEscalation
	}
	return nil
}

// capabilitySubset reports whether every capability in child is
// present in parent. An empty child claims nothing and is a subset of
// any parent.
func capabilitySubset(parent, child []authority.Capability) bool {
	for _, c := range child {
		if !slices.Contains(parent, c) {
			return false
		}
	}
	return true
}

// scopeSubset reports whether every dimension of child is a subset of
// the matching dimension of parent.
func scopeSubset(parent, child authority.Scope) bool {
	return stringSliceSubset(parent.Resources, child.Resources) &&
		stringSliceSubset(parent.Subjects, child.Subjects) &&
		stringSliceSubset(parent.Actions, child.Actions) &&
		stringSliceSubset(parent.Organizations, child.Organizations) &&
		stringSliceSubset(parent.Geography, child.Geography) &&
		stringSliceSubset(parent.Channels, child.Channels) &&
		timeWindowSubset(parent.TimeWindow, child.TimeWindow) &&
		quantitySubset(parent.Quantity, child.Quantity) &&
		monetarySubset(parent.Monetary, child.Monetary)
}

// stringSliceSubset reports whether child stays within the bounds
// parent sets for the dimension. An empty parent is unconstrained and
// admits any child. A non-empty parent constrains the dimension, so an
// empty child — which drops the constraint — is a widening and is
// rejected; otherwise every child element must appear in the parent.
func stringSliceSubset(parent, child []string) bool {
	if len(parent) == 0 {
		return true
	}
	if len(child) == 0 {
		return false
	}
	parentSet := make(map[string]struct{}, len(parent))
	for _, s := range parent {
		parentSet[s] = struct{}{}
	}
	for _, s := range child {
		if _, ok := parentSet[s]; !ok {
			return false
		}
	}
	return true
}

// timeWindowSubset reports whether child's window sits inside parent's.
// A nil child claims an unconstrained window and is allowed only when
// parent is also nil; a non-nil child under a nil parent is a subset
// (the child narrows an unconstrained parent).
func timeWindowSubset(parent, child *authority.TimeWindow) bool {
	if child == nil {
		return parent == nil
	}
	if parent == nil {
		return true
	}
	return !child.Start.Before(parent.Start) && !child.End.After(parent.End)
}

// quantitySubset reports whether child's quantity bound sits inside
// parent's. A nil child claims an unconstrained quantity and is
// allowed only when parent is also nil; a non-nil child under a nil
// parent narrows an unconstrained parent. Both non-nil requires a
// matching unit and a child limit at or below the parent's.
func quantitySubset(parent, child *authority.Quantity) bool {
	if child == nil {
		return parent == nil
	}
	if parent == nil {
		return true
	}
	return child.Unit == parent.Unit && child.Limit <= parent.Limit
}

// monetarySubset reports whether child's monetary bound sits inside
// parent's. A nil child claims an unconstrained amount and is allowed
// only when parent is also nil; a non-nil child under a nil parent
// narrows an unconstrained parent. Both non-nil requires a matching
// ISO 4217 currency and a child limit at or below the parent's.
func monetarySubset(parent, child *authority.Monetary) bool {
	if child == nil {
		return parent == nil
	}
	if parent == nil {
		return true
	}
	return child.Currency == parent.Currency && child.Limit <= parent.Limit
}

// validitySubset reports whether child's validity window sits inside
// parent's: child.NotBefore no earlier than parent's and
// child.NotAfter no later than parent's.
func validitySubset(parent, child authority.Validity) bool {
	return !child.NotBefore.Before(parent.NotBefore) &&
		!child.NotAfter.After(parent.NotAfter)
}

// delegationDepthOK reports whether the child's delegation depth bound
// fits under the parent's. A nil parent MaxDepth is unbounded and
// allows any child — bounded or not. A non-nil parent MaxDepth N means
// the parent may delegate with depth at most N-1, so the child must
// declare a non-nil MaxDepth strictly less than N; a nil child
// MaxDepth under a bounded parent claims unbounded depth and is an
// escalation.
func delegationDepthOK(parentConstraints, childConstraints authority.DelegationConstraints) bool {
	if parentConstraints.MaxDepth == nil {
		return true
	}
	return childConstraints.MaxDepth != nil &&
		*childConstraints.MaxDepth < *parentConstraints.MaxDepth
}
