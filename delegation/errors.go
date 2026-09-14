package delegation

import "errors"

// Sentinel errors for subset violations detected by Derive and
// VerifySubset. Each violation returns exactly one sentinel — the
// first detected — matched with errors.Is.
var (
	// ErrCapabilityEscalation is returned when the child claims a
	// capability the parent does not hold.
	ErrCapabilityEscalation = errors.New("delegation: capability escalation")

	// ErrScopeEscalation is returned when a child scope dimension
	// exceeds the parent's bound: a resource, subject, action,
	// organization, geography, or channel not in the parent's list;
	// a time window outside the parent's; a quantity limit above the
	// parent's or with a different unit; a monetary limit above the
	// parent's or with a different currency; or a nil child bound
	// (unconstrained) under a non-nil parent bound.
	ErrScopeEscalation = errors.New("delegation: scope escalation")

	// ErrValidityEscalation is returned when the child's validity
	// window reaches before the parent's NotBefore or past the
	// parent's NotAfter.
	ErrValidityEscalation = errors.New("delegation: validity escalation")

	// ErrDepthEscalation is returned when the child claims more
	// delegation depth than the parent allows: a non-nil parent
	// MaxDepth N requires a non-nil child MaxDepth strictly less
	// than N.
	ErrDepthEscalation = errors.New("delegation: depth escalation")
)
