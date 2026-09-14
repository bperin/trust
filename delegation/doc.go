// Package delegation derives strictly-narrower child authorities from a
// parent authority and verifies the subset relationship between an
// existing child/parent pair.
//
// Derive validates a DelegationSpec against a parent Authority: every
// claimed capability must be present in the parent, every scope
// dimension must narrow — never widen — the parent's, the validity
// window must sit inside the parent's, and the delegation depth must
// fit under the parent's DelegationConstraints. On success Derive
// returns an unsigned child Authority whose Parent is the hex encoding
// of the parent's canonical hash — the child is content-addressed to
// its parent — with Status == authority.StatusActive and a zero Proof.
// Signing is the caller's responsibility.
//
// VerifySubset runs the same checks against an existing child/parent
// pair. It is pure: no I/O, no global state, no re-derivation.
//
// # Subset semantics
//
// A nil/empty dimension on the parent is unconstrained for that
// dimension. A child string-slice dimension under an unconstrained
// (empty) parent is always a subset; under a non-empty parent slice
// the child must be non-empty and every element must appear in the
// parent's slice — an empty child slice under a constrained parent
// drops the constraint and is a widening, not a subset. A nil child
// pointer dimension (TimeWindow,
// Quantity, Monetary) claims the parent's full range and is allowed
// only when the parent is also unconstrained there; a non-nil child
// dimension must sit strictly inside the parent's bound. Delegation
// depth: a nil parent MaxDepth is unbounded and allows any child; a
// non-nil parent MaxDepth N requires a non-nil child MaxDepth strictly
// less than N.
//
// Violations are never silently narrowed: the first detected
// escalation returns a typed sentinel — ErrCapabilityEscalation,
// ErrScopeEscalation, ErrValidityEscalation, or ErrDepthEscalation —
// matched with errors.Is.
//
// # Dependency rule
//
// This package imports authority only — for the data model and
// CanonicalHash. It never imports kms, auth, chain, or signature:
// delegation is pure subset logic and does not sign or verify. The
// isolation test in this package enforces that rule.
package delegation
