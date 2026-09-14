package authority

import (
	"errors"
	"fmt"
)

// Sentinel errors returned by the validation functions. Check them
// with errors.Is.
var (
	// ErrEmptySubject is returned by Validate when Authority.Subject
	// is empty — an authority must name its subject.
	ErrEmptySubject = errors.New("authority: empty subject")

	// ErrEmptyCapabilityNamespace is returned by ValidateCapabilities
	// when a capability's Namespace is empty.
	ErrEmptyCapabilityNamespace = errors.New("authority: empty capability namespace")

	// ErrEmptyCapabilityName is returned by ValidateCapabilities when
	// a capability's Name is empty.
	ErrEmptyCapabilityName = errors.New("authority: empty capability name")

	// ErrUnsortedCapabilities is returned by ValidateCapabilities
	// when the slice is not sorted strictly ascending by
	// (Namespace, Name). Sorted order is the canonical form; an
	// unsorted input is a construction error, not normalized.
	ErrUnsortedCapabilities = errors.New("authority: capabilities not sorted ascending by (namespace, name)")

	// ErrUnsortedScope is returned by ValidateScope when a non-nil
	// scope dimension slice is not sorted strictly ascending —
	// unsorted or containing duplicates. Sorted, dedup-free order is
	// the canonical form; an unsorted input is a construction error,
	// not normalized.
	ErrUnsortedScope = errors.New("authority: scope dimension not sorted ascending and dedup-free")

	// ErrUnknownStatus is returned by Validate when Authority.Status
	// is not one of the defined Status constants.
	ErrUnknownStatus = errors.New("authority: unknown status")
)

// Validate checks an authority for structural validity: a non-nil
// authority with a non-empty Subject, sorted valid capabilities, a
// canonically sorted scope, and a known Status. It does not verify the
// Proof — cryptographic verification is a separate concern.
func Validate(auth *Authority) error {
	if auth == nil {
		return ErrNilAuthority
	}
	if auth.Subject == "" {
		return ErrEmptySubject
	}
	if err := ValidateCapabilities(auth.Capabilities); err != nil {
		return err
	}
	if err := ValidateScope(auth.Scope); err != nil {
		return err
	}
	switch auth.Status {
	case StatusActive, StatusRevoked, StatusSuperseded, StatusExpired:
		return nil
	default:
		return fmt.Errorf("%w: %d", ErrUnknownStatus, auth.Status)
	}
}

// ValidateCapabilities checks that caps is in canonical form: every
// capability has a non-empty Namespace and Name, and the slice is
// sorted strictly ascending by (Namespace, Name) — lexicographic,
// namespace first. Strictly ascending order implies dedup-free: a
// repeated (Namespace, Name) pair is rejected as unsorted. A nil or
// empty slice is valid.
func ValidateCapabilities(caps []Capability) error {
	for i, c := range caps {
		if c.Namespace == "" {
			return fmt.Errorf("%w at index %d", ErrEmptyCapabilityNamespace, i)
		}
		if c.Name == "" {
			return fmt.Errorf("%w at index %d", ErrEmptyCapabilityName, i)
		}
		if i > 0 {
			prev := caps[i-1]
			if prev.Namespace > c.Namespace ||
				(prev.Namespace == c.Namespace && prev.Name >= c.Name) {
				return fmt.Errorf("%w at index %d", ErrUnsortedCapabilities, i)
			}
		}
	}
	return nil
}

// ValidateScope checks that every non-nil string slice dimension of s
// is sorted strictly ascending — dedup-free. A zero-value Scope (all
// dimensions nil) is valid. The pointer dimensions (TimeWindow,
// Quantity, Monetary) carry no ordering constraint and are not
// inspected here.
func ValidateScope(s Scope) error {
	dimensions := []struct {
		name   string
		values []string
	}{
		{"resources", s.Resources},
		{"subjects", s.Subjects},
		{"actions", s.Actions},
		{"organizations", s.Organizations},
		{"geography", s.Geography},
		{"channels", s.Channels},
	}
	for _, d := range dimensions {
		if err := validateSortedStrings(d.values); err != nil {
			return fmt.Errorf("scope %s: %w", d.name, err)
		}
	}
	return nil
}

// validateSortedStrings reports whether vals is sorted strictly
// ascending. Nil and single-element slices are trivially sorted.
func validateSortedStrings(vals []string) error {
	for i := 1; i < len(vals); i++ {
		if vals[i-1] >= vals[i] {
			return fmt.Errorf("%w at index %d", ErrUnsortedScope, i)
		}
	}
	return nil
}
