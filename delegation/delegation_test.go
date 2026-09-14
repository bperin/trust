package delegation

import (
	"encoding/hex"
	"errors"
	"testing"
	"time"

	"github.com/bperin/trust/authority"
)

var (
	testWindowStart = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	testWindowEnd   = time.Date(2026, 12, 31, 23, 59, 59, 0, time.UTC)
)

func intPtr(n int) *int { return &n }

// testParent returns a broadly-scoped parent: three capabilities,
// constrained resources/actions, a 2026 time window, quantity and
// monetary bounds, 2026 validity, and MaxDepth 3.
func testParent() *authority.Authority {
	return &authority.Authority{
		Subject: "did:example:parent",
		Capabilities: []authority.Capability{
			authority.CapabilityAttest,
			authority.CapabilityDelegate,
			authority.CapabilitySign,
		},
		Scope: authority.Scope{
			Resources: []string{"doc:a", "doc:b"},
			Actions:   []string{"read", "write"},
			TimeWindow: &authority.TimeWindow{
				Start: testWindowStart,
				End:   testWindowEnd,
			},
			Quantity: &authority.Quantity{Unit: "operations", Limit: 100},
			Monetary: &authority.Monetary{Currency: "USD", Limit: 1000},
		},
		Validity: authority.Validity{
			NotBefore: testWindowStart,
			NotAfter:  testWindowEnd,
		},
		DelegationConstraints: authority.DelegationConstraints{MaxDepth: intPtr(3)},
		Status:                authority.StatusActive,
	}
}

// validSpec returns a DelegationSpec that is a strict subset of
// testParent in every dimension.
func validSpec() DelegationSpec {
	return DelegationSpec{
		Subject:      "did:example:child",
		Capabilities: []authority.Capability{authority.CapabilityAttest},
		Scope: authority.Scope{
			Resources: []string{"doc:a"},
			Actions:   []string{"read"},
			TimeWindow: &authority.TimeWindow{
				Start: time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC),
				End:   time.Date(2026, 6, 30, 0, 0, 0, 0, time.UTC),
			},
			Quantity: &authority.Quantity{Unit: "operations", Limit: 10},
			Monetary: &authority.Monetary{Currency: "USD", Limit: 100},
		},
		Validity: authority.Validity{
			NotBefore: time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC),
			NotAfter:  time.Date(2026, 11, 30, 0, 0, 0, 0, time.UTC),
		},
		DelegationConstraints: authority.DelegationConstraints{MaxDepth: intPtr(2)},
	}
}

// TestDerive_StrictSubset verifies a valid strict-subset derivation:
// the child's Parent is the hex encoding of the parent's canonical
// hash, Status is Active, Proof is zeroed, and the spec fields are
// copied through.
func TestDerive_StrictSubset(t *testing.T) {
	t.Parallel()

	parent := testParent()
	spec := validSpec()

	child, err := Derive(parent, spec)
	if err != nil {
		t.Fatalf("Derive: %v", err)
	}

	ph, err := authority.CanonicalHash(parent)
	if err != nil {
		t.Fatalf("CanonicalHash: %v", err)
	}
	wantParent := hex.EncodeToString(ph[:])
	if child.Parent == nil {
		t.Fatal("child.Parent is nil, want hex canonical hash")
	}
	if *child.Parent != wantParent {
		t.Errorf("child.Parent = %q, want %q", *child.Parent, wantParent)
	}

	if child.Status != authority.StatusActive {
		t.Errorf("child.Status = %d, want %d (StatusActive)", child.Status, authority.StatusActive)
	}

	if len(child.Proof.Signature) != 0 {
		t.Errorf("child.Proof.Signature = %x, want empty (unsigned)", child.Proof.Signature)
	}
	if child.Proof.Algorithm != 0 || child.Proof.KeyID != "" {
		t.Errorf("child.Proof = %+v, want zero proof", child.Proof)
	}

	if child.Subject != spec.Subject {
		t.Errorf("child.Subject = %q, want %q", child.Subject, spec.Subject)
	}
	if len(child.Capabilities) != 1 || child.Capabilities[0] != authority.CapabilityAttest {
		t.Errorf("child.Capabilities = %v, want [attest]", child.Capabilities)
	}
	if child.DelegationConstraints.MaxDepth == nil || *child.DelegationConstraints.MaxDepth != 2 {
		t.Errorf("child MaxDepth = %v, want 2", child.DelegationConstraints.MaxDepth)
	}

	// The derived pair must satisfy VerifySubset.
	if err := VerifySubset(child, parent); err != nil {
		t.Errorf("VerifySubset(derived child, parent) = %v, want nil", err)
	}

	// The parent must not be mutated.
	if parent.Parent != nil {
		t.Errorf("parent.Parent mutated to %q, want nil", *parent.Parent)
	}
}

// TestDerive_NilParent verifies Derive rejects a nil parent.
func TestDerive_NilParent(t *testing.T) {
	t.Parallel()

	child, err := Derive(nil, validSpec())
	if err == nil {
		t.Fatal("Derive(nil, spec) = nil error, want error")
	}
	if child != nil {
		t.Errorf("Derive(nil, spec) child = %v, want nil", child)
	}
	if !errors.Is(err, authority.ErrNilAuthority) {
		t.Errorf("Derive(nil, spec) error = %v, want ErrNilAuthority", err)
	}
}

// TestDerive_Escalations runs the escalation matrix: each case mutates
// a valid spec into a violation and asserts the matching sentinel.
func TestDerive_Escalations(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		mutate func(*DelegationSpec)
		want   error
	}{
		{
			name: "capability not held by parent",
			mutate: func(s *DelegationSpec) {
				s.Capabilities = append(s.Capabilities, authority.CapabilityRevoke)
			},
			want: ErrCapabilityEscalation,
		},
		{
			name: "capability where parent has none at all",
			mutate: func(s *DelegationSpec) {
				s.Capabilities = []authority.Capability{{Namespace: "evil", Name: "admin"}}
			},
			want: ErrCapabilityEscalation,
		},
		{
			name: "resource not in parent scope",
			mutate: func(s *DelegationSpec) {
				s.Scope.Resources = []string{"doc:a", "doc:zzz"}
			},
			want: ErrScopeEscalation,
		},
		{
			name: "action not in parent scope",
			mutate: func(s *DelegationSpec) {
				s.Scope.Actions = []string{"read", "delete"}
			},
			want: ErrScopeEscalation,
		},
		{
			name: "empty child slice under constrained parent drops the constraint",
			mutate: func(s *DelegationSpec) {
				s.Scope.Resources = nil
			},
			want: ErrScopeEscalation,
		},
		{
			name: "wider time window start",
			mutate: func(s *DelegationSpec) {
				s.Scope.TimeWindow = &authority.TimeWindow{
					Start: testWindowStart.Add(-time.Hour),
					End:   testWindowEnd,
				}
			},
			want: ErrScopeEscalation,
		},
		{
			name: "wider time window end",
			mutate: func(s *DelegationSpec) {
				s.Scope.TimeWindow = &authority.TimeWindow{
					Start: testWindowStart,
					End:   testWindowEnd.Add(time.Hour),
				}
			},
			want: ErrScopeEscalation,
		},
		{
			name: "nil time window under constrained parent",
			mutate: func(s *DelegationSpec) {
				s.Scope.TimeWindow = nil
			},
			want: ErrScopeEscalation,
		},
		{
			name: "larger quantity limit",
			mutate: func(s *DelegationSpec) {
				s.Scope.Quantity = &authority.Quantity{Unit: "operations", Limit: 101}
			},
			want: ErrScopeEscalation,
		},
		{
			name: "quantity unit mismatch",
			mutate: func(s *DelegationSpec) {
				s.Scope.Quantity = &authority.Quantity{Unit: "documents", Limit: 10}
			},
			want: ErrScopeEscalation,
		},
		{
			name: "nil quantity under constrained parent",
			mutate: func(s *DelegationSpec) {
				s.Scope.Quantity = nil
			},
			want: ErrScopeEscalation,
		},
		{
			name: "larger monetary limit",
			mutate: func(s *DelegationSpec) {
				s.Scope.Monetary = &authority.Monetary{Currency: "USD", Limit: 1000.01}
			},
			want: ErrScopeEscalation,
		},
		{
			name: "monetary currency mismatch",
			mutate: func(s *DelegationSpec) {
				s.Scope.Monetary = &authority.Monetary{Currency: "EUR", Limit: 10}
			},
			want: ErrScopeEscalation,
		},
		{
			name: "nil monetary under constrained parent",
			mutate: func(s *DelegationSpec) {
				s.Scope.Monetary = nil
			},
			want: ErrScopeEscalation,
		},
		{
			name: "validity starts before parent",
			mutate: func(s *DelegationSpec) {
				s.Validity.NotBefore = testWindowStart.Add(-time.Second)
			},
			want: ErrValidityEscalation,
		},
		{
			name: "validity ends after parent",
			mutate: func(s *DelegationSpec) {
				s.Validity.NotAfter = testWindowEnd.Add(time.Second)
			},
			want: ErrValidityEscalation,
		},
		{
			name: "nil child MaxDepth under bounded parent",
			mutate: func(s *DelegationSpec) {
				s.DelegationConstraints.MaxDepth = nil
			},
			want: ErrDepthEscalation,
		},
		{
			name: "child MaxDepth equal to parent's is not strict",
			mutate: func(s *DelegationSpec) {
				s.DelegationConstraints.MaxDepth = intPtr(3)
			},
			want: ErrDepthEscalation,
		},
		{
			name: "child MaxDepth above parent's",
			mutate: func(s *DelegationSpec) {
				s.DelegationConstraints.MaxDepth = intPtr(4)
			},
			want: ErrDepthEscalation,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			spec := validSpec()
			tc.mutate(&spec)
			child, err := Derive(testParent(), spec)
			if tc.want == nil {
				if err != nil {
					t.Fatalf("Derive = %v, want nil error", err)
				}
				if child == nil {
					t.Fatal("Derive returned nil child on success")
				}
				return
			}
			if !errors.Is(err, tc.want) {
				t.Errorf("Derive error = %v, want %v", err, tc.want)
			}
			if child != nil {
				t.Errorf("Derive child = %v, want nil on escalation", child)
			}
		})
	}
}

// TestDerive_DepthBoundaries covers the delegation-depth boundary
// matrix: unbounded parent admits any child; bounded parent requires a
// strictly-smaller non-nil child bound.
func TestDerive_DepthBoundaries(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		parentDepth *int
		childDepth  *int
		wantErr     error
	}{
		{name: "unbounded parent, nil child", parentDepth: nil, childDepth: nil},
		{name: "unbounded parent, bounded child", parentDepth: nil, childDepth: intPtr(0)},
		{name: "unbounded parent, deep child", parentDepth: nil, childDepth: intPtr(99)},
		{name: "parent depth 2, nil child", parentDepth: intPtr(2), childDepth: nil, wantErr: ErrDepthEscalation},
		{name: "parent depth 2, child depth 1", parentDepth: intPtr(2), childDepth: intPtr(1)},
		{name: "parent depth 2, child depth 0", parentDepth: intPtr(2), childDepth: intPtr(0)},
		{name: "parent depth 2, child depth 2", parentDepth: intPtr(2), childDepth: intPtr(2), wantErr: ErrDepthEscalation},
		{name: "parent depth 1, child depth 0", parentDepth: intPtr(1), childDepth: intPtr(0)},
		{name: "parent depth 0 admits no delegation", parentDepth: intPtr(0), childDepth: intPtr(0), wantErr: ErrDepthEscalation},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			parent := testParent()
			parent.DelegationConstraints.MaxDepth = tc.parentDepth
			spec := validSpec()
			spec.DelegationConstraints.MaxDepth = tc.childDepth

			child, err := Derive(parent, spec)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("Derive error = %v, want %v", err, tc.wantErr)
			}
			if tc.wantErr == nil && child == nil {
				t.Fatal("Derive returned nil child on success")
			}
			if tc.wantErr != nil && child != nil {
				t.Errorf("Derive child = %v, want nil on escalation", child)
			}
		})
	}
}

// TestDerive_UnconstrainedParent verifies a parent with no scope
// constraints admits a child that adds its own pointer-dimension
// bounds — narrowing an unconstrained parent is a subset, not an
// escalation. Slice dimensions follow the same rule: an empty parent
// slice is unconstrained and admits any child slice.
func TestDerive_UnconstrainedParent(t *testing.T) {
	t.Parallel()

	parent := testParent()
	parent.Scope = authority.Scope{} // fully unconstrained

	spec := validSpec()
	spec.Scope = authority.Scope{
		TimeWindow: &authority.TimeWindow{Start: testWindowStart, End: testWindowEnd},
		Quantity:   &authority.Quantity{Unit: "operations", Limit: 5},
		Monetary:   &authority.Monetary{Currency: "EUR", Limit: 1},
	}

	child, err := Derive(parent, spec)
	if err != nil {
		t.Fatalf("Derive = %v, want nil error under unconstrained parent", err)
	}
	if child == nil {
		t.Fatal("Derive returned nil child on success")
	}

	// A child slice element under an empty parent slice narrows an
	// unconstrained dimension: empty parent admits any child.
	spec.Scope.Resources = []string{"anything"}
	child, err = Derive(parent, spec)
	if err != nil {
		t.Errorf("Derive with child resource under unconstrained parent = %v, want nil error", err)
	}
	if child == nil {
		t.Error("Derive returned nil child on success")
	}
}

// TestVerifySubset runs VerifySubset over a valid pair, each violation
// dimension, and nil inputs.
func TestVerifySubset(t *testing.T) {
	t.Parallel()

	parent := testParent()
	validChild, err := Derive(parent, validSpec())
	if err != nil {
		t.Fatalf("Derive fixture: %v", err)
	}

	// childWith returns a minimal valid-subset child with one field
	// swapped out per case.
	childWith := func(mutate func(*authority.Authority)) *authority.Authority {
		c := *validChild
		mutate(&c)
		return &c
	}

	tests := []struct {
		name  string
		child *authority.Authority
		want  error
	}{
		{
			name:  "valid pair",
			child: validChild,
			want:  nil,
		},
		{
			name: "capability escalation",
			child: childWith(func(c *authority.Authority) {
				c.Capabilities = append(c.Capabilities, authority.CapabilityRevoke)
			}),
			want: ErrCapabilityEscalation,
		},
		{
			name: "scope escalation",
			child: childWith(func(c *authority.Authority) {
				c.Scope.Resources = []string{"doc:a", "doc:zzz"}
			}),
			want: ErrScopeEscalation,
		},
		{
			name: "scope escalation via nil window under constrained parent",
			child: childWith(func(c *authority.Authority) {
				c.Scope.TimeWindow = nil
			}),
			want: ErrScopeEscalation,
		},
		{
			name: "validity escalation",
			child: childWith(func(c *authority.Authority) {
				c.Validity.NotAfter = testWindowEnd.Add(time.Hour)
			}),
			want: ErrValidityEscalation,
		},
		{
			name: "depth escalation",
			child: childWith(func(c *authority.Authority) {
				c.DelegationConstraints.MaxDepth = nil
			}),
			want: ErrDepthEscalation,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := VerifySubset(tc.child, parent)
			if !errors.Is(err, tc.want) {
				t.Errorf("VerifySubset = %v, want %v", err, tc.want)
			}
		})
	}
}

// TestVerifySubset_NilInputs verifies nil child and nil parent each
// return an error.
func TestVerifySubset_NilInputs(t *testing.T) {
	t.Parallel()

	parent := testParent()
	child, err := Derive(parent, validSpec())
	if err != nil {
		t.Fatalf("Derive fixture: %v", err)
	}

	if err := VerifySubset(nil, parent); err == nil {
		t.Error("VerifySubset(nil, parent) = nil, want error")
	}
	if err := VerifySubset(child, nil); err == nil {
		t.Error("VerifySubset(child, nil) = nil, want error")
	}
	if err := VerifySubset(nil, nil); err == nil {
		t.Error("VerifySubset(nil, nil) = nil, want error")
	}
}

// TestVerifySubset_FirstViolationWins verifies that when several
// dimensions escalate at once, the first check in the fixed order —
// capabilities before scope before validity before depth — supplies
// the returned sentinel.
func TestVerifySubset_FirstViolationWins(t *testing.T) {
	t.Parallel()

	parent := testParent()
	child, err := Derive(parent, validSpec())
	if err != nil {
		t.Fatalf("Derive fixture: %v", err)
	}

	// Escalate scope, validity, and depth simultaneously: capability
	// still passes, so scope wins.
	child.Scope.Resources = []string{"doc:a", "doc:zzz"}
	child.Validity.NotAfter = testWindowEnd.Add(time.Hour)
	child.DelegationConstraints.MaxDepth = nil
	if err := VerifySubset(child, parent); !errors.Is(err, ErrScopeEscalation) {
		t.Errorf("VerifySubset = %v, want ErrScopeEscalation (first violation)", err)
	}

	// Escalate capabilities too: now capability wins.
	child.Capabilities = append(child.Capabilities, authority.CapabilityRevoke)
	if err := VerifySubset(child, parent); !errors.Is(err, ErrCapabilityEscalation) {
		t.Errorf("VerifySubset = %v, want ErrCapabilityEscalation (first violation)", err)
	}
}

// TestHelpers_SubsetBoundaries exercises the package-private subset
// helpers directly at their boundaries.
func TestHelpers_SubsetBoundaries(t *testing.T) {
	t.Parallel()

	t.Run("stringSliceSubset", func(t *testing.T) {
		t.Parallel()
		cases := []struct {
			name   string
			parent []string
			child  []string
			want   bool
		}{
			{"empty child of empty parent", nil, nil, true},
			{"empty child of non-empty parent", []string{"a"}, nil, false},
			{"non-empty child of empty parent", nil, []string{"a"}, true},
			{"equal", []string{"a", "b"}, []string{"a", "b"}, true},
			{"strict subset", []string{"a", "b"}, []string{"b"}, true},
			{"element not in parent", []string{"a"}, []string{"a", "b"}, false},
		}
		for _, tc := range cases {
			if got := stringSliceSubset(tc.parent, tc.child); got != tc.want {
				t.Errorf("%s: stringSliceSubset(%v, %v) = %v, want %v", tc.name, tc.parent, tc.child, got, tc.want)
			}
		}
	})

	t.Run("timeWindowSubset", func(t *testing.T) {
		t.Parallel()
		p := &authority.TimeWindow{Start: testWindowStart, End: testWindowEnd}
		cases := []struct {
			name   string
			parent *authority.TimeWindow
			child  *authority.TimeWindow
			want   bool
		}{
			{"nil child of nil parent", nil, nil, true},
			{"nil child of bounded parent", p, nil, false},
			{"bounded child of nil parent", nil, p, true},
			{"equal windows", p, &authority.TimeWindow{Start: testWindowStart, End: testWindowEnd}, true},
			{"strict subset", p, &authority.TimeWindow{Start: testWindowStart.Add(time.Hour), End: testWindowEnd.Add(-time.Hour)}, true},
			{"start before parent", p, &authority.TimeWindow{Start: testWindowStart.Add(-time.Hour), End: testWindowEnd}, false},
			{"end after parent", p, &authority.TimeWindow{Start: testWindowStart, End: testWindowEnd.Add(time.Hour)}, false},
		}
		for _, tc := range cases {
			if got := timeWindowSubset(tc.parent, tc.child); got != tc.want {
				t.Errorf("%s: timeWindowSubset = %v, want %v", tc.name, got, tc.want)
			}
		}
	})

	t.Run("quantitySubset", func(t *testing.T) {
		t.Parallel()
		p := &authority.Quantity{Unit: "operations", Limit: 10}
		cases := []struct {
			name   string
			parent *authority.Quantity
			child  *authority.Quantity
			want   bool
		}{
			{"nil child of nil parent", nil, nil, true},
			{"nil child of bounded parent", p, nil, false},
			{"bounded child of nil parent", nil, p, true},
			{"equal limit same unit", p, &authority.Quantity{Unit: "operations", Limit: 10}, true},
			{"smaller limit same unit", p, &authority.Quantity{Unit: "operations", Limit: 5}, true},
			{"larger limit same unit", p, &authority.Quantity{Unit: "operations", Limit: 11}, false},
			{"smaller limit different unit", p, &authority.Quantity{Unit: "documents", Limit: 5}, false},
		}
		for _, tc := range cases {
			if got := quantitySubset(tc.parent, tc.child); got != tc.want {
				t.Errorf("%s: quantitySubset = %v, want %v", tc.name, got, tc.want)
			}
		}
	})

	t.Run("monetarySubset", func(t *testing.T) {
		t.Parallel()
		p := &authority.Monetary{Currency: "USD", Limit: 100}
		cases := []struct {
			name   string
			parent *authority.Monetary
			child  *authority.Monetary
			want   bool
		}{
			{"nil child of nil parent", nil, nil, true},
			{"nil child of bounded parent", p, nil, false},
			{"bounded child of nil parent", nil, p, true},
			{"equal limit same currency", p, &authority.Monetary{Currency: "USD", Limit: 100}, true},
			{"smaller limit same currency", p, &authority.Monetary{Currency: "USD", Limit: 50}, true},
			{"larger limit same currency", p, &authority.Monetary{Currency: "USD", Limit: 100.01}, false},
			{"smaller limit different currency", p, &authority.Monetary{Currency: "EUR", Limit: 50}, false},
		}
		for _, tc := range cases {
			if got := monetarySubset(tc.parent, tc.child); got != tc.want {
				t.Errorf("%s: monetarySubset = %v, want %v", tc.name, got, tc.want)
			}
		}
	})

	t.Run("delegationDepthOK", func(t *testing.T) {
		t.Parallel()
		cases := []struct {
			name   string
			parent authority.DelegationConstraints
			child  authority.DelegationConstraints
			want   bool
		}{
			{"nil parent admits nil child", authority.DelegationConstraints{}, authority.DelegationConstraints{}, true},
			{"nil parent admits bounded child", authority.DelegationConstraints{}, authority.DelegationConstraints{MaxDepth: intPtr(7)}, true},
			{"bounded parent rejects nil child", authority.DelegationConstraints{MaxDepth: intPtr(2)}, authority.DelegationConstraints{}, false},
			{"strictly smaller child ok", authority.DelegationConstraints{MaxDepth: intPtr(2)}, authority.DelegationConstraints{MaxDepth: intPtr(1)}, true},
			{"equal depth rejected", authority.DelegationConstraints{MaxDepth: intPtr(2)}, authority.DelegationConstraints{MaxDepth: intPtr(2)}, false},
			{"larger child rejected", authority.DelegationConstraints{MaxDepth: intPtr(2)}, authority.DelegationConstraints{MaxDepth: intPtr(3)}, false},
		}
		for _, tc := range cases {
			if got := delegationDepthOK(tc.parent, tc.child); got != tc.want {
				t.Errorf("%s: delegationDepthOK = %v, want %v", tc.name, got, tc.want)
			}
		}
	})
}
