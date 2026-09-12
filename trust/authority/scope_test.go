package authority

import (
	"errors"
	"testing"
)

// TestScopeIntersection exercises each scope dimension: a child
// within the parent's bound verifies; a child exceeding it fails
// with ErrScopeViolation.
func TestScopeIntersection(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(specs []chainSpec)
		want   error
	}{
		{"resource outside parent", func(s []chainSpec) {
			s[1].resources = []string{"res-a", "res-x"}
		}, ErrScopeViolation},
		{"organization outside parent", func(s []chainSpec) {
			s[1].orgs = []string{"org-9"}
		}, ErrScopeViolation},
		{"geography outside parent", func(s []chainSpec) {
			s[1].geos = []string{"US", "APAC"}
		}, ErrScopeViolation},
		{"channel outside parent", func(s []chainSpec) {
			s[1].channels = []string{"online", "phone"}
		}, ErrScopeViolation},
		{"quantity exceeds parent", func(s []chainSpec) {
			s[1].quantity = u64(2000)
		}, ErrScopeViolation},
		{"monetary amount exceeds parent", func(s []chainSpec) {
			s[1].monetary = &Monetary{Amount: 20000, Currency: "USD"}
		}, ErrScopeViolation},
		{"monetary currency outside parent", func(s []chainSpec) {
			s[1].monetary = &Monetary{Amount: 100, Currency: "EUR"}
		}, ErrScopeViolation},
		{"window precedes parent", func(s []chainSpec) {
			s[1].window = &TimeWindow{NotBefore: winStart.AddDate(0, 0, -1), NotAfter: winNarrow1}
		}, ErrScopeViolation},
		{"window exceeds parent", func(s []chainSpec) {
			s[2].window = &TimeWindow{NotBefore: winLeaf0, NotAfter: winEnd.AddDate(0, 0, 1)}
		}, ErrScopeViolation},
	}
	for _, vc := range cases {
		for _, tc := range algorithmCases {
			t.Run(vc.name+"/"+tc.name, func(t *testing.T) {
				specs := baseSpecs()
				vc.mutate(specs)
				chain, rootPub := buildSignedChain(t, tc.alg, specs)
				_, err := VerifyChain(chain, rootPub)
				if !errors.Is(err, vc.want) {
					t.Fatalf("VerifyChain: err = %v, want %v", err, vc.want)
				}
			})
		}
	}
}

// TestScopeWithinParent confirms a child strictly inside every
// parent dimension verifies and inherits bounds it does not narrow.
func TestScopeWithinParent(t *testing.T) {
	for _, tc := range algorithmCases {
		t.Run(tc.name, func(t *testing.T) {
			specs := baseSpecs()
			// Leaf narrows nothing: it inherits the effective scope.
			specs[2] = chainSpec{version: 3}
			chain, rootPub := buildSignedChain(t, tc.alg, specs)
			scope, err := VerifyChain(chain, rootPub)
			if err != nil {
				t.Fatalf("VerifyChain: %v", err)
			}
			assertScopeEqual(t, scope, Scope{
				Resources:       []string{"res-a", "res-b"},
				Actions:         []string{"product.attest", "delegate"},
				Organizations:   []string{"org-1"},
				Geographies:     []string{"US"},
				Channels:        []string{"online"},
				TimeWindow:      &TimeWindow{NotBefore: winNarrow0, NotAfter: winNarrow1},
				QuantityLimit:   u64(500),
				MonetaryLimit:   &Monetary{Amount: 5000, Currency: "USD"},
				DelegationDepth: u(1), // min(5-2, 2-1)
			})
		})
	}
}

// TestCapabilityNotCovered rejects a leaf that declares a capability
// outside its parent's effective set.
func TestCapabilityNotCovered(t *testing.T) {
	for _, tc := range algorithmCases {
		t.Run(tc.name, func(t *testing.T) {
			specs := baseSpecs()
			specs[2].caps = []string{"product.attest", "admin"}
			chain, rootPub := buildSignedChain(t, tc.alg, specs)
			_, err := VerifyChain(chain, rootPub)
			if !errors.Is(err, ErrCapabilityNotCovered) {
				t.Fatalf("VerifyChain: err = %v, want ErrCapabilityNotCovered", err)
			}
		})
	}
}
