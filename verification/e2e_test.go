package verification

import (
	"errors"
	"testing"
	"time"
)

// TestE2E_ValidPath verifies a valid leaf→root fixture end to end.
func TestE2E_ValidPath(t *testing.T) {
	t.Parallel()
	f := buildFixture(t)
	res, err := NewEngine().Verify(f.inputs())
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !res.Valid {
		for _, fl := range res.Failures {
			t.Errorf("failure: check=%v hop=%d err=%v", fl.Check, fl.Hop, fl.Err)
		}
		t.Fatal("valid path reported invalid")
	}
	if len(res.Failures) != 0 {
		t.Errorf("failures = %d, want 0", len(res.Failures))
	}
}

// TestE2E_FiveHeadlineModes drives the five headline failure modes,
// each producing its exact sentinel, pairwise distinct.
func TestE2E_FiveHeadlineModes(t *testing.T) {
	t.Parallel()
	modes := []struct {
		name  string
		build func(t *testing.T) (*fixture, Inputs)
		want  error
	}{
		{"tampered attestation", func(t *testing.T) (*fixture, Inputs) {
			f := buildFixture(t)
			f.att.Signature[0] ^= 0xff
			return f, f.inputs()
		}, ErrSignatureMismatch},
		{"escalated scope", func(t *testing.T) (*fixture, Inputs) {
			f := buildFixtureWith(t, fixtureOpts{claimResources: []string{"secret-resource"}})
			return f, f.inputs()
		}, ErrScopeViolation},
		{"expired window", func(t *testing.T) (*fixture, Inputs) {
			f := buildFixture(t)
			in := f.inputs()
			in.Now = f.now.Add(2 * time.Hour)
			return f, in
		}, ErrExpired},
		{"revoked authority", func(t *testing.T) (*fixture, Inputs) {
			f := buildFixtureWith(t, fixtureOpts{revokeHop: 1})
			return f, f.inputs()
		}, ErrRevoked},
		{"broken chain", func(t *testing.T) (*fixture, Inputs) {
			f := buildFixture(t)
			f.makeDetachedRoot(t)
			f.chain[2] = f.detachedRoot
			return f, f.inputs()
		}, ErrChainBroken},
	}

	sentinels := []error{ErrSignatureMismatch, ErrScopeViolation, ErrExpired, ErrRevoked, ErrChainBroken}

	for _, m := range modes {
		m := m
		t.Run(m.name, func(t *testing.T) {
			t.Parallel()
			_, in := m.build(t)
			res, err := NewEngine().Verify(in)
			if err != nil {
				t.Fatalf("Verify: %v", err)
			}
			if res.Valid {
				t.Fatalf("result valid, want failure")
			}
			if len(res.Failures) == 0 {
				t.Fatalf("no failures recorded, want %v", m.want)
			}
			if !errors.Is(res.Failures[0].Err, m.want) {
				t.Errorf("err = %v, want %v", res.Failures[0].Err, m.want)
			}
		})
	}

	// The five headline sentinels are pairwise distinct error values.
	for i := 0; i < len(sentinels); i++ {
		for j := i + 1; j < len(sentinels); j++ {
			if sentinels[i] == sentinels[j] {
				t.Errorf("sentinels %d and %d alias", i, j)
			}
		}
	}
}
