package verification

import (
	"errors"
	"fmt"
	"testing"
)

// allTrustSentinels lists the 17 trust sentinels in errors.go.
var allTrustSentinels = []error{
	ErrSignatureMismatch, ErrSignatureKeyMismatch, ErrAuthorityInvalid,
	ErrChainBroken, ErrNotRootAuthority, ErrDelegationDepth,
	ErrCapabilityNotGranted, ErrScopeViolation, ErrNotYetValid,
	ErrExpired, ErrRevoked, ErrSuperseded, ErrIdentityUnresolved,
	ErrKeyBinding, ErrEvidenceIntegrity, ErrProvenanceMismatch,
	ErrCommitmentInvalid, ErrStructural,
}

// allProgrammerSentinels lists the 4 programmer sentinels.
var allProgrammerSentinels = []error{
	ErrNilAttestation, ErrNilSigningKey, ErrEmptyChain, ErrNilProvenance,
}

func TestFailureSentinelsNeverAlias(t *testing.T) {
	t.Parallel()
	for i, a := range allTrustSentinels {
		for j, b := range allTrustSentinels {
			if i == j {
				continue
			}
			if errors.Is(a, b) {
				t.Errorf("sentinel %d aliases sentinel %d (forward)", i, j)
			}
			if errors.Is(b, a) {
				t.Errorf("sentinel %d aliases sentinel %d (reverse)", j, i)
			}
		}
	}
	for i, a := range allProgrammerSentinels {
		for j, b := range allProgrammerSentinels {
			if i == j {
				continue
			}
			if errors.Is(a, b) || errors.Is(b, a) {
				t.Errorf("programmer sentinels %d and %d alias", i, j)
			}
		}
		for j, trust := range allTrustSentinels {
			if errors.Is(a, trust) || errors.Is(trust, a) {
				t.Errorf("programmer sentinel %d aliases trust sentinel %d", i, j)
			}
		}
	}
}

func TestSentinelWrapping(t *testing.T) {
	t.Parallel()
	err := fmt.Errorf("hop %d: %w", 2, ErrExpired)
	if !errors.Is(err, ErrExpired) {
		t.Error("wrapped sentinel not matched by errors.Is")
	}
}

func TestSentinelMessagesPrefixed(t *testing.T) {
	t.Parallel()
	for i, s := range append(append([]error{}, allTrustSentinels...), allProgrammerSentinels...) {
		if len(s.Error()) < len("verification: ") || s.Error()[:13] != "verification:" {
			t.Errorf("sentinel %d message %q lacks verification: prefix", i, s.Error())
		}
	}
}
