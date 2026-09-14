package verification

import (
	"errors"
	"testing"
)

func TestCheckIDConstants(t *testing.T) {
	t.Parallel()
	cases := []struct {
		id   CheckID
		want int
	}{{CheckStructural, 1}, {CheckSignature, 2}, {CheckAuthorization, 3},
		{CheckAuthorityProof, 4}, {CheckChainLink, 5}, {CheckRootAuthority, 6},
		{CheckTemporal, 7}, {CheckRevocation, 8}, {CheckIdentity, 9},
		{CheckKeyBinding, 10}, {CheckEvidence, 11}, {CheckProvenance, 12},
		{CheckCommitment, 13}}
	for _, c := range cases {
		if int(c.id) != c.want {
			t.Errorf("CheckID %d != %d", c.id, c.want)
		}
	}
}

func TestCheckIDString(t *testing.T) {
	t.Parallel()
	seen := map[string]bool{}
	for id := CheckStructural; id <= CheckCommitment; id++ {
		s := id.String()
		if s == "" || s == "unknown" {
			t.Errorf("CheckID %d has no stable name", id)
		}
		if seen[s] {
			t.Errorf("CheckID.String() duplicate %q", s)
		}
		seen[s] = true
	}
	if CheckStructural.String() != "structural" || CheckCommitment.String() != "commitment" {
		t.Errorf("stable names drifted: %q, %q", CheckStructural, CheckCommitment)
	}
}

func TestCheckStatusDistinct(t *testing.T) {
	t.Parallel()
	if CheckPassed == CheckFailed || CheckFailed == CheckSkipped || CheckPassed == CheckSkipped {
		t.Error("check statuses not distinct")
	}
	if CheckPassed != 1 || CheckFailed != 2 || CheckSkipped != 3 {
		t.Errorf("unexpected status values: %d %d %d", CheckPassed, CheckFailed, CheckSkipped)
	}
}

func TestResultValidZeroFailures(t *testing.T) {
	t.Parallel()
	f := buildFixture(t)
	res, err := NewEngine().Verify(f.inputs())
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !res.Valid {
		t.Error("engine result with zero failures should be valid")
	}
	if len(res.Failures) != 0 {
		t.Errorf("failures = %d, want 0", len(res.Failures))
	}
}

func TestResultInvalidWithFailures(t *testing.T) {
	t.Parallel()
	f := buildFixture(t)
	in := f.inputs()
	in.Attestation.Signature[0] ^= 0xff
	res, err := NewEngine().Verify(in)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if res.Valid {
		t.Error("engine result with failures should be invalid")
	}
	if len(res.Failures) == 0 {
		t.Error("failures should be populated")
	}
	if !errors.Is(res.Failures[0].Err, ErrSignatureMismatch) {
		t.Errorf("failure err = %v, want ErrSignatureMismatch", res.Failures[0].Err)
	}
}

func TestFailureHopConvention(t *testing.T) {
	t.Parallel()
	f := Failure{Check: CheckSignature, Err: ErrSignatureMismatch, Hop: -1}
	if f.Hop != -1 {
		t.Errorf("non-hop failure Hop = %d, want -1", f.Hop)
	}
	res := Result{Failures: []Failure{f}}
	if res.Failures[0].Hop != -1 {
		t.Error("Failure.Hop did not round-trip through Result")
	}
}
