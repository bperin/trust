package verification

import (
	"strings"
	"testing"
)

func TestCheckIDValues(t *testing.T) {
	tests := []struct {
		name string
		id   CheckID
		want int
	}{
		{"CheckStructural", CheckStructural, 1},
		{"CheckSignature", CheckSignature, 2},
		{"CheckAuthorization", CheckAuthorization, 3},
		{"CheckAuthorityProof", CheckAuthorityProof, 4},
		{"CheckChainLink", CheckChainLink, 5},
		{"CheckRootAuthority", CheckRootAuthority, 6},
		{"CheckTemporal", CheckTemporal, 7},
		{"CheckRevocation", CheckRevocation, 8},
		{"CheckIdentity", CheckIdentity, 9},
		{"CheckKeyBinding", CheckKeyBinding, 10},
		{"CheckEvidence", CheckEvidence, 11},
		{"CheckProvenance", CheckProvenance, 12},
		{"CheckCommitment", CheckCommitment, 13},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := int(tt.id); got != tt.want {
				t.Errorf("%s = %d, want %d", tt.name, got, tt.want)
			}
		})
	}
}

func TestCheckIDString(t *testing.T) {
	tests := []struct {
		id   CheckID
		want string
	}{
		{CheckStructural, "structural"},
		{CheckSignature, "signature"},
		{CheckAuthorization, "authorization"},
		{CheckAuthorityProof, "authority_proof"},
		{CheckChainLink, "chain_link"},
		{CheckRootAuthority, "root_authority"},
		{CheckTemporal, "temporal"},
		{CheckRevocation, "revocation"},
		{CheckIdentity, "identity"},
		{CheckKeyBinding, "key_binding"},
		{CheckEvidence, "evidence"},
		{CheckProvenance, "provenance"},
		{CheckCommitment, "commitment"},
	}
	seen := make(map[string]CheckID, len(tests))
	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			got := tt.id.String()
			if got != tt.want {
				t.Errorf("CheckID(%d).String() = %q, want %q", int(tt.id), got, tt.want)
			}
			if got == "" {
				t.Errorf("CheckID(%d).String() is empty", int(tt.id))
			}
			if got != strings.ToLower(got) {
				t.Errorf("CheckID(%d).String() = %q is not lowercase", int(tt.id), got)
			}
			if prev, dup := seen[got]; dup {
				t.Errorf("CheckID(%d).String() = %q duplicates CheckID(%d)", int(tt.id), got, int(prev))
			}
			seen[got] = tt.id
		})
	}
}

func TestCheckIDStringUnknown(t *testing.T) {
	for _, id := range []CheckID{0, -1, 14, 99} {
		if got := id.String(); got != "unknown" {
			t.Errorf("CheckID(%d).String() = %q, want %q", int(id), got, "unknown")
		}
	}
}

func TestCheckStatusDistinct(t *testing.T) {
	statuses := []struct {
		name   string
		status CheckStatus
		want   int
	}{
		{"CheckPassed", CheckPassed, 1},
		{"CheckFailed", CheckFailed, 2},
		{"CheckSkipped", CheckSkipped, 3},
	}
	for _, tt := range statuses {
		t.Run(tt.name, func(t *testing.T) {
			if got := int(tt.status); got != tt.want {
				t.Errorf("%s = %d, want %d", tt.name, got, tt.want)
			}
		})
	}
	if CheckPassed == CheckFailed || CheckFailed == CheckSkipped || CheckPassed == CheckSkipped {
		t.Error("CheckPassed, CheckFailed, CheckSkipped must be three distinct values")
	}
}

func TestResultValidZeroFailures(t *testing.T) {
	tests := []struct {
		name     string
		failures []Failure
	}{
		{"nil failures", nil},
		{"empty failures", []Failure{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := Result{Valid: true, Failures: tt.failures}
			if !r.Valid {
				t.Error("Result.Valid = false, want true for zero failures")
			}
			if !r.consistent() {
				t.Error("Result violates Valid == (len(Failures)==0) invariant")
			}
		})
	}
}

func TestResultInvalidWithFailures(t *testing.T) {
	tests := []struct {
		name     string
		failures []Failure
	}{
		{"one failure", []Failure{{Check: CheckSignature, Err: ErrSignatureMismatch, Hop: -1}}},
		{"two failures", []Failure{
			{Check: CheckSignature, Err: ErrSignatureMismatch, Hop: -1},
			{Check: CheckTemporal, Err: ErrExpired, Hop: 0},
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := Result{Valid: false, Failures: tt.failures}
			if r.Valid {
				t.Error("Result.Valid = true, want false when failures present")
			}
			if !r.consistent() {
				t.Error("Result violates Valid == (len(Failures)==0) invariant")
			}
		})
	}
}

func TestResultInconsistentAssembly(t *testing.T) {
	tests := []struct {
		name string
		r    Result
	}{
		{"valid with failures", Result{Valid: true, Failures: []Failure{{Check: CheckSignature, Err: ErrSignatureMismatch, Hop: -1}}}},
		{"invalid with no failures", Result{Valid: false, Failures: nil}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.r.consistent() {
				t.Error("mis-assembled Result reports consistent, want false")
			}
		})
	}
}

func TestFailureHopRoundTrip(t *testing.T) {
	f := Failure{Check: CheckSignature, Err: ErrSignatureMismatch, Hop: -1, Detail: "sig verify failed"}
	r := Result{Valid: false, Failures: []Failure{f}}
	got := r.Failures[0]
	if got.Hop != -1 {
		t.Errorf("Failure.Hop = %d, want -1 for non-hop-scoped check", got.Hop)
	}
	if got.Check != f.Check || got.Detail != f.Detail {
		t.Errorf("Failure round-trip changed fields: got %+v, want %+v", got, f)
	}
}
