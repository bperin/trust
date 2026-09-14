package attestation

import (
	"errors"
	"testing"
	"time"

	"github.com/bperin/trust/authority"
	"github.com/bperin/trust/evidence"
)

// TestValidate is the table-driven rejection suite: every structural
// violation maps to its typed sentinel.
func TestValidate(t *testing.T) {
	t.Parallel()

	unsorted := func(t *testing.T) []evidence.Evidence {
		sorted := sortEvidence(t, []evidence.Evidence{testEvidence("ev-a"), testEvidence("ev-b")})
		// Reverse canonical order — guaranteed unsorted.
		return []evidence.Evidence{sorted[1], sorted[0]}
	}
	duplicated := func(t *testing.T) []evidence.Evidence {
		sorted := sortEvidence(t, []evidence.Evidence{testEvidence("ev-a")})
		return []evidence.Evidence{sorted[0], sorted[0]}
	}

	cases := []struct {
		name    string
		mutate  func(t *testing.T, a *Attestation)
		nilAtt  bool
		wantErr error
	}{
		{name: "nil attestation", nilAtt: true, wantErr: ErrNilAttestation},
		{name: "empty issuer", mutate: func(_ *testing.T, a *Attestation) { a.Issuer = "" }, wantErr: ErrEmptyIssuer},
		{name: "empty signing key id", mutate: func(_ *testing.T, a *Attestation) { a.SigningKeyID = "" }, wantErr: ErrEmptySigningKeyID},
		{name: "empty authority ref", mutate: func(_ *testing.T, a *Attestation) { a.AuthorityRef = "" }, wantErr: ErrEmptyAuthorityRef},
		{name: "empty capability namespace", mutate: func(_ *testing.T, a *Attestation) { a.Capability.Namespace = "" }, wantErr: ErrEmptyCapabilityNamespace},
		{name: "empty capability name", mutate: func(_ *testing.T, a *Attestation) { a.Capability.Name = "" }, wantErr: ErrEmptyCapabilityName},
		{name: "invalid claim", mutate: func(_ *testing.T, a *Attestation) { a.Claim.Issuer = "" }, wantErr: ErrInvalidClaim},
		{name: "invalid claim value", mutate: func(_ *testing.T, a *Attestation) { a.Claim.Value = nil }, wantErr: ErrInvalidClaim},
		{name: "invalid evidence", mutate: func(_ *testing.T, a *Attestation) { a.Evidence[0].Identifier = "" }, wantErr: ErrInvalidEvidence},
		{name: "evidence bad content hash", mutate: func(_ *testing.T, a *Attestation) {
			a.Evidence[0].ContentHash = []byte{1, 2, 3}
		}, wantErr: ErrInvalidEvidence},
		{name: "unknown status", mutate: func(_ *testing.T, a *Attestation) { a.Status = authority.Status(99) }, wantErr: ErrUnknownStatus},
		{name: "zero status", mutate: func(_ *testing.T, a *Attestation) { a.Status = 0 }, wantErr: ErrUnknownStatus},
		{name: "zero issued-at", mutate: func(_ *testing.T, a *Attestation) { a.IssuedAt = time.Time{} }, wantErr: ErrZeroIssuedAt},
		{name: "empty validity", mutate: func(_ *testing.T, a *Attestation) { a.Validity = authority.Validity{} }, wantErr: ErrEmptyValidity},
		{name: "unsorted evidence", mutate: func(t *testing.T, a *Attestation) { a.Evidence = unsorted(t) }, wantErr: ErrUnsortedEvidence},
		{name: "duplicated evidence", mutate: func(t *testing.T, a *Attestation) { a.Evidence = duplicated(t) }, wantErr: ErrUnsortedEvidence},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var att *Attestation
			if !tc.nilAtt {
				att = testAttestation(t)
				tc.mutate(t, att)
			}
			err := Validate(att)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("Validate: got err %v, want errors.Is(_, %v)", err, tc.wantErr)
			}
		})
	}
}

// TestValidate_EmptyEvidence asserts both nil and empty evidence
// slices are accepted — zero evidence is structurally valid.
func TestValidate_EmptyEvidence(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name string
		ev   []evidence.Evidence
	}{
		{"nil slice", nil},
		{"empty slice", []evidence.Evidence{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			att := testAttestation(t)
			att.Evidence = tc.ev
			if err := Validate(att); err != nil {
				t.Fatalf("Validate: got %v, want nil", err)
			}
			if _, err := CanonicalHash(att); err != nil {
				t.Fatalf("CanonicalHash: got %v, want nil", err)
			}
		})
	}
}

// TestValidate_SingleEvidence asserts a single-element evidence slice
// is trivially sorted and accepted.
func TestValidate_SingleEvidence(t *testing.T) {
	t.Parallel()

	att := testAttestation(t)
	att.Evidence = []evidence.Evidence{testEvidence("only")}
	if err := Validate(att); err != nil {
		t.Fatalf("Validate: got %v, want nil", err)
	}
}
