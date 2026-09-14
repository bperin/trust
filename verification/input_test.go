package verification

import (
	"crypto/ed25519"
	"testing"
	"time"

	"github.com/bperin/trust/attestation"
	"github.com/bperin/trust/authority"
	"github.com/bperin/trust/identity/did"
)

type fakeResolver struct{}

func (fakeResolver) Resolve(did.DID) (*did.Document, error) { return &did.Document{}, nil }

func TestInputsOptionalFields(t *testing.T) {
	t.Parallel()

	key := ed25519.PublicKey(make([]byte, ed25519.PublicKeySize))
	in := Inputs{
		Attestation: &attestation.Attestation{},
		SigningKey:  key,
		Chain: []AuthorityHop{
			{Authority: &authority.Authority{}, PublicKey: key},
		},
	}

	if in.Attestation == nil {
		t.Fatal("Attestation: got nil, want set")
	}
	if in.SigningKey == nil {
		t.Fatal("SigningKey: got nil, want set")
	}
	if len(in.Chain) != 1 {
		t.Fatalf("Chain: got len %d, want 1", len(in.Chain))
	}
	if in.IdentityResolver != nil {
		t.Fatalf("IdentityResolver: got %v, want nil (optional)", in.IdentityResolver)
	}
	if in.Evidence != nil {
		t.Fatalf("Evidence: got %v, want nil (optional)", in.Evidence)
	}
	if in.Commitments != nil {
		t.Fatalf("Commitments: got %v, want nil (optional)", in.Commitments)
	}
	if !in.Now.IsZero() {
		t.Fatalf("Now: got %v, want zero (resolved by engine)", in.Now)
	}
}

func TestInputsZeroValue(t *testing.T) {
	t.Parallel()

	var in Inputs
	if in.Attestation != nil {
		t.Fatalf("Attestation: got %v, want nil", in.Attestation)
	}
	if in.SigningKey != nil {
		t.Fatalf("SigningKey: got %v, want nil", in.SigningKey)
	}
	if in.Chain != nil {
		t.Fatalf("Chain: got %v, want nil", in.Chain)
	}
	if in.IdentityResolver != nil {
		t.Fatalf("IdentityResolver: got %v, want nil", in.IdentityResolver)
	}
	if in.Evidence != nil {
		t.Fatalf("Evidence: got %v, want nil", in.Evidence)
	}
	if in.Commitments != nil {
		t.Fatalf("Commitments: got %v, want nil", in.Commitments)
	}
	if !in.Now.IsZero() {
		t.Fatalf("Now: got %v, want zero", in.Now)
	}
}

func TestAuthorityHopShape(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		hop  AuthorityHop
	}{
		{"zero value", AuthorityHop{}},
		{"authority only", AuthorityHop{Authority: &authority.Authority{}}},
		{"key only", AuthorityHop{PublicKey: ed25519.PublicKey{}}},
		{"both", AuthorityHop{Authority: &authority.Authority{}, PublicKey: ed25519.PublicKey{}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			chain := []AuthorityHop{tt.hop}
			in := Inputs{Chain: chain}
			if len(in.Chain) != 1 {
				t.Fatalf("Chain: got len %d, want 1", len(in.Chain))
			}
			if got := in.Chain[0].Authority; got != tt.hop.Authority {
				t.Fatalf("Authority: got %v, want %v", got, tt.hop.Authority)
			}
		})
	}
}

func TestInputsOptionalFieldsSettable(t *testing.T) {
	t.Parallel()

	in := Inputs{
		IdentityResolver: fakeResolver{},
		Evidence:         map[string][]byte{"deadbeef": {0x01}},
		Commitments:      []CommitmentProof{},
		Now:              time.Unix(1, 0).UTC(),
	}
	if in.IdentityResolver == nil {
		t.Fatal("IdentityResolver: got nil, want set")
	}
	if len(in.Evidence) != 1 {
		t.Fatalf("Evidence: got len %d, want 1", len(in.Evidence))
	}
	if in.Commitments == nil {
		t.Fatal("Commitments: got nil, want set")
	}
	if in.Now.IsZero() {
		t.Fatal("Now: got zero, want set")
	}
}
