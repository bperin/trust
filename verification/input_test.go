package verification

import (
	"testing"
)

func TestInputsOptionalFields(t *testing.T) {
	t.Parallel()
	f := buildFixture(t)
	in := Inputs{
		Attestation: f.att,
		SigningKey:  f.attPub,
		Chain:       f.chain,
	}
	if in.IdentityResolver != nil {
		t.Error("IdentityResolver should default to nil")
	}
	if in.Evidence != nil {
		t.Error("Evidence should default to nil")
	}
	if in.Commitments != nil {
		t.Error("Commitments should default to nil")
	}
	if !in.Now.IsZero() {
		t.Error("Now should default to zero")
	}
	if in.Attestation == nil || in.SigningKey == nil || len(in.Chain) == 0 {
		t.Fatal("required fields not retained")
	}
}

func TestAuthorityHopShape(t *testing.T) {
	t.Parallel()
	f := buildFixture(t)
	for i, hop := range f.chain {
		if hop.Authority == nil {
			t.Errorf("hop %d Authority nil", i)
		}
		if hop.PublicKey == nil {
			t.Errorf("hop %d PublicKey nil", i)
		}
	}
	var zero AuthorityHop
	if zero.Authority != nil || zero.PublicKey != nil {
		t.Error("zero AuthorityHop not zero-valued")
	}
}

func TestInputsChainOrderLeafToRoot(t *testing.T) {
	t.Parallel()
	f := buildFixture(t)
	if f.chain[0].Authority.Subject != testLeafDID {
		t.Errorf("Chain[0] subject = %q, want leaf", f.chain[0].Authority.Subject)
	}
	if f.chain[len(f.chain)-1].Authority.Subject != testRootDID {
		t.Errorf("last Chain subject = %q, want root", f.chain[len(f.chain)-1].Authority.Subject)
	}
	if f.chain[len(f.chain)-1].Authority.Parent != nil {
		t.Error("root authority must have nil Parent")
	}
}
