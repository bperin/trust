package verification

import (
	"errors"
	"testing"
)

func TestVerifyProvenance_RoundTrip(t *testing.T) {
	t.Parallel()
	f := buildFixture(t)
	in := f.inputs()
	prov, err := BuildProvenance(in)
	if err != nil {
		t.Fatalf("BuildProvenance: %v", err)
	}
	if err := VerifyProvenance(prov, in); err != nil {
		t.Errorf("VerifyProvenance round trip: %v", err)
	}
}

func TestVerifyProvenance_NoResolverConsistent(t *testing.T) {
	t.Parallel()
	f := buildFixture(t)
	in := f.inputs()
	in.IdentityResolver = nil
	prov, err := BuildProvenance(in)
	if err != nil {
		t.Fatalf("BuildProvenance: %v", err)
	}
	if err := VerifyProvenance(prov, in); err != nil {
		t.Errorf("nil-resolver trace must verify against nil-resolver input: %v", err)
	}
	if err := VerifyProvenance(prov, f.inputs()); !errors.Is(err, ErrProvenanceMismatch) {
		t.Errorf("resolver mismatch: err = %v, want ErrProvenanceMismatch", err)
	}
}

func TestVerifyProvenance_Nil(t *testing.T) {
	t.Parallel()
	f := buildFixture(t)
	if err := VerifyProvenance(nil, f.inputs()); !errors.Is(err, ErrNilProvenance) {
		t.Errorf("err = %v, want ErrNilProvenance", err)
	}
}

func TestVerifyProvenance_MutatedRef(t *testing.T) {
	t.Parallel()
	f := buildFixture(t)
	in := f.inputs()
	prov, _ := BuildProvenance(in)
	prov.Links[0].Ref = "0000000000000000000000000000000000000000000000000000000000000000"
	err := VerifyProvenance(prov, in)
	if !errors.Is(err, ErrProvenanceMismatch) {
		t.Errorf("err = %v, want ErrProvenanceMismatch", err)
	}
}

func TestVerifyProvenance_MutatedSubject(t *testing.T) {
	t.Parallel()
	f := buildFixture(t)
	in := f.inputs()
	prov, _ := BuildProvenance(in)
	prov.Links[0].Subject = "did:trust:impostor"
	if err := VerifyProvenance(prov, in); !errors.Is(err, ErrProvenanceMismatch) {
		t.Errorf("err = %v, want ErrProvenanceMismatch", err)
	}
}

func TestVerifyProvenance_Reordered(t *testing.T) {
	t.Parallel()
	f := buildFixture(t)
	in := f.inputs()
	prov, _ := BuildProvenance(in)
	prov.Links[0], prov.Links[1] = prov.Links[1], prov.Links[0]
	if err := VerifyProvenance(prov, in); !errors.Is(err, ErrProvenanceMismatch) {
		t.Errorf("err = %v, want ErrProvenanceMismatch", err)
	}
}

func TestVerifyProvenance_MissingLink(t *testing.T) {
	t.Parallel()
	f := buildFixture(t)
	in := f.inputs()
	prov, _ := BuildProvenance(in)
	prov.Links = prov.Links[1:]
	if err := VerifyProvenance(prov, in); !errors.Is(err, ErrProvenanceMismatch) {
		t.Errorf("err = %v, want ErrProvenanceMismatch", err)
	}
}

func TestVerifyProvenance_ExtraLink(t *testing.T) {
	t.Parallel()
	f := buildFixture(t)
	in := f.inputs()
	prov, _ := BuildProvenance(in)
	prov.Links = append(prov.Links, Link{Kind: NodeIdentity, Ref: "extra"})
	if err := VerifyProvenance(prov, in); !errors.Is(err, ErrProvenanceMismatch) {
		t.Errorf("err = %v, want ErrProvenanceMismatch", err)
	}
}

func TestVerifyProvenance_MutatedParent(t *testing.T) {
	t.Parallel()
	f := buildFixture(t)
	in := f.inputs()
	prov, _ := BuildProvenance(in)
	prov.Links[1].Parent = "ffffffff"
	if err := VerifyProvenance(prov, in); !errors.Is(err, ErrProvenanceMismatch) {
		t.Errorf("err = %v, want ErrProvenanceMismatch", err)
	}
}
