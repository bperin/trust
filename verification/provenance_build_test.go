package verification

import (
	"testing"
)

// wantKinds returns the expected link kinds for an n-hop chain with a
// resolver present.
func wantKinds(n int, withIdentity bool) []NodeKind {
	kinds := []NodeKind{NodeAttestation, NodeClaim, NodeSigningKey}
	for i := 0; i < n; i++ {
		kinds = append(kinds, NodeAuthority)
	}
	for i := 0; i < n-1; i++ {
		kinds = append(kinds, NodeDelegation)
	}
	kinds = append(kinds, NodeRootAuthority)
	if n > 0 {
		// identity link only with resolver; handled by callers
		_ = n
	}
	return kinds
}

func TestBuildProvenance_Order(t *testing.T) {
	t.Parallel()
	f := buildFixture(t)
	prov, err := BuildProvenance(f.inputs())
	if err != nil {
		t.Fatalf("BuildProvenance: %v", err)
	}
	want := []NodeKind{NodeAttestation, NodeClaim, NodeSigningKey,
		NodeAuthority, NodeAuthority, NodeAuthority,
		NodeDelegation, NodeDelegation,
		NodeRootAuthority, NodeIdentity}
	if len(prov.Links) != len(want) {
		t.Fatalf("got %d links, want %d", len(prov.Links), len(want))
	}
	for i, k := range want {
		if prov.Links[i].Kind != k {
			t.Errorf("link %d kind = %d, want %d", i, prov.Links[i].Kind, k)
		}
	}
}

func TestBuildProvenance_Refs(t *testing.T) {
	t.Parallel()
	f := buildFixture(t)
	prov, err := BuildProvenance(f.inputs())
	if err != nil {
		t.Fatalf("BuildProvenance: %v", err)
	}
	if prov.Links[0].Subject != f.att.Issuer {
		t.Errorf("attestation link subject = %q, want %q", prov.Links[0].Subject, f.att.Issuer)
	}
	if prov.Links[1].Parent != prov.Links[0].Ref {
		t.Error("claim link parent must be the attestation ref")
	}
	if prov.Links[2].KeyID != f.att.SigningKeyID {
		t.Errorf("signing key link keyID = %q, want %q", prov.Links[2].KeyID, f.att.SigningKeyID)
	}
	// Chain[0]'s authority ref must equal Attestation.AuthorityRef.
	if prov.Links[3].Ref != f.att.AuthorityRef {
		t.Errorf("leaf authority ref %q != AuthorityRef %q", prov.Links[3].Ref, f.att.AuthorityRef)
	}
	// Root authority link parent is empty; leaf authority parent is mid ref.
	if prov.Links[5].Parent != "" {
		t.Errorf("root authority parent = %q, want empty", prov.Links[5].Parent)
	}
	if prov.Links[3].Parent == "" {
		t.Error("leaf authority must reference its parent")
	}
}

func TestBuildProvenance_NoResolver(t *testing.T) {
	t.Parallel()
	f := buildFixture(t)
	in := f.inputs()
	in.IdentityResolver = nil
	prov, err := BuildProvenance(in)
	if err != nil {
		t.Fatalf("BuildProvenance: %v", err)
	}
	for _, l := range prov.Links {
		if l.Kind == NodeIdentity {
			t.Error("identity link emitted without resolver")
		}
	}
	if got, want := len(prov.Links), 3+2*len(in.Chain); got != want {
		t.Errorf("link count = %d, want %d", got, want)
	}
}

func TestBuildProvenance_NilAttestation(t *testing.T) {
	t.Parallel()
	f := buildFixture(t)
	in := f.inputs()
	in.Attestation = nil
	if _, err := BuildProvenance(in); err != ErrNilAttestation {
		t.Errorf("err = %v, want ErrNilAttestation", err)
	}
}

func TestBuildProvenance_EmptyChain(t *testing.T) {
	t.Parallel()
	f := buildFixture(t)
	in := f.inputs()
	in.Chain = nil
	if _, err := BuildProvenance(in); err != ErrEmptyChain {
		t.Errorf("err = %v, want ErrEmptyChain", err)
	}
}

func TestBuildProvenance_SingleHop(t *testing.T) {
	t.Parallel()
	f := buildFixture(t)
	in := f.inputs()
	in.Chain = in.Chain[len(in.Chain)-1:]
	prov, err := BuildProvenance(in)
	if err != nil {
		t.Fatalf("BuildProvenance: %v", err)
	}
	// 3 fixed + 1 authority + 0 delegation + 1 root + 1 identity.
	if len(prov.Links) != 6 {
		t.Errorf("link count = %d, want 6", len(prov.Links))
	}
	delegations := 0
	for _, l := range prov.Links {
		if l.Kind == NodeDelegation {
			delegations++
		}
	}
	if delegations != 0 {
		t.Errorf("single-hop chain has %d delegation links, want 0", delegations)
	}
}

func TestBuildProvenance_LinkCountScales(t *testing.T) {
	t.Parallel()
	f := buildFixture(t)
	in := f.inputs()
	prov, err := BuildProvenance(in)
	if err != nil {
		t.Fatalf("BuildProvenance: %v", err)
	}
	want := 3 + 2*len(in.Chain) + 1 // + identity
	if len(prov.Links) != want {
		t.Errorf("link count = %d, want %d", len(prov.Links), want)
	}
}

func TestBuildProvenance_Deterministic(t *testing.T) {
	t.Parallel()
	f := buildFixture(t)
	in := f.inputs()
	p1, err := BuildProvenance(in)
	if err != nil {
		t.Fatalf("first build: %v", err)
	}
	p2, err := BuildProvenance(in)
	if err != nil {
		t.Fatalf("second build: %v", err)
	}
	h1, _ := CanonicalHash(p1)
	h2, _ := CanonicalHash(p2)
	if hashRefHex(h1) != hashRefHex(h2) {
		t.Error("provenance build not deterministic")
	}
}

func TestBuildProvenance_DelegationRefs(t *testing.T) {
	t.Parallel()
	f := buildFixture(t)
	in := f.inputs()
	prov, err := BuildProvenance(in)
	if err != nil {
		t.Fatalf("BuildProvenance: %v", err)
	}
	// Delegation links bind child ref to parent ref.
	delegations := 0
	for _, l := range prov.Links {
		if l.Kind != NodeDelegation {
			continue
		}
		if l.Ref == "" || l.Parent == "" || l.Ref == l.Parent {
			t.Errorf("delegation link %d has refs %q -> %q", delegations, l.Ref, l.Parent)
		}
		delegations++
	}
	if delegations != len(in.Chain)-1 {
		t.Errorf("delegation links = %d, want %d", delegations, len(in.Chain)-1)
	}
}
