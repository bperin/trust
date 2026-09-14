package verification

import (
	"encoding/hex"
	"errors"
	"fmt"
	"testing"

	"github.com/bperin/trust/attestation"
	"github.com/bperin/trust/authority"
	"github.com/bperin/trust/claim"
	"github.com/bperin/trust/identity/did"
)

// testResolver is a static did.Resolver fixture: it resolves every DID
// to the same document.
type testResolver struct{}

func (testResolver) Resolve(did.DID) (*did.Document, error) {
	return &did.Document{ID: "did:test:root"}, nil
}

// testInputs builds a deterministic fixture: an attestation hanging
// from a hops-deep authority chain ordered leaf→root, with each
// authority's Parent set to the next hop's canonical-hash hex and the
// attestation's AuthorityRef set to the leaf hop's hash.
func testInputs(t *testing.T, hops int, resolver did.Resolver) Inputs {
	t.Helper()
	if hops < 1 {
		t.Fatalf("hops = %d, want >= 1", hops)
	}
	chain := make([]AuthorityHop, hops)
	refs := make([]string, hops)
	for i := hops - 1; i >= 0; i-- {
		a := &authority.Authority{
			Subject: fmt.Sprintf("did:test:authority-%d", i),
			Status:  authority.StatusActive,
		}
		if i+1 < hops {
			parent := refs[i+1]
			a.Parent = &parent
		}
		h, err := authority.CanonicalHash(a)
		if err != nil {
			t.Fatalf("authority.CanonicalHash hop %d: %v", i, err)
		}
		refs[i] = hex.EncodeToString(h[:])
		chain[i] = AuthorityHop{Authority: a}
	}
	return Inputs{
		Attestation: &attestation.Attestation{
			Issuer:       "did:test:issuer",
			SigningKeyID: "did:test:issuer#key-1",
			AuthorityRef: refs[0],
			Claim: claim.Claim{
				Issuer:  "did:test:issuer",
				Subject: "did:test:subject",
				Type:    claim.ClaimType{Namespace: "test", Name: "role"},
				Value:   "admin",
			},
		},
		Chain:            chain,
		IdentityResolver: resolver,
	}
}

// linkKinds projects a provenance to its ordered link kinds.
func linkKinds(p *Provenance) []NodeKind {
	kinds := make([]NodeKind, len(p.Links))
	for i, l := range p.Links {
		kinds[i] = l.Kind
	}
	return kinds
}

// countKind returns how many links carry the given kind.
func countKind(p *Provenance, kind NodeKind) int {
	n := 0
	for _, l := range p.Links {
		if l.Kind == kind {
			n++
		}
	}
	return n
}

func TestBuildProvenance_Order(t *testing.T) {
	tests := []struct {
		name  string
		hops  int
		kinds []NodeKind
	}{
		{
			name: "two-hop chain",
			hops: 2,
			kinds: []NodeKind{
				NodeAttestation, NodeClaim, NodeSigningKey,
				NodeAuthority, NodeAuthority,
				NodeDelegation,
				NodeRootAuthority, NodeIdentity,
			},
		},
		{
			name: "three-hop chain",
			hops: 3,
			kinds: []NodeKind{
				NodeAttestation, NodeClaim, NodeSigningKey,
				NodeAuthority, NodeAuthority, NodeAuthority,
				NodeDelegation, NodeDelegation,
				NodeRootAuthority, NodeIdentity,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			prov, err := BuildProvenance(testInputs(t, tt.hops, testResolver{}))
			if err != nil {
				t.Fatalf("BuildProvenance: %v", err)
			}
			got := linkKinds(prov)
			if len(got) != len(tt.kinds) {
				t.Fatalf("link count = %d, want %d (kinds %v)", len(got), len(tt.kinds), got)
			}
			for i := range got {
				if got[i] != tt.kinds[i] {
					t.Errorf("link %d kind = %d, want %d", i, got[i], tt.kinds[i])
				}
			}
		})
	}
}

func TestBuildProvenance_Refs(t *testing.T) {
	in := testInputs(t, 3, testResolver{})
	prov, err := BuildProvenance(in)
	if err != nil {
		t.Fatalf("BuildProvenance: %v", err)
	}
	links := prov.Links

	attHash, err := attestation.CanonicalHash(in.Attestation)
	if err != nil {
		t.Fatalf("attestation.CanonicalHash: %v", err)
	}
	attRef := hex.EncodeToString(attHash[:])
	claimHash, err := claim.CanonicalHash(&in.Attestation.Claim)
	if err != nil {
		t.Fatalf("claim.CanonicalHash: %v", err)
	}
	claimRef := hex.EncodeToString(claimHash[:])

	hopRefs := make([]string, len(in.Chain))
	for i, hop := range in.Chain {
		h, err := authority.CanonicalHash(hop.Authority)
		if err != nil {
			t.Fatalf("authority.CanonicalHash hop %d: %v", i, err)
		}
		hopRefs[i] = hex.EncodeToString(h[:])
	}

	tests := []struct {
		name    string
		link    Link
		ref     string
		subject string
		keyID   string
		parent  string
	}{
		{"attestation", links[0], attRef, "did:test:issuer", "", ""},
		{"claim", links[1], claimRef, "", "", attRef},
		{"signing key", links[2], "", "", "did:test:issuer#key-1", attRef},
		{"authority leaf", links[3], hopRefs[0], "did:test:authority-0", "", hopRefs[1]},
		{"authority mid", links[4], hopRefs[1], "did:test:authority-1", "", hopRefs[2]},
		{"authority root", links[5], hopRefs[2], "did:test:authority-2", "", ""},
		{"delegation 0->1", links[6], hopRefs[0], "", "", hopRefs[1]},
		{"delegation 1->2", links[7], hopRefs[1], "", "", hopRefs[2]},
		{"root authority", links[8], hopRefs[2], "", "", ""},
		{"identity", links[9], "did:test:authority-2", "did:test:authority-2", "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.link.Ref != tt.ref {
				t.Errorf("ref = %q, want %q", tt.link.Ref, tt.ref)
			}
			if tt.link.Subject != tt.subject {
				t.Errorf("subject = %q, want %q", tt.link.Subject, tt.subject)
			}
			if tt.link.KeyID != tt.keyID {
				t.Errorf("keyID = %q, want %q", tt.link.KeyID, tt.keyID)
			}
			if tt.link.Parent != tt.parent {
				t.Errorf("parent = %q, want %q", tt.link.Parent, tt.parent)
			}
		})
	}

	if links[3].Ref != in.Attestation.AuthorityRef {
		t.Errorf("Chain[0] authority ref = %q, want Attestation.AuthorityRef %q",
			links[3].Ref, in.Attestation.AuthorityRef)
	}
}

func TestBuildProvenance_NoResolver(t *testing.T) {
	prov, err := BuildProvenance(testInputs(t, 3, nil))
	if err != nil {
		t.Fatalf("BuildProvenance: %v", err)
	}
	if got := countKind(prov, NodeIdentity); got != 0 {
		t.Errorf("NodeIdentity links = %d, want 0", got)
	}
	if got, want := len(prov.Links), 3+2*3; got != want {
		t.Errorf("link count = %d, want %d", got, want)
	}
}

func TestBuildProvenance_LinkCount(t *testing.T) {
	tests := []struct {
		name     string
		hops     int
		resolver did.Resolver
		want     int
	}{
		{"single hop, no resolver", 1, nil, 3 + 2*1},
		{"single hop, resolver", 1, testResolver{}, 3 + 2*1 + 1},
		{"two hops, no resolver", 2, nil, 3 + 2*2},
		{"seven hops, no resolver", 7, nil, 3 + 2*7},
		{"seven hops, resolver", 7, testResolver{}, 3 + 2*7 + 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			prov, err := BuildProvenance(testInputs(t, tt.hops, tt.resolver))
			if err != nil {
				t.Fatalf("BuildProvenance: %v", err)
			}
			if got := len(prov.Links); got != tt.want {
				t.Errorf("link count = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestBuildProvenance_SingleHop(t *testing.T) {
	prov, err := BuildProvenance(testInputs(t, 1, testResolver{}))
	if err != nil {
		t.Fatalf("BuildProvenance: %v", err)
	}
	want := []NodeKind{
		NodeAttestation, NodeClaim, NodeSigningKey,
		NodeAuthority,
		NodeRootAuthority, NodeIdentity,
	}
	got := linkKinds(prov)
	if len(got) != len(want) {
		t.Fatalf("link count = %d, want %d (kinds %v)", len(got), len(want), got)
	}
	for i := range got {
		if got[i] != want[i] {
			t.Errorf("link %d kind = %d, want %d", i, got[i], want[i])
		}
	}
	if got := countKind(prov, NodeDelegation); got != 0 {
		t.Errorf("NodeDelegation links = %d, want 0", got)
	}
	if prov.Links[3].Parent != "" {
		t.Errorf("root authority link parent = %q, want empty", prov.Links[3].Parent)
	}
}

func TestBuildProvenance_EmptyRootSubject(t *testing.T) {
	in := testInputs(t, 2, testResolver{})
	in.Chain[len(in.Chain)-1].Authority.Subject = ""
	prov, err := BuildProvenance(in)
	if err != nil {
		t.Fatalf("BuildProvenance: %v", err)
	}
	last := prov.Links[len(prov.Links)-1]
	if last.Kind != NodeIdentity {
		t.Fatalf("last link kind = %d, want NodeIdentity", last.Kind)
	}
	if last.Ref != "" || last.Subject != "" {
		t.Errorf("identity link ref/subject = %q/%q, want empty", last.Ref, last.Subject)
	}
}

func TestBuildProvenance_Determinism(t *testing.T) {
	in := testInputs(t, 3, testResolver{})
	a, err := BuildProvenance(in)
	if err != nil {
		t.Fatalf("BuildProvenance: %v", err)
	}
	b, err := BuildProvenance(in)
	if err != nil {
		t.Fatalf("BuildProvenance: %v", err)
	}
	ba, err := MarshalProvenance(a)
	if err != nil {
		t.Fatalf("MarshalProvenance: %v", err)
	}
	bb, err := MarshalProvenance(b)
	if err != nil {
		t.Fatalf("MarshalProvenance: %v", err)
	}
	if string(ba) != string(bb) {
		t.Errorf("canonical bytes differ:\n%s\n%s", ba, bb)
	}
}

func TestBuildProvenance_NilAttestation(t *testing.T) {
	in := testInputs(t, 2, nil)
	in.Attestation = nil
	_, err := BuildProvenance(in)
	if !errors.Is(err, ErrNilAttestation) {
		t.Errorf("err = %v, want ErrNilAttestation", err)
	}
}

func TestBuildProvenance_EmptyChain(t *testing.T) {
	in := testInputs(t, 2, nil)
	in.Chain = nil
	_, err := BuildProvenance(in)
	if !errors.Is(err, ErrEmptyChain) {
		t.Errorf("err = %v, want ErrEmptyChain", err)
	}
}
