package verification

import (
	"errors"
	"fmt"
	"testing"
)

// cloneProvenance returns a deep-enough copy: a fresh Links slice whose
// elements are value copies, so mutations never alias the original.
func cloneProvenance(p *Provenance) *Provenance {
	links := make([]Link, len(p.Links))
	copy(links, p.Links)
	return &Provenance{Links: links}
}

func TestVerifyProvenance_RoundTrip(t *testing.T) {
	for _, hops := range []int{1, 2, 3, 7} {
		t.Run(fmt.Sprintf("%d-hop", hops), func(t *testing.T) {
			in := testInputs(t, hops, testResolver{})
			prov, err := BuildProvenance(in)
			if err != nil {
				t.Fatalf("BuildProvenance: %v", err)
			}
			if err := VerifyProvenance(prov, in); err != nil {
				t.Errorf("VerifyProvenance = %v, want nil", err)
			}
		})
	}
}

func TestVerifyProvenance_NoResolverConsistent(t *testing.T) {
	in := testInputs(t, 2, nil)
	prov, err := BuildProvenance(in)
	if err != nil {
		t.Fatalf("BuildProvenance: %v", err)
	}
	if err := VerifyProvenance(prov, in); err != nil {
		t.Errorf("VerifyProvenance = %v, want nil", err)
	}
}

func TestVerifyProvenance_MutatedRef(t *testing.T) {
	in := testInputs(t, 3, testResolver{})
	base, err := BuildProvenance(in)
	if err != nil {
		t.Fatalf("BuildProvenance: %v", err)
	}
	for i := range base.Links {
		t.Run(fmt.Sprintf("link %d kind %d", i, base.Links[i].Kind), func(t *testing.T) {
			prov := cloneProvenance(base)
			prov.Links[i].Ref = "deadbeef"
			err := VerifyProvenance(prov, in)
			if !errors.Is(err, ErrProvenanceMismatch) {
				t.Errorf("VerifyProvenance = %v, want ErrProvenanceMismatch", err)
			}
		})
	}
}

func TestVerifyProvenance_MutatedFields(t *testing.T) {
	in := testInputs(t, 2, testResolver{})
	base, err := BuildProvenance(in)
	if err != nil {
		t.Fatalf("BuildProvenance: %v", err)
	}
	tests := []struct {
		name   string
		mutate func(l *Link)
	}{
		{"kind", func(l *Link) { l.Kind = NodeKind(99) }},
		{"ref", func(l *Link) { l.Ref = "deadbeef" }},
		{"subject", func(l *Link) { l.Subject = "did:test:other" }},
		{"keyID", func(l *Link) { l.KeyID = "other-key" }},
		{"parent", func(l *Link) { l.Parent = "deadbeef" }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			prov := cloneProvenance(base)
			tt.mutate(&prov.Links[3])
			err := VerifyProvenance(prov, in)
			if !errors.Is(err, ErrProvenanceMismatch) {
				t.Errorf("VerifyProvenance = %v, want ErrProvenanceMismatch", err)
			}
		})
	}
}

func TestVerifyProvenance_Reordered(t *testing.T) {
	in := testInputs(t, 3, testResolver{})
	base, err := BuildProvenance(in)
	if err != nil {
		t.Fatalf("BuildProvenance: %v", err)
	}
	tests := []struct {
		name string
		i, j int
	}{
		{"attestation and claim", 0, 1},
		{"two authority hops", 3, 4},
		{"two delegations", 6, 7},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			prov := cloneProvenance(base)
			prov.Links[tt.i], prov.Links[tt.j] = prov.Links[tt.j], prov.Links[tt.i]
			err := VerifyProvenance(prov, in)
			if !errors.Is(err, ErrProvenanceMismatch) {
				t.Errorf("VerifyProvenance = %v, want ErrProvenanceMismatch", err)
			}
		})
	}
}

func TestVerifyProvenance_MissingLink(t *testing.T) {
	in := testInputs(t, 2, testResolver{})
	base, err := BuildProvenance(in)
	if err != nil {
		t.Fatalf("BuildProvenance: %v", err)
	}
	tests := []struct {
		name string
		prov *Provenance
	}{
		{"drop link", &Provenance{Links: append([]Link{}, base.Links[:2]...)}},
		{"empty links", &Provenance{Links: nil}},
		{"extra link", &Provenance{Links: append(append([]Link{}, base.Links...), Link{Kind: NodeIdentity, Ref: "extra"})}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := VerifyProvenance(tt.prov, in)
			if !errors.Is(err, ErrProvenanceMismatch) {
				t.Errorf("VerifyProvenance = %v, want ErrProvenanceMismatch", err)
			}
		})
	}
}

func TestVerifyProvenance_Nil(t *testing.T) {
	in := testInputs(t, 2, nil)
	err := VerifyProvenance(nil, in)
	if !errors.Is(err, ErrNilProvenance) {
		t.Errorf("VerifyProvenance = %v, want ErrNilProvenance", err)
	}
}
