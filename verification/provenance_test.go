package verification

import (
	"crypto/subtle"
	"errors"
	"testing"

	"github.com/bperin/trust/canonical"
	"github.com/bperin/trust/crypto/hash"
)

var _ canonical.EncodingDeclarer = (*Provenance)(nil)

func TestCanonicalHash_FIPS1804(t *testing.T) {
	t.Parallel()

	// Vector: [FIPS 180-4] SHA-256 of "abc".
	want := [32]byte{
		0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
		0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
		0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
		0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad,
	}
	if got := hash.NewSHA256().Sum([]byte("abc")); subtle.ConstantTimeCompare(got[:], want[:]) != 1 {
		t.Fatalf("SHA-256(\"abc\"): got %x, want %x", got, want)
	}

	// The digest path is SHA-256 over the JCS canonical bytes.
	p := &Provenance{Links: []Link{
		{Kind: NodeAttestation, Ref: "abc"},
	}}
	enc, err := MarshalProvenance(p)
	if err != nil {
		t.Fatalf("MarshalProvenance: %v", err)
	}
	digest, err := CanonicalHash(p)
	if err != nil {
		t.Fatalf("CanonicalHash: %v", err)
	}
	if want := hash.NewSHA256().Sum(enc); subtle.ConstantTimeCompare(digest[:], want[:]) != 1 {
		t.Fatalf("CanonicalHash: got %x, want SHA-256 of canonical bytes %x", digest, want)
	}
}

func TestProvenanceRoundTrip(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		p    *Provenance
	}{
		{
			name: "full chain",
			p: &Provenance{Links: []Link{
				{Kind: NodeAttestation, Ref: "aa", Subject: "did:ex:alice", KeyID: "k1", Parent: "bb"},
				{Kind: NodeAuthority, Ref: "bb", Subject: "did:ex:bob", KeyID: "k2", Parent: "cc"},
				{Kind: NodeIdentity, Ref: "did:ex:bob"},
			}},
		},
		{
			name: "single link",
			p:    &Provenance{Links: []Link{{Kind: NodeClaim, Ref: "deadbeef"}}},
		},
		{
			name: "empty fields link",
			p:    &Provenance{Links: []Link{{}}},
		},
		{
			name: "nil links",
			p:    &Provenance{},
		},
		{
			name: "empty links",
			p:    &Provenance{Links: []Link{}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			before, err := CanonicalHash(tt.p)
			if err != nil {
				t.Fatalf("CanonicalHash before marshal: %v", err)
			}
			enc, err := MarshalProvenance(tt.p)
			if err != nil {
				t.Fatalf("MarshalProvenance: %v", err)
			}
			back, err := UnmarshalProvenance(enc)
			if err != nil {
				t.Fatalf("UnmarshalProvenance: %v", err)
			}
			after, err := CanonicalHash(back)
			if err != nil {
				t.Fatalf("CanonicalHash after unmarshal: %v", err)
			}
			if subtle.ConstantTimeCompare(before[:], after[:]) != 1 {
				t.Fatalf("round-trip digest: got %x, want %x (input %+v)", after, before, tt.p)
			}
		})
	}
}

func TestProvenanceEmptyDigest(t *testing.T) {
	t.Parallel()

	first, err := CanonicalHash(&Provenance{})
	if err != nil {
		t.Fatalf("CanonicalHash: %v", err)
	}
	second, err := CanonicalHash(&Provenance{})
	if err != nil {
		t.Fatalf("CanonicalHash: %v", err)
	}
	if subtle.ConstantTimeCompare(first[:], second[:]) != 1 {
		t.Fatalf("repeat digest: got %x, want %x", second, first)
	}
}

func TestProvenanceEmptyVsNilLinks(t *testing.T) {
	t.Parallel()

	nilDigest, err := CanonicalHash(&Provenance{Links: nil})
	if err != nil {
		t.Fatalf("CanonicalHash nil links: %v", err)
	}
	emptyDigest, err := CanonicalHash(&Provenance{Links: []Link{}})
	if err != nil {
		t.Fatalf("CanonicalHash empty links: %v", err)
	}
	if subtle.ConstantTimeCompare(nilDigest[:], emptyDigest[:]) != 1 {
		t.Fatalf("nil vs empty links digest: got %x, want %x", emptyDigest, nilDigest)
	}
}

func TestNodeKindConstants(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		kind NodeKind
		want NodeKind
	}{
		{"NodeAttestation", NodeAttestation, 1},
		{"NodeClaim", NodeClaim, 2},
		{"NodeSigningKey", NodeSigningKey, 3},
		{"NodeAuthority", NodeAuthority, 4},
		{"NodeDelegation", NodeDelegation, 5},
		{"NodeRootAuthority", NodeRootAuthority, 6},
		{"NodeIdentity", NodeIdentity, 7},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if tt.kind != tt.want {
				t.Fatalf("%s: got %d, want %d", tt.name, tt.kind, tt.want)
			}
		})
	}
}

func TestCanonicalEncodingDeclarer(t *testing.T) {
	t.Parallel()

	var p Provenance
	if got := p.CanonicalEncoding(); got != canonical.EncodingJSON {
		t.Fatalf("CanonicalEncoding: got %d, want %d", got, canonical.EncodingJSON)
	}
}

func TestMarshalProvenanceGolden(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		p    *Provenance
		want string
	}{
		{
			name: "single link sorted keys",
			p: &Provenance{Links: []Link{
				{Kind: NodeAttestation, Ref: "aa", Subject: "s", KeyID: "k", Parent: "p"},
			}},
			want: `{"links":[{"keyId":"k","kind":1,"parent":"p","ref":"aa","subject":"s"}]}`,
		},
		{
			name: "empty links omitted",
			p:    &Provenance{Links: []Link{}},
			want: `{}`,
		},
		{
			name: "nil links omitted",
			p:    &Provenance{},
			want: `{}`,
		},
		{
			name: "empty field link",
			p:    &Provenance{Links: []Link{{}}},
			want: `{"links":[{"keyId":"","kind":0,"parent":"","ref":"","subject":""}]}`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := MarshalProvenance(tt.p)
			if err != nil {
				t.Fatalf("MarshalProvenance: %v", err)
			}
			if string(got) != tt.want {
				t.Fatalf("MarshalProvenance(%+v): got %s, want %s", tt.p, got, tt.want)
			}
		})
	}
}

func TestCanonicalHashNil(t *testing.T) {
	t.Parallel()

	got, err := CanonicalHash(nil)
	if !errors.Is(err, ErrNilProvenance) {
		t.Fatalf("CanonicalHash(nil): got err %v, want %v", err, ErrNilProvenance)
	}
	if got != [32]byte{} {
		t.Fatalf("CanonicalHash(nil): got digest %x, want zero", got)
	}
}

func TestMarshalProvenanceNil(t *testing.T) {
	t.Parallel()

	if _, err := MarshalProvenance(nil); !errors.Is(err, ErrNilProvenance) {
		t.Fatalf("MarshalProvenance(nil): got err %v, want %v", err, ErrNilProvenance)
	}
}

func TestUnmarshalProvenanceGarbage(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		in   []byte
	}{
		{"not json", []byte("{not json")},
		{"nil", nil},
		{"empty", []byte{}},
		{"scalar", []byte("42")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			p, err := UnmarshalProvenance(tt.in)
			if err == nil {
				t.Fatalf("UnmarshalProvenance(%q): got %+v, want error", tt.in, p)
			}
		})
	}
}

func TestUnmarshalProvenanceTruncated(t *testing.T) {
	t.Parallel()

	full, err := MarshalProvenance(&Provenance{Links: []Link{
		{Kind: NodeAuthority, Ref: "aa", Subject: "s", KeyID: "k", Parent: "p"},
	}})
	if err != nil {
		t.Fatalf("MarshalProvenance: %v", err)
	}
	truncated := full[:len(full)/2]
	if p, err := UnmarshalProvenance(truncated); err == nil {
		t.Fatalf("UnmarshalProvenance(%q): got %+v, want error", truncated, p)
	}
}

func TestProvenanceMutatedDigestDiffers(t *testing.T) {
	t.Parallel()

	original := &Provenance{Links: []Link{
		{Kind: NodeAuthority, Ref: "aa", Subject: "s", KeyID: "k", Parent: "p"},
	}}
	mutated := &Provenance{Links: []Link{
		{Kind: NodeAuthority, Ref: "ab", Subject: "s", KeyID: "k", Parent: "p"},
	}}
	before, err := CanonicalHash(original)
	if err != nil {
		t.Fatalf("CanonicalHash original: %v", err)
	}
	after, err := CanonicalHash(mutated)
	if err != nil {
		t.Fatalf("CanonicalHash mutated: %v", err)
	}
	if subtle.ConstantTimeCompare(before[:], after[:]) != 0 {
		t.Fatalf("mutated digest %x equals original %x, want different", after, before)
	}
}
