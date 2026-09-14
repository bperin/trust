package commitment

import (
	"bytes"
	"crypto/subtle"
	"errors"
	"testing"
)

// fixedCommitment returns a deterministic 3-leaf commitment for
// serialization tests. The leaves are byte-filled digests already in
// ascending order; the root is fixed but need not verify.
func fixedCommitment() *Commitment {
	var root, l1, l2, l3 [32]byte
	for i := range root {
		root[i] = 0xaa
		l1[i] = 0x01
		l2[i] = 0x02
		l3[i] = 0x03
	}
	return &Commitment{
		Root:       root,
		Size:       3,
		LeafHashes: [][32]byte{l1, l2, l3},
		Algorithm:  AlgorithmRFC6962SHA256,
	}
}

// TestSerialize_GoldenJCS pins the exact [RFC 8785] JCS bytes of a fixed
// commitment: keys sorted (algorithm < leafHashes < root < size), no
// whitespace, digests as lowercase hex.
func TestSerialize_GoldenJCS(t *testing.T) {
	want := `{"algorithm":"rfc6962-sha256","leafHashes":["0101010101010101010101010101010101010101010101010101010101010101","0202020202020202020202020202020202020202020202020202020202020202","0303030303030303030303030303030303030303030303030303030303030303"],"root":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","size":3}`
	got, err := Marshal(fixedCommitment())
	if err != nil {
		t.Fatalf("Marshal() err = %v, want nil", err)
	}
	if !bytes.Equal(got, []byte(want)) {
		t.Errorf("Marshal() = %s, want %s", got, want)
	}
}

func TestSerialize_RoundTrip(t *testing.T) {
	c := mustBuild(t, stubObjects(7))
	before, err := CanonicalHash(c)
	if err != nil {
		t.Fatalf("CanonicalHash() err = %v, want nil", err)
	}
	b, err := Marshal(c)
	if err != nil {
		t.Fatalf("Marshal() err = %v, want nil", err)
	}
	back, err := Unmarshal(b)
	if err != nil {
		t.Fatalf("Unmarshal() err = %v, want nil", err)
	}
	after, err := CanonicalHash(back)
	if err != nil {
		t.Fatalf("CanonicalHash() err = %v, want nil", err)
	}
	if subtle.ConstantTimeCompare(before[:], after[:]) != 1 {
		t.Errorf("CanonicalHash round-trip = %x, want %x", after, before)
	}
	if back.Size != c.Size {
		t.Errorf("Size = %d, want %d", back.Size, c.Size)
	}
	if back.Algorithm != c.Algorithm {
		t.Errorf("Algorithm = %q, want %q", back.Algorithm, c.Algorithm)
	}
	if err := VerifyCommitment(back); err != nil {
		t.Errorf("VerifyCommitment(round-trip) err = %v, want nil", err)
	}
}

func TestMarshal_Deterministic(t *testing.T) {
	c := fixedCommitment()
	first, err := Marshal(c)
	if err != nil {
		t.Fatalf("Marshal() err = %v, want nil", err)
	}
	for i := 0; i < 8; i++ {
		got, err := Marshal(c)
		if err != nil {
			t.Fatalf("Marshal() call %d err = %v, want nil", i, err)
		}
		if !bytes.Equal(got, first) {
			t.Fatalf("Marshal() call %d = %s, want %s", i, got, first)
		}
	}
}

func TestSerialize_EmptyLeafHashes(t *testing.T) {
	c := &Commitment{
		Root:       [32]byte{0xaa},
		Size:       0,
		LeafHashes: nil,
		Algorithm:  AlgorithmRFC6962SHA256,
	}
	b, err := Marshal(c)
	if err != nil {
		t.Fatalf("Marshal() err = %v, want nil", err)
	}
	want := `"leafHashes":[]`
	if !bytes.Contains(b, []byte(want)) {
		t.Errorf("Marshal() = %s, want leafHashes rendered as %s", b, want)
	}
	back, err := Unmarshal(b)
	if err != nil {
		t.Fatalf("Unmarshal() err = %v, want nil", err)
	}
	h1, err := CanonicalHash(c)
	if err != nil {
		t.Fatalf("CanonicalHash() err = %v, want nil", err)
	}
	h2, err := CanonicalHash(back)
	if err != nil {
		t.Fatalf("CanonicalHash() err = %v, want nil", err)
	}
	if subtle.ConstantTimeCompare(h1[:], h2[:]) != 1 {
		t.Errorf("CanonicalHash round-trip = %x, want %x", h2, h1)
	}
}

func TestCanonicalHash_Stable(t *testing.T) {
	c := fixedCommitment()
	first, err := CanonicalHash(c)
	if err != nil {
		t.Fatalf("CanonicalHash() err = %v, want nil", err)
	}
	for i := 0; i < 4; i++ {
		got, err := CanonicalHash(c)
		if err != nil {
			t.Fatalf("CanonicalHash() call %d err = %v, want nil", i, err)
		}
		if subtle.ConstantTimeCompare(got[:], first[:]) != 1 {
			t.Fatalf("CanonicalHash() call %d = %x, want %x", i, got, first)
		}
	}
}

func TestCanonicalHash_Nil(t *testing.T) {
	_, err := CanonicalHash(nil)
	if !errors.Is(err, ErrNilCommitment) {
		t.Errorf("CanonicalHash(nil) err = %v, want ErrNilCommitment", err)
	}
}

func TestUnmarshal_TruncatedJSON(t *testing.T) {
	cases := []struct {
		name string
		in   string
	}{
		{"cut mid-object", `{"algorithm":"rfc6962-sha256","leafH`},
		{"empty", ``},
		{"open brace", `{`},
		{"not an object", `[1,2,3]`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Unmarshal([]byte(tc.in)); err == nil {
				t.Errorf("Unmarshal(%q) err = nil, want decode error", tc.in)
			}
		})
	}
}

func TestUnmarshal_InvalidHex(t *testing.T) {
	cases := []struct {
		name string
		in   string
	}{
		{
			"non-hex root",
			`{"algorithm":"rfc6962-sha256","leafHashes":[],"root":"zzzz","size":0}`,
		},
		{
			"odd-length root",
			`{"algorithm":"rfc6962-sha256","leafHashes":[],"root":"abc","size":0}`,
		},
		{
			"short root",
			`{"algorithm":"rfc6962-sha256","leafHashes":[],"root":"0102","size":0}`,
		},
		{
			"non-hex leaf",
			`{"algorithm":"rfc6962-sha256","leafHashes":["0x01"],"root":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","size":1}`,
		},
		{
			"short leaf",
			`{"algorithm":"rfc6962-sha256","leafHashes":["0102"],"root":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","size":1}`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Unmarshal([]byte(tc.in)); err == nil {
				t.Errorf("Unmarshal(%s) err = nil, want decode error", tc.in)
			}
		})
	}
}

// TestUnmarshal_SizeZeroDoc decodes a structurally valid document with
// size 0 and proves VerifyCommitment rejects it with ErrEmptyCommitment.
func TestUnmarshal_SizeZeroDoc(t *testing.T) {
	in := `{"algorithm":"rfc6962-sha256","leafHashes":[],"root":"0000000000000000000000000000000000000000000000000000000000000000","size":0}`
	c, err := Unmarshal([]byte(in))
	if err != nil {
		t.Fatalf("Unmarshal() err = %v, want nil", err)
	}
	if err := VerifyCommitment(c); !errors.Is(err, ErrEmptyCommitment) {
		t.Errorf("VerifyCommitment() err = %v, want ErrEmptyCommitment", err)
	}
}
