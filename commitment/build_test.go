package commitment

import (
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"testing"

	"github.com/bperin/trust/merkle"
)

// stubObject is a TrustObject that returns a fixed leaf hash, letting
// build tests control leaf values without real trust objects.
type stubObject struct {
	leaf [32]byte
}

func (s stubObject) LeafHash() ([32]byte, error) { return s.leaf, nil }

// numberedLeaf returns a distinct deterministic leaf for index i.
func numberedLeaf(i uint64) [32]byte {
	var h [32]byte
	binary.BigEndian.PutUint64(h[:8], i)
	return h
}

// stubObjects returns n TrustObjects with distinct deterministic leaves.
func stubObjects(n int) []TrustObject {
	objs := make([]TrustObject, n)
	for i := range objs {
		objs[i] = stubObject{leaf: numberedLeaf(uint64(i) + 1)}
	}
	return objs
}

// mustBuild builds a commitment or fails the test.
func mustBuild(t *testing.T, objects []TrustObject) *Commitment {
	t.Helper()
	c, err := Build(objects)
	if err != nil {
		t.Fatalf("Build() err = %v, want nil", err)
	}
	return c
}

func TestBuild_SingleObjectRoot(t *testing.T) {
	leaf := numberedLeaf(1)
	c := mustBuild(t, []TrustObject{stubObject{leaf: leaf}})

	tree, err := merkle.New([][]byte{leaf[:]})
	if err != nil {
		t.Fatalf("merkle.New() err = %v, want nil", err)
	}
	if subtle.ConstantTimeCompare(c.Root[:], tree.Root()) != 1 {
		t.Errorf("Root = %x, want %x", c.Root, tree.Root())
	}
	if c.Algorithm != AlgorithmRFC6962SHA256 {
		t.Errorf("Algorithm = %q, want %q", c.Algorithm, AlgorithmRFC6962SHA256)
	}
}

func TestBuild_DeterministicOrder(t *testing.T) {
	ordered := stubObjects(5)
	shuffled := []TrustObject{ordered[3], ordered[0], ordered[4], ordered[1], ordered[2]}

	a := mustBuild(t, ordered)
	b := mustBuild(t, shuffled)

	if subtle.ConstantTimeCompare(a.Root[:], b.Root[:]) != 1 {
		t.Errorf("Root differs for shuffled input: %x != %x", a.Root, b.Root)
	}
	if len(a.LeafHashes) != len(b.LeafHashes) {
		t.Fatalf("len(LeafHashes) = %d, want %d", len(a.LeafHashes), len(b.LeafHashes))
	}
	for i := range a.LeafHashes {
		if subtle.ConstantTimeCompare(a.LeafHashes[i][:], b.LeafHashes[i][:]) != 1 {
			t.Errorf("LeafHashes[%d] = %x, want %x", i, a.LeafHashes[i], b.LeafHashes[i])
		}
	}
}

func TestBuild_SizeEqualsLenObjects(t *testing.T) {
	cases := []struct {
		name string
		n    int
	}{
		{"one", 1},
		{"three", 3},
		{"seven", 7},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			objects := stubObjects(tc.n)
			c := mustBuild(t, objects)
			if c.Size != len(objects) {
				t.Errorf("Size = %d, want %d", c.Size, len(objects))
			}
			if len(c.LeafHashes) != len(objects) {
				t.Errorf("len(LeafHashes) = %d, want %d", len(c.LeafHashes), len(objects))
			}
		})
	}
}

func TestBuild_Empty(t *testing.T) {
	cases := []struct {
		name    string
		objects []TrustObject
	}{
		{"nil slice", nil},
		{"empty slice", []TrustObject{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Build(tc.objects)
			if !errors.Is(err, ErrEmptyObjects) {
				t.Errorf("Build() err = %v, want ErrEmptyObjects", err)
			}
		})
	}
}

func TestBuild_NilElement(t *testing.T) {
	objects := stubObjects(3)
	objects[1] = nil
	_, err := Build(objects)
	if !errors.Is(err, ErrNilObject) {
		t.Errorf("Build() err = %v, want ErrNilObject", err)
	}
}

func TestBuild_DuplicateObject(t *testing.T) {
	leaf := numberedLeaf(9)
	objects := []TrustObject{
		stubObject{leaf: leaf},
		stubObject{leaf: numberedLeaf(3)},
		stubObject{leaf: leaf},
	}
	_, err := Build(objects)
	if !errors.Is(err, ErrDuplicateObject) {
		t.Errorf("Build() err = %v, want ErrDuplicateObject", err)
	}
}

func TestBuild_SingleLeaf(t *testing.T) {
	c := mustBuild(t, stubObjects(1))
	if c.Size != 1 {
		t.Errorf("Size = %d, want 1", c.Size)
	}
	if err := VerifyCommitment(c); err != nil {
		t.Errorf("VerifyCommitment() err = %v, want nil", err)
	}
}

func TestBuild_TwoLeaves(t *testing.T) {
	c := mustBuild(t, stubObjects(2))
	if c.Size != 2 {
		t.Errorf("Size = %d, want 2", c.Size)
	}
	if err := VerifyCommitment(c); err != nil {
		t.Errorf("VerifyCommitment() err = %v, want nil", err)
	}
}

func TestBuild_LargeN(t *testing.T) {
	c := mustBuild(t, stubObjects(1027))
	if c.Size != 1027 {
		t.Errorf("Size = %d, want 1027", c.Size)
	}
	if err := VerifyCommitment(c); err != nil {
		t.Errorf("VerifyCommitment() err = %v, want nil", err)
	}
}

func TestVerifyCommitment_Valid(t *testing.T) {
	for _, n := range []int{1, 2, 3, 16, 17} {
		c := mustBuild(t, stubObjects(n))
		if err := VerifyCommitment(c); err != nil {
			t.Errorf("VerifyCommitment(size %d) err = %v, want nil", n, err)
		}
	}
}

func TestVerifyCommitment_Nil(t *testing.T) {
	if err := VerifyCommitment(nil); !errors.Is(err, ErrNilCommitment) {
		t.Errorf("VerifyCommitment(nil) err = %v, want ErrNilCommitment", err)
	}
}

// TestVerifyCommitment_Negative mutates one field of an otherwise valid
// commitment per case and asserts the named sentinel.
func TestVerifyCommitment_Negative(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(c *Commitment)
		want   error
	}{
		{
			name:   "AlgorithmMismatch",
			mutate: func(c *Commitment) { c.Algorithm = "sha256-merkle-v2" },
			want:   ErrAlgorithmMismatch,
		},
		{
			name:   "Empty zero size",
			mutate: func(c *Commitment) { c.Size = 0 },
			want:   ErrEmptyCommitment,
		},
		{
			name:   "Empty nil leaves",
			mutate: func(c *Commitment) { c.LeafHashes = nil },
			want:   ErrEmptyCommitment,
		},
		{
			name:   "SizeMismatch smaller",
			mutate: func(c *Commitment) { c.Size-- },
			want:   ErrSizeMismatch,
		},
		{
			name:   "SizeMismatch larger",
			mutate: func(c *Commitment) { c.Size += 2 },
			want:   ErrSizeMismatch,
		},
		{
			name: "Unsorted",
			mutate: func(c *Commitment) {
				c.LeafHashes[0], c.LeafHashes[len(c.LeafHashes)-1] = c.LeafHashes[len(c.LeafHashes)-1], c.LeafHashes[0]
			},
			want: ErrUnsortedLeaves,
		},
		{
			name:   "DuplicateLeaf",
			mutate: func(c *Commitment) { c.LeafHashes[1] = c.LeafHashes[0] },
			want:   ErrDuplicateLeaf,
		},
		{
			name:   "RootMismatch",
			mutate: func(c *Commitment) { c.Root[0] ^= 0xFF },
			want:   ErrRootMismatch,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := mustBuild(t, stubObjects(4))
			tc.mutate(c)
			err := VerifyCommitment(c)
			if !errors.Is(err, tc.want) {
				t.Errorf("VerifyCommitment() err = %v, want %v", err, tc.want)
			}
		})
	}
}

// TestVerifyCommitment_UnsortedTwoLeaves proves the ordering check fires
// on the minimum multi-leaf shape.
func TestVerifyCommitment_UnsortedTwoLeaves(t *testing.T) {
	c := mustBuild(t, stubObjects(2))
	c.LeafHashes[0], c.LeafHashes[1] = c.LeafHashes[1], c.LeafHashes[0]
	if err := VerifyCommitment(c); !errors.Is(err, ErrUnsortedLeaves) {
		t.Errorf("VerifyCommitment() err = %v, want ErrUnsortedLeaves", err)
	}
}
