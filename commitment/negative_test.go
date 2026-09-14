package commitment

import (
	"errors"
	"testing"

	"github.com/bperin/trust/merkle"
)

// TestNegative_TamperedRoot proves inclusion verification fails when the
// claimed root does not commit to the proof.
func TestNegative_TamperedRoot(t *testing.T) {
	t.Parallel()

	objects := stubObjects(8)
	c := mustBuild(t, objects)
	p, err := InclusionProof(c, objects[0])
	if err != nil {
		t.Fatalf("InclusionProof() err = %v, want nil", err)
	}
	badRoot := c.Root
	badRoot[0] ^= 0xff
	err = VerifyInclusion(badRoot, p, objects[0])
	if !errors.Is(err, ErrInclusionFailed) {
		t.Errorf("VerifyInclusion(tampered root) err = %v, want ErrInclusionFailed", err)
	}
	if !errors.Is(err, merkle.ErrTamperedLeaf) {
		t.Errorf("VerifyInclusion(tampered root) err = %v, want errors.Is(_, merkle.ErrTamperedLeaf)", err)
	}
}

// TestNegative_TamperedStep proves inclusion verification fails when any
// sibling hash in the audit path is altered.
func TestNegative_TamperedStep(t *testing.T) {
	t.Parallel()

	objects := stubObjects(8)
	c := mustBuild(t, objects)
	byLeaf := objectsByLeaf(objects)
	obj := byLeaf[c.LeafHashes[5]]
	base, err := InclusionProof(c, obj)
	if err != nil {
		t.Fatalf("InclusionProof() err = %v, want nil", err)
	}
	for i := range base.Steps {
		p := base
		p.Steps = append([]merkle.ProofStep(nil), base.Steps...)
		p.Steps[i].Hash[0] ^= 0xff
		err := VerifyInclusion(c.Root, p, obj)
		if !errors.Is(err, ErrInclusionFailed) {
			t.Errorf("VerifyInclusion(step %d tampered) err = %v, want ErrInclusionFailed", i, err)
		}
		if !errors.Is(err, merkle.ErrTamperedLeaf) {
			t.Errorf("VerifyInclusion(step %d tampered) err = %v, want errors.Is(_, merkle.ErrTamperedLeaf)", i, err)
		}
	}
}

// TestNegative_WrongObject proves a proof for one committed object does not
// verify a different object.
func TestNegative_WrongObject(t *testing.T) {
	t.Parallel()

	objects := stubObjects(8)
	c := mustBuild(t, objects)
	byLeaf := objectsByLeaf(objects)
	obj := byLeaf[c.LeafHashes[5]]
	p, err := InclusionProof(c, obj)
	if err != nil {
		t.Fatalf("InclusionProof() err = %v, want nil", err)
	}

	wrong := byLeaf[c.LeafHashes[6]]
	err = VerifyInclusion(c.Root, p, wrong)
	if !errors.Is(err, ErrInclusionFailed) {
		t.Errorf("VerifyInclusion(committed wrong object) err = %v, want ErrInclusionFailed", err)
	}
	if !errors.Is(err, merkle.ErrTamperedLeaf) {
		t.Errorf("VerifyInclusion(committed wrong object) err = %v, want errors.Is(_, merkle.ErrTamperedLeaf)", err)
	}

	uncommitted := stubObject{leaf: numberedLeaf(1000)}
	err = VerifyInclusion(c.Root, p, uncommitted)
	if !errors.Is(err, ErrInclusionFailed) {
		t.Errorf("VerifyInclusion(uncommitted object) err = %v, want ErrInclusionFailed", err)
	}
	if !errors.Is(err, merkle.ErrTamperedLeaf) {
		t.Errorf("VerifyInclusion(uncommitted object) err = %v, want errors.Is(_, merkle.ErrTamperedLeaf)", err)
	}
}

// TestNegative_WrongIndex proves a proof does not verify under a different
// claimed leaf index or out-of-range index.
func TestNegative_WrongIndex(t *testing.T) {
	t.Parallel()

	objects := stubObjects(8)
	c := mustBuild(t, objects)
	byLeaf := objectsByLeaf(objects)
	obj := byLeaf[c.LeafHashes[5]]
	base, err := InclusionProof(c, obj)
	if err != nil {
		t.Fatalf("InclusionProof() err = %v, want nil", err)
	}

	cases := []struct {
		name   string
		index  int
		merkle error
	}{
		// Index 4 carries a different side-marker sequence than index 5 in
		// an 8-leaf tree, so the proof shape check rejects it.
		{"in-range wrong index", 4, merkle.ErrTamperedLeaf},
		{"index past tree size", 8, merkle.ErrIndexOutOfRange},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := base
			p.Index = tc.index
			err := VerifyInclusion(c.Root, p, obj)
			if !errors.Is(err, ErrInclusionFailed) {
				t.Errorf("VerifyInclusion(index %d) err = %v, want ErrInclusionFailed", tc.index, err)
			}
			if !errors.Is(err, tc.merkle) {
				t.Errorf("VerifyInclusion(index %d) err = %v, want errors.Is(_, %v)", tc.index, err, tc.merkle)
			}
		})
	}
}

// TestNegative_DuplicateLeaves proves duplicate objects are rejected at
// build and duplicate adjacent leaves are rejected at verify.
func TestNegative_DuplicateLeaves(t *testing.T) {
	t.Parallel()

	leaf := numberedLeaf(9)
	_, err := Build([]TrustObject{
		stubObject{leaf: leaf},
		stubObject{leaf: numberedLeaf(3)},
		stubObject{leaf: leaf},
	})
	if !errors.Is(err, ErrDuplicateObject) {
		t.Errorf("Build(duplicate objects) err = %v, want ErrDuplicateObject", err)
	}

	c := mustBuild(t, stubObjects(4))
	c.LeafHashes[1] = c.LeafHashes[0]
	if err := VerifyCommitment(c); !errors.Is(err, ErrDuplicateLeaf) {
		t.Errorf("VerifyCommitment(duplicate leaf) err = %v, want ErrDuplicateLeaf", err)
	}
}

// TestNegative_EmptySet proves an empty object slice is rejected at build
// and an empty commitment is rejected at verify.
func TestNegative_EmptySet(t *testing.T) {
	t.Parallel()

	for name, objects := range map[string][]TrustObject{"nil slice": nil, "empty slice": {}} {
		if _, err := Build(objects); !errors.Is(err, ErrEmptyObjects) {
			t.Errorf("Build(%s) err = %v, want ErrEmptyObjects", name, err)
		}
	}

	empty := &Commitment{Algorithm: AlgorithmRFC6962SHA256}
	if err := VerifyCommitment(empty); !errors.Is(err, ErrEmptyCommitment) {
		t.Errorf("VerifyCommitment(empty) err = %v, want ErrEmptyCommitment", err)
	}
}

// TestNegative_AllSentinelsReached exercises every sentinel in errors.go
// with at least one trigger and asserts errors.Is reaches it. The explicit
// allSentinels list fails if a new sentinel is added without a negative
// case here.
func TestNegative_AllSentinelsReached(t *testing.T) {
	t.Parallel()

	allSentinels := []error{
		ErrEmptyObjects,
		ErrNilObject,
		ErrDuplicateObject,
		ErrObjectNotCommitted,
		ErrNilCommitment,
		ErrAlgorithmMismatch,
		ErrEmptyCommitment,
		ErrSizeMismatch,
		ErrUnsortedLeaves,
		ErrDuplicateLeaf,
		ErrRootMismatch,
		ErrInclusionFailed,
		ErrNotPrefix,
		ErrInvalidRange,
	}

	c4 := mustBuild(t, stubObjects(4))
	byLeaf := objectsByLeaf(stubObjects(4))
	proofObj := byLeaf[c4.LeafHashes[0]]
	proof, err := InclusionProof(c4, proofObj)
	if err != nil {
		t.Fatalf("InclusionProof() err = %v, want nil", err)
	}

	// nonPrefix builds (old, next) where old.LeafHashes is not a prefix of
	// next.LeafHashes: tag 0x00 leaves sort before tag 0x80 leaves.
	nonPrefix := func(t *testing.T) (*Commitment, *Commitment) {
		t.Helper()
		old := mustBuild(t, taggedObjects(0x80, 3))
		next := mustBuild(t, append(taggedObjects(0x80, 3), taggedObjects(0x00, 2)...))
		return old, next
	}

	cases := []struct {
		name     string
		sentinel error
		trigger  func(t *testing.T) error
	}{
		{
			name:     "ErrEmptyObjects build nil",
			sentinel: ErrEmptyObjects,
			trigger:  func(t *testing.T) error { _, err := Build(nil); return err },
		},
		{
			name:     "ErrNilObject build nil element",
			sentinel: ErrNilObject,
			trigger: func(t *testing.T) error {
				_, err := Build([]TrustObject{stubObjects(2)[0], nil})
				return err
			},
		},
		{
			name:     "ErrNilObject leaf hash",
			sentinel: ErrNilObject,
			trigger:  func(t *testing.T) error { _, err := LeafHash(nil); return err },
		},
		{
			name:     "ErrNilObject verify inclusion",
			sentinel: ErrNilObject,
			trigger: func(t *testing.T) error {
				return VerifyInclusion(c4.Root, proof, nil)
			},
		},
		{
			name:     "ErrDuplicateObject build",
			sentinel: ErrDuplicateObject,
			trigger: func(t *testing.T) error {
				leaf := numberedLeaf(7)
				_, err := Build([]TrustObject{stubObject{leaf: leaf}, stubObject{leaf: leaf}})
				return err
			},
		},
		{
			name:     "ErrObjectNotCommitted",
			sentinel: ErrObjectNotCommitted,
			trigger: func(t *testing.T) error {
				_, err := InclusionProof(c4, stubObject{leaf: numberedLeaf(1000)})
				return err
			},
		},
		{
			name:     "ErrNilCommitment verify",
			sentinel: ErrNilCommitment,
			trigger:  func(t *testing.T) error { return VerifyCommitment(nil) },
		},
		{
			name:     "ErrNilCommitment inclusion proof",
			sentinel: ErrNilCommitment,
			trigger: func(t *testing.T) error {
				_, err := InclusionProof(nil, proofObj)
				return err
			},
		},
		{
			name:     "ErrNilCommitment consistency",
			sentinel: ErrNilCommitment,
			trigger: func(t *testing.T) error {
				_, err := ConsistencyProofBetween(nil, c4)
				return err
			},
		},
		{
			name:     "ErrNilCommitment canonical hash",
			sentinel: ErrNilCommitment,
			trigger:  func(t *testing.T) error { _, err := CanonicalHash(nil); return err },
		},
		{
			name:     "ErrAlgorithmMismatch",
			sentinel: ErrAlgorithmMismatch,
			trigger: func(t *testing.T) error {
				bad := *c4
				bad.Algorithm = "sha256-merkle-v2"
				return VerifyCommitment(&bad)
			},
		},
		{
			name:     "ErrEmptyCommitment zero size",
			sentinel: ErrEmptyCommitment,
			trigger: func(t *testing.T) error {
				return VerifyCommitment(&Commitment{Algorithm: AlgorithmRFC6962SHA256})
			},
		},
		{
			name:     "ErrEmptyCommitment nil leaves",
			sentinel: ErrEmptyCommitment,
			trigger: func(t *testing.T) error {
				return VerifyCommitment(&Commitment{Size: 3, Algorithm: AlgorithmRFC6962SHA256})
			},
		},
		{
			name:     "ErrSizeMismatch",
			sentinel: ErrSizeMismatch,
			trigger: func(t *testing.T) error {
				bad := *c4
				bad.Size++
				return VerifyCommitment(&bad)
			},
		},
		{
			name:     "ErrUnsortedLeaves",
			sentinel: ErrUnsortedLeaves,
			trigger: func(t *testing.T) error {
				bad := *c4
				bad.LeafHashes = append([][32]byte(nil), c4.LeafHashes...)
				bad.LeafHashes[0], bad.LeafHashes[3] = bad.LeafHashes[3], bad.LeafHashes[0]
				return VerifyCommitment(&bad)
			},
		},
		{
			name:     "ErrDuplicateLeaf",
			sentinel: ErrDuplicateLeaf,
			trigger: func(t *testing.T) error {
				bad := *c4
				bad.LeafHashes = append([][32]byte(nil), c4.LeafHashes...)
				bad.LeafHashes[1] = bad.LeafHashes[0]
				return VerifyCommitment(&bad)
			},
		},
		{
			name:     "ErrRootMismatch",
			sentinel: ErrRootMismatch,
			trigger: func(t *testing.T) error {
				bad := *c4
				bad.Root[0] ^= 0xff
				return VerifyCommitment(&bad)
			},
		},
		{
			name:     "ErrInclusionFailed",
			sentinel: ErrInclusionFailed,
			trigger: func(t *testing.T) error {
				badRoot := c4.Root
				badRoot[0] ^= 0xff
				return VerifyInclusion(badRoot, proof, proofObj)
			},
		},
		{
			name:     "ErrNotPrefix",
			sentinel: ErrNotPrefix,
			trigger: func(t *testing.T) error {
				old, next := nonPrefix(t)
				_, err := ConsistencyProofBetween(old, next)
				return err
			},
		},
		{
			name:     "ErrInvalidRange equal sizes",
			sentinel: ErrInvalidRange,
			trigger: func(t *testing.T) error {
				_, err := ConsistencyProofBetween(c4, c4)
				return err
			},
		},
		{
			name:     "ErrInvalidRange zero old size",
			sentinel: ErrInvalidRange,
			trigger: func(t *testing.T) error {
				empty := &Commitment{Size: 0, Algorithm: AlgorithmRFC6962SHA256}
				_, err := ConsistencyProofBetween(empty, c4)
				return err
			},
		},
	}

	exercised := make(map[error]bool, len(allSentinels))
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.trigger(t)
			if !errors.Is(err, tc.sentinel) {
				t.Errorf("%s: got error %v, want errors.Is(_, %v)", tc.name, err, tc.sentinel)
			}
			exercised[tc.sentinel] = true
		})
	}
	for _, sentinel := range allSentinels {
		if !exercised[sentinel] {
			t.Errorf("sentinel %v has no negative case, want every sentinel in errors.go exercised", sentinel)
		}
	}
}
