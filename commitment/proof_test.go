package commitment

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"testing"

	"github.com/bperin/trust/merkle"
)

// objectsByLeaf returns a lookup from leaf hash to the stubObject carrying it.
func objectsByLeaf(objects []TrustObject) map[[32]byte]TrustObject {
	m := make(map[[32]byte]TrustObject, len(objects))
	for _, o := range objects {
		s := o.(stubObject)
		m[s.leaf] = o
	}
	return m
}

func TestInclusionProof_EveryIndex(t *testing.T) {
	const n = 8
	objects := stubObjects(n)
	c := mustBuild(t, objects)
	byLeaf := objectsByLeaf(objects)

	for i := 0; i < n; i++ {
		obj := byLeaf[c.LeafHashes[i]]
		p, err := InclusionProof(c, obj)
		if err != nil {
			t.Fatalf("InclusionProof(leaf %d) err = %v, want nil", i, err)
		}
		if p.Index != i {
			t.Errorf("Index = %d, want %d", p.Index, i)
		}
		if p.TreeSize != n {
			t.Errorf("TreeSize = %d, want %d", p.TreeSize, n)
		}
		if err := VerifyInclusion(c.Root, p, obj); err != nil {
			t.Errorf("VerifyInclusion(leaf %d) err = %v, want nil", i, err)
		}
	}
}

func TestInclusionProof_Uncommitted(t *testing.T) {
	c := mustBuild(t, stubObjects(4))
	absent := stubObject{leaf: numberedLeaf(1000)}
	_, err := InclusionProof(c, absent)
	if !errors.Is(err, ErrObjectNotCommitted) {
		t.Errorf("InclusionProof() err = %v, want ErrObjectNotCommitted", err)
	}
}

func TestInclusionProof_NilCommitment(t *testing.T) {
	_, err := InclusionProof(nil, stubObject{leaf: numberedLeaf(1)})
	if !errors.Is(err, ErrNilCommitment) {
		t.Errorf("InclusionProof(nil, _) err = %v, want ErrNilCommitment", err)
	}
}

func TestInclusionProof_NilObject(t *testing.T) {
	c := mustBuild(t, stubObjects(2))
	_, err := InclusionProof(c, nil)
	if !errors.Is(err, ErrNilObject) {
		t.Errorf("InclusionProof(_, nil) err = %v, want ErrNilObject", err)
	}
}

func TestInclusionProof_SingleLeaf(t *testing.T) {
	obj := stubObject{leaf: numberedLeaf(1)}
	c := mustBuild(t, []TrustObject{obj})

	p, err := InclusionProof(c, obj)
	if err != nil {
		t.Fatalf("InclusionProof() err = %v, want nil", err)
	}
	if len(p.Steps) != 0 {
		t.Errorf("len(Steps) = %d, want 0", len(p.Steps))
	}
	if p.Index != 0 || p.TreeSize != 1 {
		t.Errorf("Index/TreeSize = %d/%d, want 0/1", p.Index, p.TreeSize)
	}
	if err := VerifyInclusion(c.Root, p, obj); err != nil {
		t.Errorf("VerifyInclusion() err = %v, want nil", err)
	}
}

// TestVerifyInclusion_RFC6962Vector verifies a proof against a pinned
// [RFC 6962] §2.1 root computed by an independent recomputation
// (SHA-256 over the RFC's 0x00/0x01 domain-separated recursion) for a
// 4-leaf tree whose leaves are the byte-filled digests 0x01..0x04.
func TestVerifyInclusion_RFC6962Vector(t *testing.T) {
	// Vector: [RFC 6962] §2.1 MTH over four 32-byte leaves, leaf i filled
	// with byte i+1. Root pinned from an independent SHA-256 recomputation.
	wantRoot := [32]byte{
		0x3b, 0x3c, 0x0c, 0xe4, 0x5d, 0x11, 0x51, 0x7a,
		0x54, 0x30, 0x0a, 0x19, 0x6b, 0x61, 0x49, 0x7c,
		0x41, 0x65, 0x15, 0x0d, 0x72, 0xb7, 0x78, 0x2a,
		0x45, 0x48, 0xe3, 0x98, 0x4d, 0xa7, 0x71, 0xb2,
	}
	objects := make([]TrustObject, 4)
	for i := range objects {
		var leaf [32]byte
		for j := range leaf {
			leaf[j] = byte(i + 1)
		}
		objects[i] = stubObject{leaf: leaf}
	}
	c := mustBuild(t, objects)
	if subtle.ConstantTimeCompare(c.Root[:], wantRoot[:]) != 1 {
		t.Fatalf("Root = %x, want RFC 6962 vector %x", c.Root, wantRoot)
	}
	for _, obj := range objects {
		p, err := InclusionProof(c, obj)
		if err != nil {
			t.Fatalf("InclusionProof() err = %v, want nil", err)
		}
		if err := VerifyInclusion(wantRoot, p, obj); err != nil {
			t.Errorf("VerifyInclusion() err = %v, want nil", err)
		}
	}
}

// TestVerifyInclusion_Negative mutates one part of a valid proof per case
// and asserts ErrInclusionFailed plus the surfaced merkle sentinel.
func TestVerifyInclusion_Negative(t *testing.T) {
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
		root   [32]byte
		proof  Proof
		obj    TrustObject
		merkle error
	}{
		{
			name:   "TamperedRoot",
			root:   func() [32]byte { r := c.Root; r[0] ^= 0xff; return r }(),
			proof:  base,
			obj:    obj,
			merkle: merkle.ErrTamperedLeaf,
		},
		{
			name: "TamperedStep",
			root: c.Root,
			proof: func() Proof {
				p := base
				p.Steps = append([]merkle.ProofStep(nil), base.Steps...)
				p.Steps[0].Hash[0] ^= 0xff
				return p
			}(),
			obj:    obj,
			merkle: merkle.ErrTamperedLeaf,
		},
		{
			name:   "WrongObject",
			root:   c.Root,
			proof:  base,
			obj:    byLeaf[c.LeafHashes[6]],
			merkle: merkle.ErrTamperedLeaf,
		},
		{
			name: "WrongIndex",
			root: c.Root,
			proof: func() Proof {
				p := base
				p.Index = 4
				return p
			}(),
			obj:    obj,
			merkle: merkle.ErrTamperedLeaf,
		},
		{
			// Size 6 gives index 5 a different side-marker sequence than
			// size 8, so the proof shape no longer matches.
			name: "WrongSize",
			root: c.Root,
			proof: func() Proof {
				p := base
				p.TreeSize = 6
				return p
			}(),
			obj:    obj,
			merkle: merkle.ErrTamperedLeaf,
		},
		{
			name: "IndexOutOfRange",
			root: c.Root,
			proof: func() Proof {
				p := base
				p.Index = 8
				return p
			}(),
			obj:    obj,
			merkle: merkle.ErrIndexOutOfRange,
		},
		{
			name: "TruncatedProof",
			root: c.Root,
			proof: func() Proof {
				p := base
				p.Steps = p.Steps[:len(p.Steps)-1]
				return p
			}(),
			obj:    obj,
			merkle: merkle.ErrTamperedLeaf,
		},
		{
			name: "ExtendedProof",
			root: c.Root,
			proof: func() Proof {
				p := base
				p.Steps = append(append([]merkle.ProofStep(nil), base.Steps...), merkle.ProofStep{})
				return p
			}(),
			obj:    obj,
			merkle: merkle.ErrTamperedLeaf,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := VerifyInclusion(tc.root, tc.proof, tc.obj)
			if !errors.Is(err, ErrInclusionFailed) {
				t.Errorf("VerifyInclusion() err = %v, want ErrInclusionFailed", err)
			}
			if !errors.Is(err, tc.merkle) {
				t.Errorf("VerifyInclusion() err = %v, want errors.Is(_, %v)", err, tc.merkle)
			}
		})
	}
}

func TestVerifyInclusion_NilObject(t *testing.T) {
	c := mustBuild(t, stubObjects(2))
	p, err := InclusionProof(c, stubObject{leaf: c.LeafHashes[0]})
	if err != nil {
		t.Fatalf("InclusionProof() err = %v, want nil", err)
	}
	if err := VerifyInclusion(c.Root, p, nil); !errors.Is(err, ErrNilObject) {
		t.Errorf("VerifyInclusion(_, _, nil) err = %v, want ErrNilObject", err)
	}
}

func TestProofJSON_RoundTrip(t *testing.T) {
	var s1, s2 merkle.ProofStep
	for i := range s1.Hash {
		s1.Hash[i] = byte(i)
		s2.Hash[i] = byte(0xff - i)
	}
	s1.IsRight = true
	orig := Proof{Index: 3, TreeSize: 7, Steps: []merkle.ProofStep{s1, s2}}

	b, err := json.Marshal(&orig)
	if err != nil {
		t.Fatalf("Marshal() err = %v, want nil", err)
	}
	var back Proof
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatalf("Unmarshal() err = %v, want nil", err)
	}
	if back.Index != orig.Index || back.TreeSize != orig.TreeSize {
		t.Errorf("Index/TreeSize = %d/%d, want %d/%d", back.Index, back.TreeSize, orig.Index, orig.TreeSize)
	}
	if len(back.Steps) != len(orig.Steps) {
		t.Fatalf("len(Steps) = %d, want %d", len(back.Steps), len(orig.Steps))
	}
	for i := range orig.Steps {
		if subtle.ConstantTimeCompare(back.Steps[i].Hash[:], orig.Steps[i].Hash[:]) != 1 {
			t.Errorf("Steps[%d].Hash = %x, want %x", i, back.Steps[i].Hash, orig.Steps[i].Hash)
		}
		if back.Steps[i].IsRight != orig.Steps[i].IsRight {
			t.Errorf("Steps[%d].IsRight = %t, want %t", i, back.Steps[i].IsRight, orig.Steps[i].IsRight)
		}
	}
}

func TestProofJSON_NilSteps(t *testing.T) {
	orig := Proof{Index: 0, TreeSize: 1, Steps: nil}
	b, err := json.Marshal(&orig)
	if err != nil {
		t.Fatalf("Marshal() err = %v, want nil", err)
	}
	var back Proof
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatalf("Unmarshal() err = %v, want nil", err)
	}
	if back.Index != 0 || back.TreeSize != 1 {
		t.Errorf("Index/TreeSize = %d/%d, want 0/1", back.Index, back.TreeSize)
	}
	if len(back.Steps) != 0 {
		t.Errorf("len(Steps) = %d, want 0", len(back.Steps))
	}
}

func TestProofJSON_InvalidHex(t *testing.T) {
	in := `{"index":0,"treeSize":2,"steps":[{"hash":"zzzz","isRight":true}]}`
	var p Proof
	if err := json.Unmarshal([]byte(in), &p); err == nil {
		t.Errorf("Unmarshal(%s) err = nil, want decode error", in)
	}
}

func TestProofJSON_ShortHash(t *testing.T) {
	in := `{"index":0,"treeSize":2,"steps":[{"hash":"0102","isRight":false}]}`
	var p Proof
	if err := json.Unmarshal([]byte(in), &p); err == nil {
		t.Errorf("Unmarshal(%s) err = nil, want decode error", in)
	}
}

// TestProofJSON_HexForm pins the wire shape: lowercase hex, isRight bool.
func TestProofJSON_HexForm(t *testing.T) {
	var step merkle.ProofStep
	step.Hash[0] = 0xab
	step.IsRight = true
	p := Proof{Index: 1, TreeSize: 2, Steps: []merkle.ProofStep{step}}
	b, err := json.Marshal(&p)
	if err != nil {
		t.Fatalf("Marshal() err = %v, want nil", err)
	}
	want := `{"index":1,"treeSize":2,"steps":[{"hash":"ab00000000000000000000000000000000000000000000000000000000000000","isRight":true}]}`
	if string(b) != want {
		t.Errorf("Marshal() = %s, want %s", b, want)
	}
}
