package merkle

import (
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"testing"
)

// All vectors below were produced by an independent Python implementation of
// [RFC 6962] §2.1 (hashlib SHA-256, a direct transcription of the RFC
// recursion) over the leaves d0, d1, ... Cross-implementation vectors catch
// parser and construction bugs that self-consistent round-trips miss.

func testLeaves(n int) [][]byte {
	leaves := make([][]byte, n)
	for i := range leaves {
		leaves[i] = []byte(fmt.Sprintf("d%d", i))
	}
	return leaves
}

func mustDecode(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("decode hex %q: got error %v, want nil", s, err)
	}
	return b
}

func mustDecode32(t *testing.T, s string) [32]byte {
	t.Helper()
	b := mustDecode(t, s)
	if len(b) != 32 {
		t.Fatalf("decode hex %q: got %d bytes, want 32", s, len(b))
	}
	var out [32]byte
	copy(out[:], b)
	return out
}

func ctEqual(a, b []byte) bool {
	return subtle.ConstantTimeCompare(a, b) == 1
}

type vectorStep struct {
	hash    string
	isRight bool
}

var rootVectors = []struct {
	n    int
	root string
}{
	{1, "c67f9ffe68e0761021341dd516428f42fbdea633731cbdada03bea6b84c652f7"},
	{2, "46c78708413a23175f51faf1c22604bccb44482d553b45943b189130ea8221c8"},
	{3, "c64c5b9326951a2db82d5462565696286659d1c7a4a26a92703568f63462f7ba"},
	{4, "8df3870b33fae650e81938994f98eb4551b143b86c95d3dae4e6444e00715016"},
	{5, "2b650a5633502111de1a865b3581e012a91dc1f8b780ddf646a44873dec93163"},
	{6, "b65368cd1f024732c21e9db86bcde27d7de95dc2c40d728dd979ffcf943556e3"},
	{7, "73a590fb266b81557040b146b9d479e2a1b5849b125167642f5b64866f1d5c7d"},
	{8, "3b0c343929799440e33ea5b8376857850457f497736ca6ada6c320ee235b67a4"},
	{9, "68be87542fb826407adcdf28d49f0376082c7f3070e51523b21a8e75ddf90fcf"},
	{10, "9bfd185351345de98fdfed73047051035dbdc257fedac0fad5531585f20f6e41"},
}

var leafHashVectors = map[int]string{
	0: "c67f9ffe68e0761021341dd516428f42fbdea633731cbdada03bea6b84c652f7",
	1: "49b717e4d6ecdd82f6f6648cf8f86fdf4a912600a4557398e1733186fa952c1d",
	2: "f366df4718ef75064317794ff5300e0963e96dd93fe24203118055fa5a00be13",
	3: "5e0c4e1130dfa84d27437ba073eb817e1896643d42ea100a0940f8752d496783",
	4: "39298be94337336fc5515e7a34de6ef23c9a1bff66378b71918ae2d105d684c8",
	5: "6d1bb6bbb111af4a1e9ec0b9fb2613cc2bcb394141cee8c2cd462b5ad3803d78",
	6: "d750ca922fabc5422eec469d4370779b61d5488186cb871eeea299d8113d20bc",
	7: "8f8688ee86ceeee577d99cdc0baa38f04b2506913ce8a923d391ad6a9147b3ec",
}

var inclusionVectors = []struct {
	name  string
	n, m  int
	steps []vectorStep
}{
	{name: "single leaf", n: 1, m: 0, steps: nil},
	{name: "two leaves index 0", n: 2, m: 0, steps: []vectorStep{
		{"49b717e4d6ecdd82f6f6648cf8f86fdf4a912600a4557398e1733186fa952c1d", true},
	}},
	{name: "two leaves index 1", n: 2, m: 1, steps: []vectorStep{
		{"c67f9ffe68e0761021341dd516428f42fbdea633731cbdada03bea6b84c652f7", false},
	}},
	{name: "three leaves index 2", n: 3, m: 2, steps: []vectorStep{
		{"46c78708413a23175f51faf1c22604bccb44482d553b45943b189130ea8221c8", false},
	}},
	{name: "four leaves index 0", n: 4, m: 0, steps: []vectorStep{
		{"49b717e4d6ecdd82f6f6648cf8f86fdf4a912600a4557398e1733186fa952c1d", true},
		{"c59e9a6d9575777ba3bdbd3e3086516196cf87ec9760861362aba5cd0f78df1d", true},
	}},
	{name: "four leaves index 3", n: 4, m: 3, steps: []vectorStep{
		{"f366df4718ef75064317794ff5300e0963e96dd93fe24203118055fa5a00be13", false},
		{"46c78708413a23175f51faf1c22604bccb44482d553b45943b189130ea8221c8", false},
	}},
	{name: "seven leaves index 4", n: 7, m: 4, steps: []vectorStep{
		{"6d1bb6bbb111af4a1e9ec0b9fb2613cc2bcb394141cee8c2cd462b5ad3803d78", true},
		{"d750ca922fabc5422eec469d4370779b61d5488186cb871eeea299d8113d20bc", true},
		{"8df3870b33fae650e81938994f98eb4551b143b86c95d3dae4e6444e00715016", false},
	}},
	{name: "eight leaves index 5", n: 8, m: 5, steps: []vectorStep{
		{"39298be94337336fc5515e7a34de6ef23c9a1bff66378b71918ae2d105d684c8", false},
		{"352c4dbea9c4dc9bb558bebff6c26b691cc05ec9a0dfe1eae27fa7cca9e5eec9", true},
		{"8df3870b33fae650e81938994f98eb4551b143b86c95d3dae4e6444e00715016", false},
	}},
	{name: "ten leaves index 8", n: 10, m: 8, steps: []vectorStep{
		{"03d685c162e8a2f1d6e781afcbfa8433907923f45cc3f075124ec2c5cc581d5b", true},
		{"3b0c343929799440e33ea5b8376857850457f497736ca6ada6c320ee235b67a4", false},
	}},
}

var consistencyVectors = []struct {
	name  string
	m, n  int
	steps []vectorStep
}{
	{name: "one to two", m: 1, n: 2, steps: []vectorStep{
		{"49b717e4d6ecdd82f6f6648cf8f86fdf4a912600a4557398e1733186fa952c1d", true},
	}},
	{name: "one to three", m: 1, n: 3, steps: []vectorStep{
		{"49b717e4d6ecdd82f6f6648cf8f86fdf4a912600a4557398e1733186fa952c1d", true},
		{"f366df4718ef75064317794ff5300e0963e96dd93fe24203118055fa5a00be13", true},
	}},
	{name: "three to four", m: 3, n: 4, steps: []vectorStep{
		{"f366df4718ef75064317794ff5300e0963e96dd93fe24203118055fa5a00be13", false},
		{"5e0c4e1130dfa84d27437ba073eb817e1896643d42ea100a0940f8752d496783", true},
		{"46c78708413a23175f51faf1c22604bccb44482d553b45943b189130ea8221c8", false},
	}},
	{name: "two to five", m: 2, n: 5, steps: []vectorStep{
		{"c59e9a6d9575777ba3bdbd3e3086516196cf87ec9760861362aba5cd0f78df1d", true},
		{"39298be94337336fc5515e7a34de6ef23c9a1bff66378b71918ae2d105d684c8", true},
	}},
	{name: "four to seven", m: 4, n: 7, steps: []vectorStep{
		{"3cf05ff16d26c024828e93b3a14c5656e5abcbc5e6f0bce2cf8a169720599674", true},
	}},
	{name: "five to eight", m: 5, n: 8, steps: []vectorStep{
		{"39298be94337336fc5515e7a34de6ef23c9a1bff66378b71918ae2d105d684c8", false},
		{"6d1bb6bbb111af4a1e9ec0b9fb2613cc2bcb394141cee8c2cd462b5ad3803d78", true},
		{"352c4dbea9c4dc9bb558bebff6c26b691cc05ec9a0dfe1eae27fa7cca9e5eec9", true},
		{"8df3870b33fae650e81938994f98eb4551b143b86c95d3dae4e6444e00715016", false},
	}},
	{name: "three to eight", m: 3, n: 8, steps: []vectorStep{
		{"f366df4718ef75064317794ff5300e0963e96dd93fe24203118055fa5a00be13", false},
		{"5e0c4e1130dfa84d27437ba073eb817e1896643d42ea100a0940f8752d496783", true},
		{"46c78708413a23175f51faf1c22604bccb44482d553b45943b189130ea8221c8", false},
		{"b52dedba4cb3a857bcd722ab1fa28f5714e5788ecca466bd29856138ba4f1218", true},
	}},
}

func vectorRoot(t *testing.T, n int) []byte {
	t.Helper()
	for _, v := range rootVectors {
		if v.n == n {
			return mustDecode(t, v.root)
		}
	}
	t.Fatalf("no root vector for tree size %d", n)
	return nil
}

func TestNewEmptyTree(t *testing.T) {
	t.Parallel()

	for name, leaves := range map[string][][]byte{"nil slice": nil, "empty slice": {}} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			_, err := New(leaves)
			if !errors.Is(err, ErrEmptyTree) {
				t.Errorf("New with no leaves: got error %v, want errors.Is(_, ErrEmptyTree)", err)
			}
		})
	}
}

func TestRoots(t *testing.T) {
	t.Parallel()

	for _, tt := range rootVectors {
		t.Run(fmt.Sprintf("n%d", tt.n), func(t *testing.T) {
			t.Parallel()
			tree, err := New(testLeaves(tt.n))
			if err != nil {
				t.Fatalf("New with %d leaves: got error %v, want nil", tt.n, err)
			}
			want := mustDecode(t, tt.root)
			if got := tree.Root(); !ctEqual(got, want) {
				t.Errorf("root for tree of %d leaves: got %x, want %x", tt.n, got, want)
			}
		})
	}
}

func TestSingleLeafTree(t *testing.T) {
	t.Parallel()

	tree, err := New(testLeaves(1))
	if err != nil {
		t.Fatalf("New with 1 leaf: got error %v, want nil", err)
	}
	wantLeafHash := mustDecode(t, leafHashVectors[0])
	if got := tree.Root(); !ctEqual(got, wantLeafHash) {
		t.Errorf("single-leaf root: got %x, want leaf hash %x", got, wantLeafHash)
	}
	path, err := tree.Proof(0)
	if err != nil {
		t.Fatalf("Proof(0) on single-leaf tree: got error %v, want nil", err)
	}
	if len(path.Steps) != 0 {
		t.Errorf("single-leaf proof length: got %d steps, want 0", len(path.Steps))
	}
	if !Verify(wantLeafHash, []byte("d0"), path) {
		t.Errorf("Verify with empty path on single-leaf tree: got false, want true")
	}
	if Verify(wantLeafHash, []byte("d1"), path) {
		t.Errorf("Verify with wrong leaf on single-leaf tree: got true, want false")
	}
}

func TestLeafHashDomainSeparation(t *testing.T) {
	t.Parallel()

	// The leaf hash of d1 must equal the [RFC 6962] §2.1 vector, proving the
	// 0x00 domain separator is applied.
	for i, want := range leafHashVectors {
		got := leafHash([]byte(fmt.Sprintf("d%d", i)))
		wantHash := mustDecode32(t, want)
		if subtle.ConstantTimeCompare(got[:], wantHash[:]) != 1 {
			t.Errorf("leafHash(d%d): got %x, want %x", i, got, wantHash)
		}
	}

	// A raw SHA-256 with no domain separator must differ from the leaf hash.
	raw := hasher.Sum([]byte("d0"))
	got := leafHash([]byte("d0"))
	if subtle.ConstantTimeCompare(got[:], raw[:]) == 1 {
		t.Errorf("leafHash(d0): got %x, equal to undomained SHA-256, want different", got)
	}

	// A leaf hashed with the interior prefix must not verify as a sibling.
	// Vector: [RFC 6962] §2.1 domain separation requirement.
	tree, err := New(testLeaves(2))
	if err != nil {
		t.Fatalf("New with 2 leaves: got error %v, want nil", err)
	}
	path, err := tree.Proof(0)
	if err != nil {
		t.Fatalf("Proof(0) on 2-leaf tree: got error %v, want nil", err)
	}
	path.Steps[0].Hash = hasher.Sum(append([]byte{nodePrefix}, []byte("d1")...))
	if Verify(tree.Root(), []byte("d0"), path) {
		t.Errorf("Verify with node-prefixed sibling hash: got true, want false")
	}
}

func TestInclusionProofs(t *testing.T) {
	t.Parallel()

	for _, tt := range inclusionVectors {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			tree, err := New(testLeaves(tt.n))
			if err != nil {
				t.Fatalf("New with %d leaves: got error %v, want nil", tt.n, err)
			}
			got, err := tree.Proof(tt.m)
			if err != nil {
				t.Fatalf("Proof(%d) on %d-leaf tree: got error %v, want nil", tt.m, tt.n, err)
			}
			if len(got.Steps) != len(tt.steps) {
				t.Fatalf("proof length for (n=%d, m=%d): got %d steps, want %d", tt.n, tt.m, len(got.Steps), len(tt.steps))
			}
			for i, want := range tt.steps {
				wantHash := mustDecode32(t, want.hash)
				if subtle.ConstantTimeCompare(got.Steps[i].Hash[:], wantHash[:]) != 1 {
					t.Errorf("step %d hash for (n=%d, m=%d): got %x, want %x", i, tt.n, tt.m, got.Steps[i].Hash, wantHash)
				}
				if got.Steps[i].IsRight != want.isRight {
					t.Errorf("step %d direction for (n=%d, m=%d): got IsRight %t, want %t", i, tt.n, tt.m, got.Steps[i].IsRight, want.isRight)
				}
			}
		})
	}
}

func TestVerifyInclusionAgainstVectors(t *testing.T) {
	t.Parallel()

	for _, tt := range inclusionVectors {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			tree, err := New(testLeaves(tt.n))
			if err != nil {
				t.Fatalf("New with %d leaves: got error %v, want nil", tt.n, err)
			}
			path, err := tree.Proof(tt.m)
			if err != nil {
				t.Fatalf("Proof(%d): got error %v, want nil", tt.m, err)
			}
			// Verify against the independent vector root, not tree.Root(), so
			// the check covers both the proof and the construction.
			root := vectorRoot(t, tt.n)
			leaf := []byte(fmt.Sprintf("d%d", tt.m))
			if !Verify(root, leaf, path) {
				t.Errorf("Verify for (n=%d, m=%d) against vector root: got false, want true", tt.n, tt.m)
			}
		})
	}
}

func TestVerifyAllIndices(t *testing.T) {
	t.Parallel()

	for _, n := range []int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 17} {
		t.Run(fmt.Sprintf("n%d", n), func(t *testing.T) {
			t.Parallel()
			tree, err := New(testLeaves(n))
			if err != nil {
				t.Fatalf("New with %d leaves: got error %v, want nil", n, err)
			}
			root := tree.Root()
			for m := 0; m < n; m++ {
				path, err := tree.Proof(m)
				if err != nil {
					t.Fatalf("Proof(%d) on %d-leaf tree: got error %v, want nil", m, n, err)
				}
				leaf := []byte(fmt.Sprintf("d%d", m))
				if !Verify(root, leaf, path) {
					t.Errorf("Verify for (n=%d, m=%d): got false, want true", n, m)
				}
			}
		})
	}
}

func TestVerifyNegative(t *testing.T) {
	t.Parallel()

	tree, err := New(testLeaves(8))
	if err != nil {
		t.Fatalf("New with 8 leaves: got error %v, want nil", err)
	}
	root := tree.Root()
	path, err := tree.Proof(5)
	if err != nil {
		t.Fatalf("Proof(5) on 8-leaf tree: got error %v, want nil", err)
	}
	leaf := []byte("d5")

	if Verify(root, []byte("d4"), path) {
		t.Errorf("Verify with wrong leaf: got true, want false")
	}

	tampered := AuditPath{Steps: append([]ProofStep(nil), path.Steps...)}
	tampered.Steps[0].Hash[0] ^= 0xff
	if Verify(root, leaf, tampered) {
		t.Errorf("Verify with tampered sibling: got true, want false")
	}

	wrongRoot := append([]byte(nil), root...)
	wrongRoot[0] ^= 0xff
	if Verify(wrongRoot, leaf, path) {
		t.Errorf("Verify with wrong root: got true, want false")
	}

	truncated := AuditPath{Steps: path.Steps[:len(path.Steps)-1]}
	if Verify(root, leaf, truncated) {
		t.Errorf("Verify with truncated path: got true, want false")
	}

	extended := AuditPath{Steps: append(append([]ProofStep(nil), path.Steps...), ProofStep{})}
	if Verify(root, leaf, extended) {
		t.Errorf("Verify with extended path: got true, want false")
	}

	if Verify(root[:16], leaf, path) {
		t.Errorf("Verify with 16-byte root: got true, want false")
	}

	if Verify(nil, leaf, path) {
		t.Errorf("Verify with nil root: got true, want false")
	}
}

func TestProofIndexErrors(t *testing.T) {
	t.Parallel()

	tree, err := New(testLeaves(4))
	if err != nil {
		t.Fatalf("New with 4 leaves: got error %v, want nil", err)
	}
	for _, index := range []int{-1, 4, 100} {
		_, err := tree.Proof(index)
		if !errors.Is(err, ErrIndexOutOfRange) {
			t.Errorf("Proof(%d) on 4-leaf tree: got error %v, want errors.Is(_, ErrIndexOutOfRange)", index, err)
		}
	}
}

func TestNilLeafBoundary(t *testing.T) {
	t.Parallel()

	leaves := [][]byte{nil, []byte("x"), nil}
	tree, err := New(leaves)
	if err != nil {
		t.Fatalf("New with nil leaves: got error %v, want nil", err)
	}
	for _, index := range []int{0, 2} {
		path, err := tree.Proof(index)
		if err != nil {
			t.Fatalf("Proof(%d) with nil leaf: got error %v, want nil", index, err)
		}
		if !Verify(tree.Root(), nil, path) {
			t.Errorf("Verify with nil leaf at index %d: got false, want true", index)
		}
	}
}

func TestConsistencyProofs(t *testing.T) {
	t.Parallel()

	for _, tt := range consistencyVectors {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			tree, err := New(testLeaves(tt.n))
			if err != nil {
				t.Fatalf("New with %d leaves: got error %v, want nil", tt.n, err)
			}
			got, err := tree.ConsistencyProof(tt.m, tt.n)
			if err != nil {
				t.Fatalf("ConsistencyProof(%d, %d): got error %v, want nil", tt.m, tt.n, err)
			}
			if len(got.Steps) != len(tt.steps) {
				t.Fatalf("consistency proof length for (%d, %d): got %d steps, want %d", tt.m, tt.n, len(got.Steps), len(tt.steps))
			}
			for i, want := range tt.steps {
				wantHash := mustDecode32(t, want.hash)
				if subtle.ConstantTimeCompare(got.Steps[i].Hash[:], wantHash[:]) != 1 {
					t.Errorf("step %d hash for (%d, %d): got %x, want %x", i, tt.m, tt.n, got.Steps[i].Hash, wantHash)
				}
				if got.Steps[i].IsRight != want.isRight {
					t.Errorf("step %d direction for (%d, %d): got IsRight %t, want %t", i, tt.m, tt.n, got.Steps[i].IsRight, want.isRight)
				}
			}
		})
	}
}

func TestVerifyConsistencyAgainstVectors(t *testing.T) {
	t.Parallel()

	for _, tt := range consistencyVectors {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			tree, err := New(testLeaves(tt.n))
			if err != nil {
				t.Fatalf("New with %d leaves: got error %v, want nil", tt.n, err)
			}
			path, err := tree.ConsistencyProof(tt.m, tt.n)
			if err != nil {
				t.Fatalf("ConsistencyProof(%d, %d): got error %v, want nil", tt.m, tt.n, err)
			}
			// Verify against the independent vector roots for both sizes.
			oldRoot := vectorRoot(t, tt.m)
			newRoot := vectorRoot(t, tt.n)
			if !VerifyConsistency(oldRoot, newRoot, tt.m, tt.n, path) {
				t.Errorf("VerifyConsistency for (%d, %d) against vector roots: got false, want true", tt.m, tt.n)
			}
		})
	}
}

func TestVerifyConsistencyEqualSizes(t *testing.T) {
	t.Parallel()

	root := vectorRoot(t, 6)
	empty := AuditPath{}
	if !VerifyConsistency(root, root, 6, 6, empty) {
		t.Errorf("VerifyConsistency with m == n and identical roots: got false, want true")
	}
	other := vectorRoot(t, 7)
	if VerifyConsistency(root, other, 6, 6, empty) {
		t.Errorf("VerifyConsistency with m == n and different roots: got true, want false")
	}
	four, err := New(testLeaves(4))
	if err != nil {
		t.Fatalf("New with 4 leaves: got error %v, want nil", err)
	}
	nonEmpty, err := four.ConsistencyProof(2, 4)
	if err != nil {
		t.Fatalf("ConsistencyProof(2, 4): got error %v, want nil", err)
	}
	if VerifyConsistency(root, root, 6, 6, nonEmpty) {
		t.Errorf("VerifyConsistency with m == n and non-empty path: got true, want false")
	}
}

func TestVerifyConsistencyNegative(t *testing.T) {
	t.Parallel()

	tree, err := New(testLeaves(8))
	if err != nil {
		t.Fatalf("New with 8 leaves: got error %v, want nil", err)
	}
	path, err := tree.ConsistencyProof(5, 8)
	if err != nil {
		t.Fatalf("ConsistencyProof(5, 8): got error %v, want nil", err)
	}
	oldRoot := vectorRoot(t, 5)
	newRoot := vectorRoot(t, 8)

	tampered := AuditPath{Steps: append([]ProofStep(nil), path.Steps...)}
	tampered.Steps[0].Hash[0] ^= 0xff
	if VerifyConsistency(oldRoot, newRoot, 5, 8, tampered) {
		t.Errorf("VerifyConsistency with tampered proof node: got true, want false")
	}

	if VerifyConsistency(vectorRoot(t, 6), newRoot, 5, 8, path) {
		t.Errorf("VerifyConsistency with wrong old root: got true, want false")
	}

	flipNew := append([]byte(nil), newRoot...)
	flipNew[0] ^= 0xff
	if VerifyConsistency(oldRoot, flipNew, 5, 8, path) {
		t.Errorf("VerifyConsistency with wrong new root: got true, want false")
	}

	if VerifyConsistency(newRoot, oldRoot, 5, 8, path) {
		t.Errorf("VerifyConsistency with swapped roots: got true, want false")
	}

	if VerifyConsistency(oldRoot, newRoot, 3, 8, path) {
		t.Errorf("VerifyConsistency with wrong m: got true, want false")
	}

	truncated := AuditPath{Steps: path.Steps[:len(path.Steps)-1]}
	if VerifyConsistency(oldRoot, newRoot, 5, 8, truncated) {
		t.Errorf("VerifyConsistency with truncated path: got true, want false")
	}

	extended := AuditPath{Steps: append(append([]ProofStep(nil), path.Steps...), ProofStep{})}
	if VerifyConsistency(oldRoot, newRoot, 5, 8, extended) {
		t.Errorf("VerifyConsistency with extended path: got true, want false")
	}

	if VerifyConsistency(oldRoot, newRoot, 0, 8, AuditPath{}) {
		t.Errorf("VerifyConsistency with m == 0: got true, want false")
	}

	if VerifyConsistency(oldRoot, newRoot, 9, 8, AuditPath{}) {
		t.Errorf("VerifyConsistency with m > n: got true, want false")
	}

	if VerifyConsistency(oldRoot[:16], newRoot, 5, 8, path) {
		t.Errorf("VerifyConsistency with 16-byte old root: got true, want false")
	}

	if VerifyConsistency(oldRoot, nil, 5, 8, path) {
		t.Errorf("VerifyConsistency with nil new root: got true, want false")
	}
}

func TestConsistencyProofRangeErrors(t *testing.T) {
	t.Parallel()

	tree, err := New(testLeaves(8))
	if err != nil {
		t.Fatalf("New with 8 leaves: got error %v, want nil", err)
	}
	for _, tt := range []struct {
		name    string
		m, n    int
		wantErr error
	}{
		{name: "zero m", m: 0, n: 8, wantErr: ErrInvalidRange},
		{name: "negative m", m: -2, n: 8, wantErr: ErrInvalidRange},
		{name: "m equals n", m: 8, n: 8, wantErr: ErrInvalidRange},
		{name: "m greater than n", m: 9, n: 8, wantErr: ErrInvalidRange},
		{name: "n not tree size", m: 4, n: 6, wantErr: ErrInvalidRange},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, err := tree.ConsistencyProof(tt.m, tt.n)
			if !errors.Is(err, tt.wantErr) {
				t.Errorf("ConsistencyProof(%d, %d): got error %v, want errors.Is(_, %v)", tt.m, tt.n, err, tt.wantErr)
			}
		})
	}
}

func TestDeterminism(t *testing.T) {
	t.Parallel()

	first, err := New(testLeaves(7))
	if err != nil {
		t.Fatalf("first New with 7 leaves: got error %v, want nil", err)
	}
	second, err := New(testLeaves(7))
	if err != nil {
		t.Fatalf("second New with 7 leaves: got error %v, want nil", err)
	}
	if !ctEqual(first.Root(), second.Root()) {
		t.Errorf("roots for identical leaves: got %x and %x, want equal", first.Root(), second.Root())
	}
	for m := 0; m < 7; m++ {
		p1, err := first.Proof(m)
		if err != nil {
			t.Fatalf("first Proof(%d): got error %v, want nil", m, err)
		}
		p2, err := second.Proof(m)
		if err != nil {
			t.Fatalf("second Proof(%d): got error %v, want nil", m, err)
		}
		if len(p1.Steps) != len(p2.Steps) {
			t.Fatalf("proof lengths for index %d: got %d and %d, want equal", m, len(p1.Steps), len(p2.Steps))
		}
		for i := range p1.Steps {
			if subtle.ConstantTimeCompare(p1.Steps[i].Hash[:], p2.Steps[i].Hash[:]) != 1 || p1.Steps[i].IsRight != p2.Steps[i].IsRight {
				t.Errorf("proof step %d for index %d: got %x/%t and %x/%t, want equal", i, m, p1.Steps[i].Hash, p1.Steps[i].IsRight, p2.Steps[i].Hash, p2.Steps[i].IsRight)
			}
		}
	}
}

func TestConcurrentAccess(t *testing.T) {
	t.Parallel()

	const size = 50
	tree, err := New(testLeaves(size))
	if err != nil {
		t.Fatalf("New with %d leaves: got error %v, want nil", size, err)
	}
	root := tree.Root()
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for j := 0; j < 25; j++ {
				index := (g*7 + j*3) % size
				path, err := tree.Proof(index)
				if err != nil {
					t.Errorf("Proof(%d) from goroutine %d: got error %v, want nil", index, g, err)
					return
				}
				if !Verify(root, []byte(fmt.Sprintf("d%d", index)), path) {
					t.Errorf("Verify for index %d from goroutine %d: got false, want true", index, g)
					return
				}
				m := 1 + (index % (size - 1))
				cproof, err := tree.ConsistencyProof(m, size)
				if err != nil {
					t.Errorf("ConsistencyProof(%d, %d) from goroutine %d: got error %v, want nil", m, size, g, err)
					return
				}
				old, err := New(testLeaves(m))
				if err != nil {
					t.Errorf("New with %d leaves from goroutine %d: got error %v, want nil", m, g, err)
					return
				}
				if !VerifyConsistency(old.Root(), root, m, size, cproof) {
					t.Errorf("VerifyConsistency for (%d, %d) from goroutine %d: got false, want true", m, size, g)
					return
				}
			}
		}(g)
	}
	wg.Wait()
}

func TestLargeTree(t *testing.T) {
	t.Parallel()

	const size = 4097
	tree, err := New(testLeaves(size))
	if err != nil {
		t.Fatalf("New with %d leaves: got error %v, want nil", size, err)
	}
	root := tree.Root()
	for i := 0; i < size; i += 97 {
		path, err := tree.Proof(i)
		if err != nil {
			t.Fatalf("Proof(%d) on %d-leaf tree: got error %v, want nil", i, size, err)
		}
		if !Verify(root, []byte(fmt.Sprintf("d%d", i)), path) {
			t.Errorf("Verify for index %d on %d-leaf tree: got false, want true", i, size)
		}
	}
	for _, m := range []int{1, 2, 4096} {
		path, err := tree.ConsistencyProof(m, size)
		if err != nil {
			t.Fatalf("ConsistencyProof(%d, %d): got error %v, want nil", m, size, err)
		}
		if !VerifyConsistency(mustSubtreeRoot(t, tree, m), root, m, size, path) {
			t.Errorf("VerifyConsistency for (%d, %d) on %d-leaf tree: got false, want true", m, size, size)
		}
	}
}

// mustSubtreeRoot builds a second tree over the first m leaves and returns
// its root, standing in for the previously advertised m-leaf tree head.
func mustSubtreeRoot(t *testing.T, tree *Tree, m int) []byte {
	t.Helper()
	old, err := New(testLeaves(m))
	if err != nil {
		t.Fatalf("New with %d leaves: got error %v, want nil", m, err)
	}
	return old.Root()
}
