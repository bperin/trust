package merkle

import (
	"crypto/subtle"
	"errors"
	"fmt"
	"sync"
	"testing"
)

// batchLeaves generates n distinct canonical attestation hashes for testing.
// Each hash is SHA-256 of a unique label, standing in for the canonical hash
// of an attestation body.
func batchLeaves(n int) [][32]byte {
	leaves := make([][32]byte, n)
	for i := range leaves {
		leaves[i] = hasher.Sum([]byte(fmt.Sprintf("h%d", i)))
	}
	return leaves
}

// ctEqual32 compares two [32]byte values in constant time.
func ctEqual32(a, b [32]byte) bool {
	return subtle.ConstantTimeCompare(a[:], b[:]) == 1
}

func TestNewBatchEmpty(t *testing.T) {
	t.Parallel()

	for name, leaves := range map[string][][32]byte{"nil slice": nil, "empty slice": {}} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			_, err := NewBatch(BatchID{}, 1, 1, leaves)
			if !errors.Is(err, ErrEmptyBatch) {
				t.Errorf("NewBatch with no leaves: got error %v, want errors.Is(_, ErrEmptyBatch)", err)
			}
		})
	}
}

// TestBatchRootMatchesTree verifies that NewBatch builds the same
// [RFC 6962] §2.1 tree as a direct call to New with the same leaves. Since
// the batch leaves are [32]byte canonical hashes (not raw attestation
// bytes), the existing root vectors for "d0".."d9" cannot be reused
// directly — the tree applies leafHash to each canonical hash. Instead we
// cross-reference against an independently built Tree.
func TestBatchRootMatchesTree(t *testing.T) {
	t.Parallel()

	for _, n := range []int{1, 2, 3, 4, 5, 8} {
		t.Run(fmt.Sprintf("n%d", n), func(t *testing.T) {
			t.Parallel()
			leaves := batchLeaves(n)
			raw := make([][]byte, n)
			for i := range leaves {
				raw[i] = leaves[i][:]
			}
			tree, err := New(raw)
			if err != nil {
				t.Fatalf("New with %d leaves: got error %v, want nil", n, err)
			}
			want := tree.Root()
			batch, err := NewBatch(BatchID{}, 1, 1, leaves)
			if err != nil {
				t.Fatalf("NewBatch with %d leaves: got error %v, want nil", n, err)
			}
			if subtle.ConstantTimeCompare(batch.Root[:], want) != 1 {
				t.Errorf("batch root for %d leaves: got %x, want %x", n, batch.Root, want)
			}
			if batch.LeafCount != uint64(n) {
				t.Errorf("batch leaf count for %d leaves: got %d, want %d", n, batch.LeafCount, n)
			}
		})
	}
}

func TestBatchRoundTrip(t *testing.T) {
	t.Parallel()

	for _, n := range []int{1, 2, 3, 4, 5, 8, 17} {
		t.Run(fmt.Sprintf("n%d", n), func(t *testing.T) {
			t.Parallel()
			leaves := batchLeaves(n)
			batch, err := NewBatch(BatchID{}, 1, 1, leaves)
			if err != nil {
				t.Fatalf("NewBatch with %d leaves: got error %v, want nil", n, err)
			}
			for i := 0; i < n; i++ {
				proof, err := InclusionProof(batch, uint64(i))
				if err != nil {
					t.Fatalf("InclusionProof(%d) on %d-leaf batch: got error %v, want nil", i, n, err)
				}
				if err := VerifyInclusion(batch.Root, uint64(i), batch.LeafCount, leaves[i], proof); err != nil {
					t.Errorf("VerifyInclusion for (n=%d, i=%d): got error %v, want nil", n, i, err)
				}
			}
		})
	}
}

func TestBatchDeterminism(t *testing.T) {
	t.Parallel()

	leaves := batchLeaves(7)
	first, err := NewBatch(BatchID{}, 1, 1, leaves)
	if err != nil {
		t.Fatalf("first NewBatch with 7 leaves: got error %v, want nil", err)
	}
	second, err := NewBatch(BatchID{}, 1, 1, leaves)
	if err != nil {
		t.Fatalf("second NewBatch with 7 leaves: got error %v, want nil", err)
	}
	if !ctEqual32(first.Root, second.Root) {
		t.Errorf("roots for identical leaves: got %x and %x, want equal", first.Root, second.Root)
	}
	for i := 0; i < 7; i++ {
		p1, err := InclusionProof(first, uint64(i))
		if err != nil {
			t.Fatalf("first InclusionProof(%d): got error %v, want nil", i, err)
		}
		p2, err := InclusionProof(second, uint64(i))
		if err != nil {
			t.Fatalf("second InclusionProof(%d): got error %v, want nil", i, err)
		}
		if len(p1) != len(p2) {
			t.Fatalf("proof lengths for index %d: got %d and %d, want equal", i, len(p1), len(p2))
		}
		for j := range p1 {
			if subtle.ConstantTimeCompare(p1[j], p2[j]) != 1 {
				t.Errorf("proof step %d for index %d: got %x and %x, want equal", j, i, p1[j], p2[j])
			}
		}
	}
}

func TestSingleLeafBatch(t *testing.T) {
	t.Parallel()

	leaves := batchLeaves(1)
	batch, err := NewBatch(BatchID{}, 1, 1, leaves)
	if err != nil {
		t.Fatalf("NewBatch with 1 leaf: got error %v, want nil", err)
	}
	proof, err := InclusionProof(batch, 0)
	if err != nil {
		t.Fatalf("InclusionProof(0) on single-leaf batch: got error %v, want nil", err)
	}
	if len(proof) != 0 {
		t.Errorf("single-leaf proof length: got %d, want 0", len(proof))
	}
	if err := VerifyInclusion(batch.Root, 0, batch.LeafCount, leaves[0], proof); err != nil {
		t.Errorf("VerifyInclusion on single-leaf batch: got error %v, want nil", err)
	}
}

func TestInclusionProofEncoding(t *testing.T) {
	t.Parallel()

	leaves := batchLeaves(4)
	batch, err := NewBatch(BatchID{}, 1, 1, leaves)
	if err != nil {
		t.Fatalf("NewBatch: got error %v, want nil", err)
	}
	raw := make([][]byte, 4)
	for i := range leaves {
		raw[i] = leaves[i][:]
	}
	tree, err := New(raw)
	if err != nil {
		t.Fatalf("New: got error %v, want nil", err)
	}
	for i := 0; i < 4; i++ {
		path, err := tree.Proof(i)
		if err != nil {
			t.Fatalf("tree.Proof(%d): got error %v, want nil", i, err)
		}
		proof, err := InclusionProof(batch, uint64(i))
		if err != nil {
			t.Fatalf("InclusionProof(%d): got error %v, want nil", i, err)
		}
		if len(proof) != len(path.Steps) {
			t.Fatalf("proof length for index %d: got %d, want %d", i, len(proof), len(path.Steps))
		}
		for j, step := range path.Steps {
			if len(proof[j]) != proofElemLen {
				t.Fatalf("proof element %d for index %d: got %d bytes, want %d", j, i, len(proof[j]), proofElemLen)
			}
			wantSide := sideLeft
			if step.IsRight {
				wantSide = sideRight
			}
			if proof[j][0] != wantSide {
				t.Errorf("proof step %d side for index %d: got 0x%02x, want 0x%02x", j, i, proof[j][0], wantSide)
			}
			var gotHash [32]byte
			copy(gotHash[:], proof[j][1:])
			if !ctEqual32(step.Hash, gotHash) {
				t.Errorf("proof step %d hash for index %d: got %x, want %x", j, i, gotHash, step.Hash)
			}
		}
	}
}

func TestInclusionProofWrongIndex(t *testing.T) {
	t.Parallel()

	batch, err := NewBatch(BatchID{}, 1, 1, batchLeaves(4))
	if err != nil {
		t.Fatalf("NewBatch: got error %v, want nil", err)
	}
	for _, index := range []uint64{4, 100, ^uint64(0)} {
		_, err := InclusionProof(batch, index)
		if !errors.Is(err, ErrWrongLeafIndex) {
			t.Errorf("InclusionProof(%d) on 4-leaf batch: got error %v, want errors.Is(_, ErrWrongLeafIndex)", index, err)
		}
	}
}

func TestVerifyInclusionTamperedLeaf(t *testing.T) {
	t.Parallel()

	leaves := batchLeaves(8)
	batch, err := NewBatch(BatchID{}, 1, 1, leaves)
	if err != nil {
		t.Fatalf("NewBatch: got error %v, want nil", err)
	}
	proof, err := InclusionProof(batch, 5)
	if err != nil {
		t.Fatalf("InclusionProof(5): got error %v, want nil", err)
	}
	wrong := leaves[4]
	if err := VerifyInclusion(batch.Root, 5, batch.LeafCount, wrong, proof); !errors.Is(err, ErrTamperedLeaf) {
		t.Errorf("VerifyInclusion with wrong leaf: got error %v, want errors.Is(_, ErrTamperedLeaf)", err)
	}
}

func TestVerifyInclusionRootMismatch(t *testing.T) {
	t.Parallel()

	leaves := batchLeaves(8)
	batch, err := NewBatch(BatchID{}, 1, 1, leaves)
	if err != nil {
		t.Fatalf("NewBatch: got error %v, want nil", err)
	}
	proof, err := InclusionProof(batch, 5)
	if err != nil {
		t.Fatalf("InclusionProof(5): got error %v, want nil", err)
	}
	wrongRoot := batch.Root
	wrongRoot[0] ^= 0xff
	if err := VerifyInclusion(wrongRoot, 5, batch.LeafCount, leaves[5], proof); !errors.Is(err, ErrTamperedLeaf) {
		t.Errorf("VerifyInclusion with wrong root: got error %v, want errors.Is(_, ErrTamperedLeaf)", err)
	}
}

func TestVerifyInclusionTamperedProof(t *testing.T) {
	t.Parallel()

	leaves := batchLeaves(8)
	batch, err := NewBatch(BatchID{}, 1, 1, leaves)
	if err != nil {
		t.Fatalf("NewBatch: got error %v, want nil", err)
	}
	proof, err := InclusionProof(batch, 5)
	if err != nil {
		t.Fatalf("InclusionProof(5): got error %v, want nil", err)
	}
	tampered := make([][]byte, len(proof))
	for i := range proof {
		tampered[i] = append([]byte(nil), proof[i]...)
	}
	tampered[0][1] ^= 0xff
	if err := VerifyInclusion(batch.Root, 5, batch.LeafCount, leaves[5], tampered); !errors.Is(err, ErrTamperedLeaf) {
		t.Errorf("VerifyInclusion with tampered proof hash: got error %v, want errors.Is(_, ErrTamperedLeaf)", err)
	}
}

func TestVerifyInclusionFlippedSide(t *testing.T) {
	t.Parallel()

	leaves := batchLeaves(8)
	batch, err := NewBatch(BatchID{}, 1, 1, leaves)
	if err != nil {
		t.Fatalf("NewBatch: got error %v, want nil", err)
	}
	proof, err := InclusionProof(batch, 5)
	if err != nil {
		t.Fatalf("InclusionProof(5): got error %v, want nil", err)
	}
	if len(proof) == 0 {
		t.Fatalf("expected non-empty proof for 8-leaf index 5, got 0 steps")
	}
	flipped := make([][]byte, len(proof))
	for i := range proof {
		flipped[i] = append([]byte(nil), proof[i]...)
	}
	if flipped[0][0] == sideLeft {
		flipped[0][0] = sideRight
	} else {
		flipped[0][0] = sideLeft
	}
	if err := VerifyInclusion(batch.Root, 5, batch.LeafCount, leaves[5], flipped); !errors.Is(err, ErrTamperedLeaf) {
		t.Errorf("VerifyInclusion with flipped side byte: got error %v, want errors.Is(_, ErrTamperedLeaf)", err)
	}
}

func TestVerifyInclusionMalformedProof(t *testing.T) {
	t.Parallel()

	leaves := batchLeaves(4)
	batch, err := NewBatch(BatchID{}, 1, 1, leaves)
	if err != nil {
		t.Fatalf("NewBatch: got error %v, want nil", err)
	}
	proof, err := InclusionProof(batch, 0)
	if err != nil {
		t.Fatalf("InclusionProof(0): got error %v, want nil", err)
	}
	if len(proof) == 0 {
		t.Fatalf("expected non-empty proof for 4-leaf index 0, got 0 steps")
	}
	malformed := make([][]byte, len(proof))
	for i := range proof {
		malformed[i] = append([]byte(nil), proof[i]...)
	}
	malformed[0] = malformed[0][:16]
	if err := VerifyInclusion(batch.Root, 0, batch.LeafCount, leaves[0], malformed); !errors.Is(err, ErrTamperedLeaf) {
		t.Errorf("VerifyInclusion with malformed proof element: got error %v, want errors.Is(_, ErrTamperedLeaf)", err)
	}
}

func TestVerifyInclusionTruncatedProof(t *testing.T) {
	t.Parallel()

	leaves := batchLeaves(8)
	batch, err := NewBatch(BatchID{}, 1, 1, leaves)
	if err != nil {
		t.Fatalf("NewBatch: got error %v, want nil", err)
	}
	proof, err := InclusionProof(batch, 5)
	if err != nil {
		t.Fatalf("InclusionProof(5): got error %v, want nil", err)
	}
	if len(proof) < 2 {
		t.Fatalf("expected proof of length >= 2 for 8-leaf index 5, got %d", len(proof))
	}
	truncated := proof[:len(proof)-1]
	if err := VerifyInclusion(batch.Root, 5, batch.LeafCount, leaves[5], truncated); !errors.Is(err, ErrTamperedLeaf) {
		t.Errorf("VerifyInclusion with truncated proof: got error %v, want errors.Is(_, ErrTamperedLeaf)", err)
	}
}

func TestBatchMetadata(t *testing.T) {
	t.Parallel()

	var id BatchID
	id[0] = 0x42
	leaves := batchLeaves(3)
	batch, err := NewBatch(id, 42, 7, leaves)
	if err != nil {
		t.Fatalf("NewBatch: got error %v, want nil", err)
	}
	if !ctEqual32(batch.ID, id) {
		t.Errorf("batch ID: got %x, want %x", batch.ID, id)
	}
	if batch.Sequence != 42 {
		t.Errorf("batch sequence: got %d, want %d", batch.Sequence, 42)
	}
	if batch.ProtocolVersion != 7 {
		t.Errorf("batch protocol version: got %d, want %d", batch.ProtocolVersion, 7)
	}
	if batch.LeafCount != 3 {
		t.Errorf("batch leaf count: got %d, want 3", batch.LeafCount)
	}
	if len(batch.Leaves) != 3 {
		t.Errorf("batch leaves length: got %d, want 3", len(batch.Leaves))
	}
	for i, leaf := range leaves {
		if !ctEqual32(batch.Leaves[i], leaf) {
			t.Errorf("batch leaf %d: got %x, want %x", i, batch.Leaves[i], leaf)
		}
	}
}

func TestBatchLeafIndependence(t *testing.T) {
	t.Parallel()

	leaves := batchLeaves(4)
	batch, err := NewBatch(BatchID{}, 1, 1, leaves)
	if err != nil {
		t.Fatalf("NewBatch: got error %v, want nil", err)
	}
	root := batch.Root
	leaves[0][0] ^= 0xff
	leaves = append(leaves, hasher.Sum([]byte("extra")))
	if batch.LeafCount != 4 {
		t.Errorf("batch leaf count after mutation: got %d, want 4", batch.LeafCount)
	}
	if !ctEqual32(batch.Root, root) {
		t.Errorf("batch root changed after caller mutation: got %x, want %x", batch.Root, root)
	}
	if err := VerifyInclusion(batch.Root, 0, batch.LeafCount, batch.Leaves[0], mustProof(t, batch, 0)); err != nil {
		t.Errorf("VerifyInclusion after caller mutation: got error %v, want nil", err)
	}
}

// mustProof is a helper that fails the test on InclusionProof error.
func mustProof(t *testing.T, b *Batch, index uint64) [][]byte {
	t.Helper()
	proof, err := InclusionProof(b, index)
	if err != nil {
		t.Fatalf("InclusionProof(%d): got error %v, want nil", index, err)
	}
	return proof
}

func TestBatchRebuiltTree(t *testing.T) {
	t.Parallel()

	leaves := batchLeaves(6)
	batch, err := NewBatch(BatchID{}, 1, 1, leaves)
	if err != nil {
		t.Fatalf("NewBatch: got error %v, want nil", err)
	}
	// Simulate a deserialized batch: exported fields set, tree nil.
	rebuilt := &Batch{
		ID:              batch.ID,
		Sequence:        batch.Sequence,
		ProtocolVersion: batch.ProtocolVersion,
		Leaves:          batch.Leaves,
		Root:            batch.Root,
		LeafCount:       batch.LeafCount,
	}
	for i := 0; i < 6; i++ {
		proof, err := InclusionProof(rebuilt, uint64(i))
		if err != nil {
			t.Fatalf("InclusionProof(%d) on rebuilt batch: got error %v, want nil", i, err)
		}
		if err := VerifyInclusion(rebuilt.Root, uint64(i), rebuilt.LeafCount, leaves[i], proof); err != nil {
			t.Errorf("VerifyInclusion for index %d on rebuilt batch: got error %v, want nil", i, err)
		}
	}
}

func TestBatchConcurrentAccess(t *testing.T) {
	t.Parallel()

	const size = 50
	leaves := batchLeaves(size)
	batch, err := NewBatch(BatchID{}, 1, 1, leaves)
	if err != nil {
		t.Fatalf("NewBatch with %d leaves: got error %v, want nil", size, err)
	}
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for j := 0; j < 25; j++ {
				index := uint64((g*7 + j*3) % size)
				proof, err := InclusionProof(batch, index)
				if err != nil {
					t.Errorf("InclusionProof(%d) from goroutine %d: got error %v, want nil", index, g, err)
					return
				}
				if err := VerifyInclusion(batch.Root, index, batch.LeafCount, leaves[index], proof); err != nil {
					t.Errorf("VerifyInclusion for index %d from goroutine %d: got error %v, want nil", index, g, err)
					return
				}
			}
		}(g)
	}
	wg.Wait()
}
