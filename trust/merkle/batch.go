package merkle

import (
	"errors"
	"fmt"
)

// Sentinel errors returned by NewBatch and InclusionProof. Check them with
// errors.Is.
var (
	// ErrEmptyBatch is returned by NewBatch when the leaf list is empty.
	// [RFC 6962] §2.1 requires at least one leaf to define a Merkle root.
	ErrEmptyBatch = errors.New("merkle: empty batch")
	// ErrWrongLeafIndex is returned by InclusionProof when the requested
	// leaf index is not smaller than the batch leaf count. [RFC 6962] §2.1.1
	// audit paths are defined only for valid leaf indices.
	ErrWrongLeafIndex = errors.New("merkle: wrong leaf index")
)

// BatchID identifies a committed [RFC 6962] §2.1 Merkle batch. It is a
// 32-byte content-addressed identifier — typically the Merkle root or a
// hash derived from the batch metadata and root.
type BatchID [32]byte

// Batch is a committed [RFC 6962] §2.1 Merkle batch of canonical attestation
// hashes. The leaves are ordered canonical hashes (SHA-256 of the canonical
// attestation bytes), and Root is the Merkle Tree Hash over those leaves.
// The same ordered leaves always produce the same root; the tree shape is
// fixed by the batch size, not by input order ambiguity.
type Batch struct {
	// ID is the content-addressed batch identifier.
	ID BatchID
	// Sequence is the monotonic batch sequence number.
	Sequence uint64
	// ProtocolVersion is the commitment protocol version.
	ProtocolVersion uint
	// Leaves is the ordered list of canonical attestation hashes committed
	// by this batch. NewBatch stores a defensive copy so later mutation of
	// the caller's slice cannot alter the batch.
	Leaves [][32]byte
	// Root is the [RFC 6962] §2.1 Merkle Tree Hash over Leaves.
	Root [32]byte
	// LeafCount is the number of leaves in the batch.
	LeafCount uint64

	// tree is the underlying [RFC 6962] §2.1 tree, retained so InclusionProof
	// can delegate to Tree.Proof without rebuilding. It is nil for batches
	// constructed without NewBatch (e.g. deserialized); InclusionProof
	// rebuilds the tree on demand in that case.
	tree *Tree
}

// NewBatch implements [RFC 6962] §2.1 — it builds a Merkle batch over the
// ordered canonical attestation hashes. Each hash is passed as leaf data to
// the tree, which applies the 0x00 leaf domain separator (SHA-256(0x00 ||
// hash)). The same ordered leaves always produce the same root. An empty
// leaf list is rejected with ErrEmptyBatch.
func NewBatch(id BatchID, sequence uint64, protocolVersion uint, leaves [][32]byte) (*Batch, error) {
	if len(leaves) == 0 {
		return nil, fmt.Errorf("merkle: new batch: %w", ErrEmptyBatch)
	}
	raw := make([][]byte, len(leaves))
	for i := range leaves {
		raw[i] = leaves[i][:]
	}
	tree, err := New(raw)
	if err != nil {
		return nil, fmt.Errorf("merkle: new batch: %w", err)
	}
	stored := make([][32]byte, len(leaves))
	copy(stored, leaves)
	var root [32]byte
	copy(root[:], tree.Root())
	return &Batch{
		ID:              id,
		Sequence:        sequence,
		ProtocolVersion: protocolVersion,
		Leaves:          stored,
		Root:            root,
		LeafCount:       uint64(len(leaves)),
		tree:            tree,
	}, nil
}

// InclusionProof implements [RFC 6962] §2.1.1 — it generates the inclusion
// proof for the leaf at index against the batch root.
//
// The proof is a list of serialized sibling hashes, one per tree level from
// leaf to root. Each element is 33 bytes: a side byte (0x00 for a left
// sibling, 0x01 for a right sibling) followed by the 32-byte sibling hash.
// Levels where the node is promoted unchanged (no sibling) contribute no
// element, matching the [RFC 6962] §2.1 audit path.
//
// An index that is not smaller than LeafCount is rejected with
// ErrWrongLeafIndex.
func InclusionProof(b *Batch, index uint64) ([][]byte, error) {
	if index >= b.LeafCount {
		return nil, fmt.Errorf("merkle: inclusion proof for index %d in batch of %d leaves: %w", index, b.LeafCount, ErrWrongLeafIndex)
	}
	tree := b.tree
	if tree == nil {
		raw := make([][]byte, len(b.Leaves))
		for i := range b.Leaves {
			raw[i] = b.Leaves[i][:]
		}
		var err error
		tree, err = New(raw)
		if err != nil {
			return nil, fmt.Errorf("merkle: inclusion proof: %w", err)
		}
	}
	path, err := tree.Proof(int(index))
	if err != nil {
		return nil, fmt.Errorf("merkle: inclusion proof: %w", err)
	}
	proof := make([][]byte, len(path.Steps))
	for i, step := range path.Steps {
		elem := make([]byte, proofElemLen)
		if step.IsRight {
			elem[0] = sideRight
		} else {
			elem[0] = sideLeft
		}
		copy(elem[1:], step.Hash[:])
		proof[i] = elem
	}
	return proof, nil
}
