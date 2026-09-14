package commitment

import (
	"bytes"
	"crypto/subtle"
	"fmt"

	"github.com/bperin/trust/merkle"
)

// Build returns a Commitment over the canonical hashes of objects: sorted ascending, duplicate-free, with Root from [RFC 6962] §2.1 merkle.New over the sorted leaves.
func Build(objects []TrustObject) (*Commitment, error) {
	if len(objects) == 0 {
		return nil, fmt.Errorf("commitment: build: %w", ErrEmptyObjects)
	}
	leaves := make([][32]byte, len(objects))
	for i, obj := range objects {
		h, err := LeafHash(obj)
		if err != nil {
			return nil, fmt.Errorf("commitment: build: object %d: %w", i, err)
		}
		leaves[i] = h
	}
	sortLeaves(leaves)
	if err := rejectDuplicates(leaves); err != nil {
		return nil, fmt.Errorf("commitment: build: %w", err)
	}
	tree, err := merkle.New(leafBytes(leaves))
	if err != nil {
		return nil, fmt.Errorf("commitment: build: %w", err)
	}
	var root [32]byte
	copy(root[:], tree.Root())
	return &Commitment{
		Root:       root,
		Size:       len(objects),
		LeafHashes: leaves,
		Algorithm:  AlgorithmRFC6962SHA256,
	}, nil
}

// VerifyCommitment recomputes the [RFC 6962] §2.1 root of c.LeafHashes and compares it against c.Root in constant time.
func VerifyCommitment(c *Commitment) error {
	// Check order is deliberate: nil and algorithm gate whether the
	// document is interpreted at all; structural checks (empty, size)
	// run before ordering checks so a malformed shape is reported
	// before its contents are judged; the root recomputation runs
	// last because it is the most expensive check.
	if c == nil {
		return ErrNilCommitment
	}
	if c.Algorithm != AlgorithmRFC6962SHA256 {
		return fmt.Errorf("commitment: verify: algorithm %q: %w", c.Algorithm, ErrAlgorithmMismatch)
	}
	if c.Size == 0 || len(c.LeafHashes) == 0 {
		return fmt.Errorf("commitment: verify: %w", ErrEmptyCommitment)
	}
	if c.Size != len(c.LeafHashes) {
		return fmt.Errorf("commitment: verify: size %d, leaves %d: %w", c.Size, len(c.LeafHashes), ErrSizeMismatch)
	}
	for i := 1; i < len(c.LeafHashes); i++ {
		if bytes.Compare(c.LeafHashes[i-1][:], c.LeafHashes[i][:]) > 0 {
			return fmt.Errorf("commitment: verify: leaf %d: %w", i, ErrUnsortedLeaves)
		}
	}
	for i := 1; i < len(c.LeafHashes); i++ {
		if c.LeafHashes[i-1] == c.LeafHashes[i] {
			return fmt.Errorf("commitment: verify: leaf %d: %w", i, ErrDuplicateLeaf)
		}
	}
	tree, err := merkle.New(leafBytes(c.LeafHashes))
	if err != nil {
		return fmt.Errorf("commitment: verify: %w", err)
	}
	if subtle.ConstantTimeCompare(tree.Root(), c.Root[:]) != 1 {
		return fmt.Errorf("commitment: verify: %w", ErrRootMismatch)
	}
	return nil
}

// leafBytes views each 32-byte leaf as a []byte for merkle.New; merkle.New hashes leaf data without retaining it, so no copy is needed.
func leafBytes(leaves [][32]byte) [][]byte {
	b := make([][]byte, len(leaves))
	for i := range leaves {
		b[i] = leaves[i][:]
	}
	return b
}
