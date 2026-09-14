package commitment

import (
	"bytes"
	"sort"
)

// sortLeaves orders leaves ascending by bytewise lexicographic order in place, so identical object sets always produce identical roots.
func sortLeaves(leaves [][32]byte) {
	sort.Slice(leaves, func(i, j int) bool {
		return bytes.Compare(leaves[i][:], leaves[j][:]) < 0
	})
}

// rejectDuplicates returns ErrDuplicateObject when two adjacent leaves are equal; leaves must already be sorted by sortLeaves. bytes.Equal is sufficient — these are non-secret digests compared inside a pure function; constant-time comparison applies only to the commitment root check in VerifyCommitment.
func rejectDuplicates(leaves [][32]byte) error {
	for i := 1; i < len(leaves); i++ {
		if bytes.Equal(leaves[i-1][:], leaves[i][:]) {
			return ErrDuplicateObject
		}
	}
	return nil
}
