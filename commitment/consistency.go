package commitment

import (
	"crypto/subtle"
	"fmt"

	"github.com/bperin/trust/merkle"
)

// ConsistencyProof is an [RFC 6962] §2.1.2 proof that the first OldSize leaves of a NewSize-leaf commitment are unchanged.
type ConsistencyProof struct {
	OldSize int
	NewSize int
	Steps   []merkle.ProofStep
}

// ConsistencyProofBetween returns the [RFC 6962] §2.1.2 consistency proof between old and next, requiring old.LeafHashes to be a strict prefix of next.LeafHashes.
func ConsistencyProofBetween(old, next *Commitment) (ConsistencyProof, error) {
	if old == nil || next == nil {
		return ConsistencyProof{}, ErrNilCommitment
	}
	if old.Size <= 0 || old.Size >= next.Size {
		return ConsistencyProof{}, fmt.Errorf("commitment: consistency proof: %w", ErrInvalidRange)
	}
	if len(old.LeafHashes) < old.Size || len(next.LeafHashes) < old.Size {
		return ConsistencyProof{}, fmt.Errorf("commitment: consistency proof: %w", ErrNotPrefix)
	}
	for i := 0; i < old.Size; i++ {
		if subtle.ConstantTimeCompare(old.LeafHashes[i][:], next.LeafHashes[i][:]) != 1 {
			return ConsistencyProof{}, fmt.Errorf("commitment: consistency proof: leaf %d: %w", i, ErrNotPrefix)
		}
	}
	tree, err := merkle.New(leafBytes(next.LeafHashes))
	if err != nil {
		return ConsistencyProof{}, fmt.Errorf("commitment: consistency proof: %w", err)
	}
	path, err := tree.ConsistencyProof(old.Size, next.Size)
	if err != nil {
		return ConsistencyProof{}, fmt.Errorf("commitment: consistency proof: %w", err)
	}
	return ConsistencyProof{OldSize: old.Size, NewSize: next.Size, Steps: path.Steps}, nil
}

// VerifyConsistency verifies that p proves the oldRoot commitment is an append-only prefix of the newRoot commitment per [RFC 6962] §2.1.2.
func VerifyConsistency(oldRoot, newRoot [32]byte, p ConsistencyProof) error {
	if !merkle.VerifyConsistency(oldRoot[:], newRoot[:], p.OldSize, p.NewSize, merkle.AuditPath{Steps: p.Steps}) {
		return fmt.Errorf("commitment: verify consistency: %w", ErrInclusionFailed)
	}
	return nil
}
