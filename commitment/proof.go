package commitment

import (
	"bytes"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"

	"github.com/bperin/trust/merkle"
)

// Proof is an [RFC 6962] §2.1.1 audit path proving one leaf is committed in a tree of TreeSize leaves.
type Proof struct {
	Index    int
	TreeSize int
	Steps    []merkle.ProofStep
}

// InclusionProof returns the [RFC 6962] §2.1.1 audit path for obj's canonical hash in c.
func InclusionProof(c *Commitment, obj TrustObject) (Proof, error) {
	if c == nil {
		return Proof{}, ErrNilCommitment
	}
	if obj == nil {
		return Proof{}, ErrNilObject
	}
	leaf, err := LeafHash(obj)
	if err != nil {
		return Proof{}, fmt.Errorf("commitment: inclusion proof: %w", err)
	}
	index := sort.Search(len(c.LeafHashes), func(i int) bool {
		return bytes.Compare(c.LeafHashes[i][:], leaf[:]) >= 0
	})
	if index >= len(c.LeafHashes) || subtle.ConstantTimeCompare(c.LeafHashes[index][:], leaf[:]) != 1 {
		return Proof{}, ErrObjectNotCommitted
	}
	tree, err := merkle.New(leafBytes(c.LeafHashes))
	if err != nil {
		return Proof{}, fmt.Errorf("commitment: inclusion proof: %w", err)
	}
	path, err := tree.Proof(index)
	if err != nil {
		return Proof{}, fmt.Errorf("commitment: inclusion proof: %w", err)
	}
	return Proof{Index: index, TreeSize: c.Size, Steps: path.Steps}, nil
}

// VerifyInclusion re-derives obj's leaf and verifies the [RFC 6962] §2.1.1 audit path p against root.
func VerifyInclusion(root [32]byte, p Proof, obj TrustObject) error {
	leaf, err := LeafHash(obj)
	if err != nil {
		return fmt.Errorf("commitment: verify inclusion: %w", err)
	}
	elements := make([][]byte, len(p.Steps))
	for i, step := range p.Steps {
		side := byte(0x00)
		if step.IsRight {
			side = 0x01
		}
		elem := make([]byte, 1, 33)
		elem[0] = side
		elements[i] = append(elem, step.Hash[:]...)
	}
	if err := merkle.VerifyInclusion(root, uint64(p.Index), uint64(p.TreeSize), leaf, elements); err != nil {
		return fmt.Errorf("%w: %w", ErrInclusionFailed, err)
	}
	return nil
}

// proofJSON is the hex wire DTO of a Proof; each step hash renders as lowercase hex.
type proofJSON struct {
	Index    int             `json:"index"`
	TreeSize int             `json:"treeSize"`
	Steps    []proofStepJSON `json:"steps"`
}

// proofStepJSON is the wire DTO of one merkle.ProofStep.
type proofStepJSON struct {
	Hash    string `json:"hash"`
	IsRight bool   `json:"isRight"`
}

// MarshalJSON encodes p as its hex DTO; each step hash becomes a lowercase hex string.
func (p *Proof) MarshalJSON() ([]byte, error) {
	if p == nil {
		return []byte("null"), nil
	}
	dto := proofJSON{Index: p.Index, TreeSize: p.TreeSize}
	if p.Steps != nil {
		dto.Steps = make([]proofStepJSON, len(p.Steps))
		for i, step := range p.Steps {
			dto.Steps[i] = proofStepJSON{
				Hash:    hex.EncodeToString(step.Hash[:]),
				IsRight: step.IsRight,
			}
		}
	}
	return json.Marshal(dto)
}

// UnmarshalJSON decodes the hex DTO, rejecting malformed or wrong-length hex for every step hash.
func (p *Proof) UnmarshalJSON(b []byte) error {
	var dto proofJSON
	if err := json.Unmarshal(b, &dto); err != nil {
		return fmt.Errorf("commitment: decode proof JSON: %w", err)
	}
	var steps []merkle.ProofStep
	if dto.Steps != nil {
		steps = make([]merkle.ProofStep, len(dto.Steps))
		for i, s := range dto.Steps {
			h, err := decodeHash(s.Hash)
			if err != nil {
				return fmt.Errorf("commitment: decode proof steps[%d]: %w", i, err)
			}
			steps[i] = merkle.ProofStep{Hash: h, IsRight: s.IsRight}
		}
	}
	p.Index = dto.Index
	p.TreeSize = dto.TreeSize
	p.Steps = steps
	return nil
}
