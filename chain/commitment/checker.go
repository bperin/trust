package commitment

import (
	"context"
	"encoding/json"
	"fmt"

	merklecommitment "github.com/bperin/trust/commitment"
	"github.com/bperin/trust/verification"
)

// Checker adapts the commitment package to the verification engine's
// CommitmentChecker interface. It is the only file in chain/commitment
// that imports the verification package.
type Checker struct {
	Anchor   *Anchor
	Provider Provider
}

// BoundProof binds an anchored root to the attestation and terminal authority being verified.
type BoundProof struct {
	Anchor            CommitmentProof         `json:"anchor"`
	Attestation       *merklecommitment.Proof `json:"attestation"`
	TerminalAuthority *merklecommitment.Proof `json:"terminalAuthority"`
}

// Verify validates an anchored root and its inclusion proofs against the supplied verification inputs.
func (c *Checker) Verify(proof verification.CommitmentProof, in verification.Inputs) error {
	if in.Attestation == nil || len(in.Chain) == 0 || in.Chain[len(in.Chain)-1].Authority == nil {
		return fmt.Errorf("commitment: %w: attestation or terminal authority is missing", ErrBindingMismatch)
	}

	var bound BoundProof
	if err := json.Unmarshal(proof.Value, &bound); err != nil {
		return fmt.Errorf("commitment: malformed proof: %w", err)
	}
	if err := Verify(context.Background(), c.Anchor, bound.Anchor.Root, bound.Anchor, c.Provider); err != nil {
		return err
	}
	if bound.Attestation == nil || bound.TerminalAuthority == nil {
		return fmt.Errorf("commitment: %w: inclusion proof is missing", ErrBindingMismatch)
	}
	if err := merklecommitment.VerifyInclusion(
		bound.Anchor.Root,
		*bound.Attestation,
		merklecommitment.NewAttestationObject(in.Attestation),
	); err != nil {
		return fmt.Errorf("commitment: %w: attestation: %v", ErrBindingMismatch, err)
	}
	if err := merklecommitment.VerifyInclusion(
		bound.Anchor.Root,
		*bound.TerminalAuthority,
		merklecommitment.NewAuthorityObject(in.Chain[len(in.Chain)-1].Authority),
	); err != nil {
		return fmt.Errorf("commitment: %w: terminal authority: %v", ErrBindingMismatch, err)
	}
	return nil
}

// Compile-time interface check.
var _ verification.CommitmentChecker = (*Checker)(nil)
