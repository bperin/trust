package commitment

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/bperin/trust/verification"
)

// Checker adapts the commitment package to the verification engine's
// CommitmentChecker interface. It is the only file in chain/commitment
// that imports the verification package.
type Checker struct {
	Anchor   *Anchor
	Provider Provider
}

// Verify decodes the JSON-encoded CommitmentProof from proof.Value and
// delegates to the package-level Verify. When Provider is nil the
// offline path runs.
func (c *Checker) Verify(proof verification.CommitmentProof, _ verification.Inputs) error {
	var cp CommitmentProof
	if err := json.Unmarshal(proof.Value, &cp); err != nil {
		return fmt.Errorf("commitment: malformed proof: %w", err)
	}
	return Verify(context.Background(), c.Anchor, cp.Root, cp, c.Provider)
}

// Compile-time interface check.
var _ verification.CommitmentChecker = (*Checker)(nil)
