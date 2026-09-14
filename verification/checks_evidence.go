package verification

import (
	"crypto/subtle"
	"encoding/hex"
	"fmt"

	"github.com/bperin/trust/crypto/hash"
	"github.com/bperin/trust/evidence"
)

// CheckEvidence verifies the supplied content of every attestation
// evidence reference: the content keyed by the evidence's canonical
// hash must hash to the evidence's stored content hash.
func checkEvidence(ctx *checkContext) error {
	for i := range ctx.in.Attestation.Evidence {
		ev := &ctx.in.Attestation.Evidence[i]
		eh, err := evidence.CanonicalHash(ev)
		if err != nil {
			return fmt.Errorf("verification: evidence %d: %w: %v", i, ErrEvidenceIntegrity, err)
		}
		content, ok := ctx.in.Evidence[hex.EncodeToString(eh[:])]
		if !ok {
			return fmt.Errorf("verification: evidence %d: %w: no supplied content", i, ErrEvidenceIntegrity)
		}
		sum := hash.NewSHA256().Sum(content)
		if subtle.ConstantTimeCompare(sum[:], ev.ContentHash) != 1 {
			return fmt.Errorf("verification: evidence %d: %w: content hash mismatch", i, ErrEvidenceIntegrity)
		}
	}
	return nil
}

// CheckProvenance verifies the transported provenance trace against
// the trace rebuilt from the inputs.
func checkProvenance(ctx *checkContext) error {
	if err := VerifyProvenance(ctx.prov, ctx.in); err != nil {
		return fmt.Errorf("verification: provenance: %w", err)
	}
	return nil
}

// CheckCommitment verifies external commitment proofs. With no
// commitment checker configured the check is skipped.
func checkCommitment(ctx *checkContext) error {
	if ctx.e.commitmentChecker == nil {
		return errSkipCheck
	}
	for _, proof := range ctx.in.Commitments {
		if err := ctx.e.commitmentChecker.Verify(proof, ctx.in); err != nil {
			return fmt.Errorf("verification: commitment %q: %w: %v", proof.ID, ErrCommitmentInvalid, err)
		}
	}
	return nil
}

// defaultChecks returns the fixed ordered check registry: structural
// through commitment, in pipeline order.
func defaultChecks() []checkSpec {
	return []checkSpec{
		{ID: CheckStructural, run: checkStructural},
		{ID: CheckSignature, run: checkSignature},
		{ID: CheckAuthorization, run: checkAuthorization},
		{ID: CheckAuthorityProof, run: checkAuthorityProof},
		{ID: CheckChainLink, run: checkChainLink},
		{ID: CheckRootAuthority, run: checkRootAuthority},
		{ID: CheckTemporal, run: checkTemporal},
		{ID: CheckRevocation, run: checkRevocation},
		{ID: CheckIdentity, run: checkIdentity},
		{ID: CheckKeyBinding, run: checkKeyBinding},
		{ID: CheckEvidence, run: checkEvidence},
		{ID: CheckProvenance, run: checkProvenance},
		{ID: CheckCommitment, run: checkCommitment},
	}
}
