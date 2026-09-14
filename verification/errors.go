package verification

import "errors"

// Trust failure sentinels — the closed taxonomy of verification
// failures. Every Failure.Err wraps exactly one of these; check with
// errors.Is. No two sentinels alias.
var (
	// ErrSignatureMismatch is the attestation signature does not
	// verify against the leaf signing key.
	ErrSignatureMismatch = errors.New("verification: signature mismatch")

	// ErrSignatureKeyMismatch is the leaf key's algorithm does not
	// match the attestation's declared algorithm.
	ErrSignatureKeyMismatch = errors.New("verification: signing key does not match attestation algorithm")

	// ErrAuthorityInvalid is an authority is malformed, mismatched,
	// inactive, or its proof does not verify.
	ErrAuthorityInvalid = errors.New("verification: authority invalid")

	// ErrChainBroken is a delegated authority's Parent reference does
	// not match the canonical hash of the next hop.
	ErrChainBroken = errors.New("verification: delegation chain broken")

	// ErrNotRootAuthority is the final hop of the chain still has a
	// parent — the chain does not terminate at a root.
	ErrNotRootAuthority = errors.New("verification: chain does not end at a root authority")

	// ErrDelegationDepth is the chain exceeds a delegation depth
	// bound.
	ErrDelegationDepth = errors.New("verification: delegation depth exceeded")

	// ErrCapabilityNotGranted is a capability is exercised that no
	// authority in the chain grants.
	ErrCapabilityNotGranted = errors.New("verification: capability not granted")

	// ErrScopeViolation is a claim or delegated scope exceeds the
	// granting authority's scope.
	ErrScopeViolation = errors.New("verification: scope violation")

	// ErrNotYetValid is the attestation or an authority is not yet
	// within its validity window.
	ErrNotYetValid = errors.New("verification: not yet valid")

	// ErrExpired is the attestation or an authority is past its
	// validity window.
	ErrExpired = errors.New("verification: expired")

	// ErrRevoked is an authority in the chain is revoked.
	ErrRevoked = errors.New("verification: revoked")

	// ErrSuperseded is an authority in the chain is superseded by a
	// newer authority.
	ErrSuperseded = errors.New("verification: superseded")

	// ErrIdentityUnresolved is the root authority subject's DID
	// cannot be resolved.
	ErrIdentityUnresolved = errors.New("verification: identity unresolved")

	// ErrKeyBinding is a signing key does not bind to the identity
	// that claims it.
	ErrKeyBinding = errors.New("verification: key binding mismatch")

	// ErrEvidenceIntegrity is supplied evidence content does not match
	// the attestation's evidence content hash, or is missing.
	ErrEvidenceIntegrity = errors.New("verification: evidence integrity failure")

	// ErrProvenanceMismatch is the transported provenance trace does
	// not match the trace rebuilt from the inputs.
	ErrProvenanceMismatch = errors.New("verification: provenance mismatch")

	// ErrCommitmentInvalid is an external commitment proof does not
	// verify.
	ErrCommitmentInvalid = errors.New("verification: commitment invalid")

	// ErrStructural is the attestation fails structural validation.
	ErrStructural = errors.New("verification: structural validation failed")
)

// Programmer sentinels: invalid Inputs, not trust failures. They never
// appear in Result.Failures.
var (
	// ErrNilAttestation is Inputs.Attestation is nil.
	ErrNilAttestation = errors.New("verification: nil attestation")

	// ErrNilSigningKey is Inputs.SigningKey is nil.
	ErrNilSigningKey = errors.New("verification: nil signing key")

	// ErrEmptyChain is Inputs.Chain is empty.
	ErrEmptyChain = errors.New("verification: empty authority chain")

	// ErrNilProvenance is a nil provenance where one is required.
	ErrNilProvenance = errors.New("verification: nil provenance")
)
