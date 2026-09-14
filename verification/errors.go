package verification

import "errors"

// Trust failure sentinels: the closed taxonomy of verification
// failures; every Failure.Err wraps exactly one, matched with errors.Is.
var (
	ErrSignatureMismatch    = errors.New("verification: signature mismatch")
	ErrSignatureKeyMismatch = errors.New("verification: signing key does not match attestation algorithm")
	ErrAuthorityInvalid     = errors.New("verification: authority invalid")
	ErrChainBroken          = errors.New("verification: delegation chain broken")
	ErrNotRootAuthority     = errors.New("verification: chain does not end at a root authority")
	ErrDelegationDepth      = errors.New("verification: delegation depth exceeded")
	ErrCapabilityNotGranted = errors.New("verification: capability not granted")
	ErrScopeViolation       = errors.New("verification: scope violation")
	ErrNotYetValid          = errors.New("verification: not yet valid")
	ErrExpired              = errors.New("verification: expired")
	ErrRevoked              = errors.New("verification: revoked")
	ErrSuperseded           = errors.New("verification: superseded")
	ErrIdentityUnresolved   = errors.New("verification: identity unresolved")
	ErrKeyBinding           = errors.New("verification: key binding mismatch")
	ErrEvidenceIntegrity    = errors.New("verification: evidence integrity failure")
	ErrProvenanceMismatch   = errors.New("verification: provenance mismatch")
	ErrCommitmentInvalid    = errors.New("verification: commitment invalid")
	ErrStructural           = errors.New("verification: structural validation failed")
)

// Programmer sentinels: invalid inputs, not trust failures; they never
// appear in Result.Failures.
var (
	ErrNilAttestation = errors.New("verification: nil attestation")
	ErrNilSigningKey  = errors.New("verification: nil signing key")
	ErrEmptyChain     = errors.New("verification: empty authority chain")
	ErrNilProvenance  = errors.New("verification: nil provenance")
)
