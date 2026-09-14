package verification

// CheckID identifies one check in the verification pipeline, in
// pipeline order.
type CheckID int

// Check IDs in pipeline order. The numeric values are the wire form.
const (
	// CheckStructural validates attestation structure.
	CheckStructural CheckID = 1

	// CheckSignature verifies the attestation signature.
	CheckSignature CheckID = 2

	// CheckAuthorization verifies the attestation is authorized by the
	// leaf authority.
	CheckAuthorization CheckID = 3

	// CheckAuthorityProof verifies every hop authority's proof.
	CheckAuthorityProof CheckID = 4

	// CheckChainLink verifies parent references and subset delegation
	// between adjacent hops.
	CheckChainLink CheckID = 5

	// CheckRootAuthority verifies the chain terminates at a root.
	CheckRootAuthority CheckID = 6

	// CheckTemporal verifies validity windows at the verification
	// time.
	CheckTemporal CheckID = 7

	// CheckRevocation verifies every hop authority is active.
	CheckRevocation CheckID = 8

	// CheckIdentity resolves the root authority subject's DID.
	CheckIdentity CheckID = 9

	// CheckKeyBinding verifies signing keys bind to their claimed
	// identities.
	CheckKeyBinding CheckID = 10

	// CheckEvidence verifies supplied evidence content against
	// content hashes.
	CheckEvidence CheckID = 11

	// CheckProvenance verifies the transported provenance trace
	// against the rebuilt one.
	CheckProvenance CheckID = 12

	// CheckCommitment verifies external commitment proofs.
	CheckCommitment CheckID = 13
)

// String returns the stable lowercase check name.
func (id CheckID) String() string {
	switch id {
	case CheckStructural:
		return "structural"
	case CheckSignature:
		return "signature"
	case CheckAuthorization:
		return "authorization"
	case CheckAuthorityProof:
		return "authorityProof"
	case CheckChainLink:
		return "chainLink"
	case CheckRootAuthority:
		return "rootAuthority"
	case CheckTemporal:
		return "temporal"
	case CheckRevocation:
		return "revocation"
	case CheckIdentity:
		return "identity"
	case CheckKeyBinding:
		return "keyBinding"
	case CheckEvidence:
		return "evidence"
	case CheckProvenance:
		return "provenance"
	case CheckCommitment:
		return "commitment"
	default:
		return "unknown"
	}
}

// CheckStatus is the outcome of a single pipeline check.
type CheckStatus int

// Check statuses. CheckSkipped is distinct from CheckFailed: a skipped
// check records no failure — its prerequisite already failed.
const (
	// CheckPassed marks a check that ran and passed.
	CheckPassed CheckStatus = 1

	// CheckFailed marks a check whose run produced a failure.
	CheckFailed CheckStatus = 2

	// CheckSkipped marks a check not run because a prerequisite
	// failed.
	CheckSkipped CheckStatus = 3
)

// CheckResult records the outcome of one pipeline check.
type CheckResult struct {
	// ID is the check's pipeline identifier.
	ID CheckID

	// Status is the check outcome.
	Status CheckStatus

	// Err is the check's error when Status is CheckFailed.
	Err error
}

// Failure is one trust failure: the check that detected it, the
// governing sentinel wrapped in Err, the offending chain hop, and the
// error text.
type Failure struct {
	// Check is the check that produced the failure.
	Check CheckID

	// Err wraps exactly one governing sentinel via %w.
	Err error

	// Hop is the Chain index for hop-scoped checks, -1 otherwise.
	Hop int

	// Detail is the error text at failure time.
	Detail string
}

// Result is the outcome of a verification run. Valid is set once at
// assembly time to len(Failures)==0.
type Result struct {
	// Valid reports whether every check passed.
	Valid bool

	// Provenance is the rebuilt provenance trace.
	Provenance *Provenance

	// Checks is the per-check outcome record, pipeline order.
	Checks []CheckResult

	// Failures is the failure list; empty when Valid.
	Failures []Failure
}
