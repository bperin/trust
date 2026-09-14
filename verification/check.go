package verification

// CheckID identifies one check in the verification pipeline.
type CheckID int

// Check IDs in pipeline order; the numeric values are the wire form.
const (
	CheckStructural     CheckID = 1
	CheckSignature      CheckID = 2
	CheckAuthorization  CheckID = 3
	CheckAuthorityProof CheckID = 4
	CheckChainLink      CheckID = 5
	CheckRootAuthority  CheckID = 6
	CheckTemporal       CheckID = 7
	CheckRevocation     CheckID = 8
	CheckIdentity       CheckID = 9
	CheckKeyBinding     CheckID = 10
	CheckEvidence       CheckID = 11
	CheckProvenance     CheckID = 12
	CheckCommitment     CheckID = 13
)

// String returns the check's stable lowercase name.
func (id CheckID) String() string {
	switch id {
	case CheckStructural:
		return "structural"
	case CheckSignature:
		return "signature"
	case CheckAuthorization:
		return "authorization"
	case CheckAuthorityProof:
		return "authority_proof"
	case CheckChainLink:
		return "chain_link"
	case CheckRootAuthority:
		return "root_authority"
	case CheckTemporal:
		return "temporal"
	case CheckRevocation:
		return "revocation"
	case CheckIdentity:
		return "identity"
	case CheckKeyBinding:
		return "key_binding"
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

// Check statuses; CheckSkipped records no failure — its prerequisite already failed.
const (
	CheckPassed  CheckStatus = 1
	CheckFailed  CheckStatus = 2
	CheckSkipped CheckStatus = 3
)

// CheckResult records the outcome of one pipeline check.
type CheckResult struct {
	ID     CheckID
	Status CheckStatus
	Err    error // non-nil only when Status is CheckFailed
}

// Failure is one trust failure: the check, the governing sentinel, the offending hop, and detail text.
type Failure struct {
	Check  CheckID
	Err    error // wraps exactly one governing sentinel via %w
	Hop    int   // chain index for hop-scoped checks, -1 otherwise
	Detail string
}

// Result is the outcome of a verification run; Valid == (len(Failures)==0), set at assembly.
type Result struct {
	Valid      bool
	Provenance *Provenance
	Checks     []CheckResult
	Failures   []Failure
}

// consistent reports whether r satisfies the Valid invariant.
func (r Result) consistent() bool {
	return r.Valid == (len(r.Failures) == 0)
}
