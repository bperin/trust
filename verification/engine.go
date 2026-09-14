package verification

import (
	"errors"
	"time"
)

// errSkipCheck signals a non-applicable check; the engine records CheckSkipped.
var errSkipCheck = errors.New("verification: check skipped")

// Engine runs the ordered verification pipeline; immutable after NewEngine and safe for concurrent Verify.
type Engine struct {
	clock             func() time.Time
	binder            KeyBinder
	commitmentChecker CommitmentChecker
	checks            []checkSpec
}

// checkFunc runs one check against the context; an error records a failure.
type checkFunc func(*checkContext) error

// checkSpec binds a check to its pipeline identifier.
type checkSpec struct {
	ID  CheckID
	run checkFunc
}

// checkContext carries the per-Verify state checks read; only hop may be set.
type checkContext struct {
	in   Inputs
	now  time.Time
	prov *Provenance
	e    *Engine

	// hop is the offending Chain index a hop-scoped check sets; -1 otherwise.
	hop int
}

// checkPrerequisites gates each check on earlier checks; a failed
// prerequisite records CheckSkipped so Failures holds the root cause.
var checkPrerequisites = map[CheckID][]CheckID{
	CheckSignature:      {CheckStructural},
	CheckAuthorization:  {CheckSignature},
	CheckAuthorityProof: {CheckAuthorization},
	CheckChainLink:      {CheckAuthorityProof},
	CheckRootAuthority:  {CheckChainLink},
	CheckTemporal:       {CheckStructural},
	CheckRevocation:     {CheckStructural},
	CheckIdentity:       {CheckStructural},
	CheckKeyBinding:     {CheckSignature},
	CheckEvidence:       {CheckStructural},
	CheckProvenance:     {CheckStructural},
	CheckCommitment:     {CheckStructural},
}

// Verify runs the offline pipeline; errors are programmer errors only — trust failures land in Result.Failures.
func (e *Engine) Verify(in Inputs) (*Result, error) {
	if in.Attestation == nil {
		return nil, ErrNilAttestation
	}
	if in.SigningKey == nil {
		return nil, ErrNilSigningKey
	}
	if len(in.Chain) == 0 {
		return nil, ErrEmptyChain
	}
	now := in.Now
	if now.IsZero() {
		now = e.clock()
	}
	prov, err := BuildProvenance(in)
	if err != nil {
		return nil, err
	}

	ctx := &checkContext{in: in, now: now, prov: prov, e: e, hop: -1}
	checks := make([]CheckResult, 0, len(e.checks))
	var failures []Failure
	failed := make(map[CheckID]bool)

	for _, spec := range e.checks {
		if prerequisiteFailed(spec.ID, failed) {
			checks = append(checks, CheckResult{ID: spec.ID, Status: CheckSkipped})
			continue
		}
		ctx.hop = -1
		err := spec.run(ctx)
		switch {
		case errors.Is(err, errSkipCheck):
			checks = append(checks, CheckResult{ID: spec.ID, Status: CheckSkipped})
		case err != nil:
			failed[spec.ID] = true
			checks = append(checks, CheckResult{ID: spec.ID, Status: CheckFailed, Err: err})
			failures = append(failures, Failure{Check: spec.ID, Err: err, Hop: ctx.hop, Detail: err.Error()})
		default:
			checks = append(checks, CheckResult{ID: spec.ID, Status: CheckPassed})
		}
	}
	return &Result{Valid: len(failures) == 0, Provenance: prov, Checks: checks, Failures: failures}, nil
}

// prerequisiteFailed reports whether any prerequisite of id failed.
func prerequisiteFailed(id CheckID, failed map[CheckID]bool) bool {
	for _, prereq := range checkPrerequisites[id] {
		if failed[prereq] {
			return true
		}
	}
	return false
}
