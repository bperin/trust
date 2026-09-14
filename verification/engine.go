package verification

import (
	"errors"
	"time"
)

// errSkipCheck signals a check that does not apply to the inputs; the
// engine records CheckSkipped rather than CheckFailed.
var errSkipCheck = errors.New("verification: check skipped")

// Engine runs the ordered verification pipeline over Inputs. An Engine
// is immutable after NewEngine and safe for concurrent Verify calls.
type Engine struct {
	clock             func() time.Time
	binder            KeyBinder
	commitmentChecker CommitmentChecker
	checks            []checkSpec
}

// checkFunc runs one check against the context, returning an error to
// record a failure.
type checkFunc func(*checkContext) error

// checkSpec binds a check to its pipeline identifier.
type checkSpec struct {
	ID  CheckID
	run checkFunc
}

// checkContext carries the per-Verify state checks read. Check
// implementations must not mutate it beyond setting hop.
type checkContext struct {
	in   Inputs
	now  time.Time
	prov *Provenance
	e    *Engine

	// hop is the offending Chain index a hop-scoped check sets before
	// returning an error; -1 otherwise.
	hop int
}

// checkPrerequisites maps each check to the checks that must pass
// before it runs; a check whose prerequisite failed is recorded as
// CheckSkipped so the failure list holds the root cause.
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

// Verify runs the full offline verification pipeline over in. It
// returns an error only for programmer errors — nil attestation, nil
// signing key, empty chain, or a provenance build failure; all trust
// failures land in the returned Result's Failures. Verify never
// mutates the engine and is safe for concurrent use.
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
