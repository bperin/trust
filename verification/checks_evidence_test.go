package verification

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"testing"

	"github.com/bperin/trust/crypto/hash"
	"github.com/bperin/trust/evidence"
)

func TestCheckEvidence_Pass(t *testing.T) {
	t.Parallel()
	f := buildFixture(t, []byte("evidence material 0"))
	if _, err := runSingleCheck(t, f, checkEvidence); err != nil {
		t.Errorf("supplied evidence failed: %v", err)
	}
}

func TestCheckEvidenceFIPS1804(t *testing.T) {
	t.Parallel()
	// "abc" per [FIPS 180-4].
	sum := sha256.Sum256([]byte("abc"))
	f := buildFixture(t, []byte("abc"))
	ev := &f.att.Evidence[0]
	if subtle.ConstantTimeCompare(sum[:], ev.ContentHash) != 1 {
		t.Fatal("fixture evidence hash is not the FIPS 180-4 abc vector")
	}
	if _, err := runSingleCheck(t, f, checkEvidence); err != nil {
		t.Errorf("FIPS vector evidence failed: %v", err)
	}
}

func TestCheckEvidence_ContentHashMismatch(t *testing.T) {
	t.Parallel()
	f := buildFixture(t, []byte("evidence material 0"))
	in := f.inputs()
	in.Evidence[hashRefHex(mustEvidenceHash(t, f))] = []byte("tampered content")
	prov, _ := BuildProvenance(in)
	ctx := &checkContext{in: in, now: f.now, prov: prov, e: NewEngine(), hop: -1}
	err := checkEvidence(ctx)
	if !errors.Is(err, ErrEvidenceIntegrity) {
		t.Errorf("err = %v, want ErrEvidenceIntegrity", err)
	}
}

func TestCheckEvidence_MissingContent(t *testing.T) {
	t.Parallel()
	f := buildFixture(t, []byte("evidence material 0"))
	in := f.inputs()
	in.Evidence = nil
	prov, _ := BuildProvenance(in)
	ctx := &checkContext{in: in, now: f.now, prov: prov, e: NewEngine(), hop: -1}
	err := checkEvidence(ctx)
	if !errors.Is(err, ErrEvidenceIntegrity) {
		t.Errorf("err = %v, want ErrEvidenceIntegrity", err)
	}
}

func TestCheckEvidence_NoEvidencePasses(t *testing.T) {
	t.Parallel()
	f := buildFixture(t)
	if _, err := runSingleCheck(t, f, checkEvidence); err != nil {
		t.Errorf("attestation without evidence should pass: %v", err)
	}
}

func TestCheckProvenance_Pass(t *testing.T) {
	t.Parallel()
	f := buildFixture(t)
	if _, err := runSingleCheck(t, f, checkProvenance); err != nil {
		t.Errorf("provenance check failed: %v", err)
	}
}

func TestCheckProvenance_Mismatch(t *testing.T) {
	t.Parallel()
	f := buildFixture(t)
	in := f.inputs()
	prov, _ := BuildProvenance(in)
	prov.Links[0].Ref = "0000"
	ctx := &checkContext{in: in, now: f.now, prov: prov, e: NewEngine(), hop: -1}
	err := checkProvenance(ctx)
	if !errors.Is(err, ErrProvenanceMismatch) {
		t.Errorf("err = %v, want ErrProvenanceMismatch", err)
	}
}

// stubChecker is a configurable CommitmentChecker.
type stubChecker struct {
	err error
}

func (c *stubChecker) Verify(proof CommitmentProof, in Inputs) error { return c.err }

func TestCheckCommitment_SkippedWithoutChecker(t *testing.T) {
	t.Parallel()
	f := buildFixture(t)
	ctx, err := runSingleCheck(t, f, checkCommitment)
	if !errors.Is(err, errSkipCheck) {
		t.Errorf("err = %v, want skip signal", err)
	}
	if ctx.hop != -1 {
		t.Errorf("Hop = %d, want -1", ctx.hop)
	}
}

func TestCheckCommitment_Pass(t *testing.T) {
	t.Parallel()
	f := buildFixture(t)
	in := f.inputs()
	prov, _ := BuildProvenance(in)
	e := NewEngine(WithCommitmentChecker(&stubChecker{}))
	ctx := &checkContext{in: in, now: f.now, prov: prov, e: e, hop: -1}
	if err := checkCommitment(ctx); err != nil {
		t.Errorf("commitment check failed: %v", err)
	}
}

func TestCheckCommitment_Failing(t *testing.T) {
	t.Parallel()
	f := buildFixture(t)
	in := f.inputs()
	in.Commitments = []CommitmentProof{{ID: "c1", Value: []byte("proof")}}
	prov, _ := BuildProvenance(in)
	e := NewEngine(WithCommitmentChecker(&stubChecker{err: errors.New("rejected")}))
	ctx := &checkContext{in: in, now: f.now, prov: prov, e: e, hop: -1}
	err := checkCommitment(ctx)
	if !errors.Is(err, ErrCommitmentInvalid) {
		t.Errorf("err = %v, want ErrCommitmentInvalid", err)
	}
}

func TestDefaultChecks_Order(t *testing.T) {
	t.Parallel()
	checks := defaultChecks()
	if len(checks) != 13 {
		t.Fatalf("defaultChecks length = %d, want 13", len(checks))
	}
	for i, spec := range checks {
		if int(spec.ID) != i+1 {
			t.Errorf("check %d has ID %d, want %d", i, spec.ID, i+1)
		}
		if spec.run == nil {
			t.Errorf("check %d has nil run", i)
		}
	}
}

func TestVerifyValidPath(t *testing.T) {
	t.Parallel()
	f := buildFixture(t)
	res, err := NewEngine().Verify(f.inputs())
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !res.Valid {
		for _, fail := range res.Failures {
			t.Errorf("failure: check=%v hop=%d err=%v", fail.Check, fail.Hop, fail.Err)
		}
		t.Fatal("valid fixture reported invalid")
	}
	if len(res.Failures) != 0 {
		t.Errorf("failures = %d, want 0", len(res.Failures))
	}
	if len(res.Checks) != 13 {
		t.Fatalf("checks = %d, want 13", len(res.Checks))
	}
	for _, cr := range res.Checks {
		if cr.ID == CheckCommitment {
			if cr.Status != CheckSkipped {
				t.Errorf("commitment status = %v, want CheckSkipped", cr.Status)
			}
			continue
		}
		if cr.Status != CheckPassed {
			t.Errorf("check %v status = %v, want CheckPassed", cr.ID, cr.Status)
		}
	}
}

// mustEvidenceHash returns the canonical hash of the fixture's first
// evidence entry.
func mustEvidenceHash(t *testing.T, f *fixture) [32]byte {
	t.Helper()
	h, err := evidence.CanonicalHash(&f.att.Evidence[0])
	if err != nil {
		t.Fatalf("evidence hash: %v", err)
	}
	return h
}

func TestSHA256Primitive(t *testing.T) {
	t.Parallel()
	sum := hash.NewSHA256().Sum([]byte("abc"))
	want := sha256.Sum256([]byte("abc"))
	if subtle.ConstantTimeCompare(sum[:], want[:]) != 1 {
		t.Error("crypto/hash SHA-256 diverges from stdlib")
	}
	_ = context.Background()
}
