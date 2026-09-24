package commitment

import (
	"encoding/json"
	"errors"
	"math/big"
	"testing"

	"github.com/bperin/trust/attestation"
	"github.com/bperin/trust/authority"
	merklecommitment "github.com/bperin/trust/commitment"
	"github.com/bperin/trust/verification"
)

func TestChecker_VerifySuccess(t *testing.T) {
	a := mustAnchor(t, 1, "0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC")
	in, value := boundCheckerProof(t, a)

	c := &Checker{Anchor: a, Provider: nil}
	if err := c.Verify(verification.CommitmentProof{ID: "test", Value: value}, in); err != nil {
		t.Fatalf("Checker.Verify: %v", err)
	}
}

func TestChecker_VerifyRootMismatch(t *testing.T) {
	a := mustAnchor(t, 1, "0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC")
	in, value := boundCheckerProof(t, a)
	var bound BoundProof
	if err := json.Unmarshal(value, &bound); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	// On-chain mode: the provider returns a root that differs from
	// the proof's root, yielding ErrRootMismatch.
	sp := &scriptedProvider{
		blockNumberResult: 15,
		receiptResult:     &Receipt{Status: 1, TransactionHash: "0x" + repeat("a", 64), BlockNumber: bound.Anchor.BlockNumber},
		rootResult:        [32]byte{0x99},
	}
	c := &Checker{Anchor: a, Provider: sp}

	err := c.Verify(verification.CommitmentProof{ID: "test", Value: value}, in)
	if !errors.Is(err, ErrRootMismatch) {
		t.Errorf("err = %v, want ErrRootMismatch", err)
	}
}

func TestChecker_RejectsAttestationNotInCommittedRoot(t *testing.T) {
	a := mustAnchor(t, 1, "0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC")
	in, value := boundCheckerProof(t, a)
	in.Attestation = &attestation.Attestation{Issuer: "did:trust:substituted"}

	err := (&Checker{Anchor: a}).Verify(verification.CommitmentProof{ID: "test", Value: value}, in)
	if !errors.Is(err, ErrBindingMismatch) {
		t.Errorf("err = %v, want ErrBindingMismatch", err)
	}
}

func TestChecker_RejectsTerminalAuthorityNotInCommittedRoot(t *testing.T) {
	a := mustAnchor(t, 1, "0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC")
	in, value := boundCheckerProof(t, a)
	in.Chain[len(in.Chain)-1].Authority = &authority.Authority{Subject: "did:trust:substituted"}

	err := (&Checker{Anchor: a}).Verify(verification.CommitmentProof{ID: "test", Value: value}, in)
	if !errors.Is(err, ErrBindingMismatch) {
		t.Errorf("err = %v, want ErrBindingMismatch", err)
	}
}

func TestChecker_RejectsMissingInclusionProof(t *testing.T) {
	a := mustAnchor(t, 1, "0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC")
	in, value := boundCheckerProof(t, a)
	var bound BoundProof
	if err := json.Unmarshal(value, &bound); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	bound.Attestation = nil
	value, err := json.Marshal(bound)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	err = (&Checker{Anchor: a}).Verify(verification.CommitmentProof{ID: "test", Value: value}, in)
	if !errors.Is(err, ErrBindingMismatch) {
		t.Errorf("err = %v, want ErrBindingMismatch", err)
	}
}

func TestChecker_InvalidJSON(t *testing.T) {
	a := mustAnchor(t, 1, "0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC")
	c := &Checker{Anchor: a, Provider: nil}

	err := c.Verify(verification.CommitmentProof{ID: "test", Value: []byte("not json")}, verification.Inputs{})
	if err == nil {
		t.Error("err = nil, want non-nil for invalid JSON")
	}
}

func TestChecker_EmptyValue(t *testing.T) {
	a := mustAnchor(t, 1, "0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC")
	c := &Checker{Anchor: a, Provider: nil}

	err := c.Verify(verification.CommitmentProof{ID: "test", Value: nil}, verification.Inputs{})
	if err == nil {
		t.Error("err = nil, want non-nil for empty value")
	}
}

func TestChecker_NilAnchor(t *testing.T) {
	c := &Checker{Anchor: nil, Provider: nil}
	p := BoundProof{Anchor: CommitmentProof{Root: [32]byte{0x42}, ChainID: big.NewInt(1)}}
	value, _ := json.Marshal(p)

	in := verification.Inputs{Attestation: &attestation.Attestation{}, Chain: []verification.AuthorityHop{{Authority: &authority.Authority{}}}}
	err := c.Verify(verification.CommitmentProof{ID: "test", Value: value}, in)
	if !errors.Is(err, ErrNilAnchor) {
		t.Errorf("err = %v, want ErrNilAnchor", err)
	}
}

func boundCheckerProof(t *testing.T, a *Anchor) (verification.Inputs, []byte) {
	t.Helper()
	att := &attestation.Attestation{Issuer: "did:trust:issuer", AuthorityRef: "root"}
	terminal := &authority.Authority{Subject: "did:trust:root", Capabilities: []authority.Capability{authority.CapabilityAttest}}
	tree, err := merklecommitment.Build([]merklecommitment.TrustObject{
		merklecommitment.NewAttestationObject(att),
		merklecommitment.NewAuthorityObject(terminal),
	})
	if err != nil {
		t.Fatalf("build commitment: %v", err)
	}
	attestationProof, err := merklecommitment.InclusionProof(tree, merklecommitment.NewAttestationObject(att))
	if err != nil {
		t.Fatalf("attestation inclusion proof: %v", err)
	}
	terminalProof, err := merklecommitment.InclusionProof(tree, merklecommitment.NewAuthorityObject(terminal))
	if err != nil {
		t.Fatalf("terminal authority inclusion proof: %v", err)
	}
	anchorProof := makeProof(t, a, tree.Root, 10)
	value, err := json.Marshal(BoundProof{Anchor: anchorProof, Attestation: &attestationProof, TerminalAuthority: &terminalProof})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return verification.Inputs{Attestation: att, Chain: []verification.AuthorityHop{{Authority: terminal}}}, value
}
