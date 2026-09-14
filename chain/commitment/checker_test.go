package commitment

import (
	"encoding/json"
	"errors"
	"math/big"
	"testing"

	"github.com/bperin/trust/verification"
)

func TestChecker_VerifySuccess(t *testing.T) {
	a := mustAnchor(t, 1, "0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC")
	root := [32]byte{0x42}
	p := makeProof(t, a, root, 10)

	value, err := json.Marshal(p)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	c := &Checker{Anchor: a, Provider: nil}
	if err := c.Verify(verification.CommitmentProof{ID: "test", Value: value}, verification.Inputs{}); err != nil {
		t.Fatalf("Checker.Verify: %v", err)
	}
}

func TestChecker_VerifyRootMismatch(t *testing.T) {
	a := mustAnchor(t, 1, "0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC")
	root := [32]byte{0x42}
	p := makeProof(t, a, root, 10)

	value, _ := json.Marshal(p)

	// On-chain mode: the provider returns a root that differs from
	// the proof's root, yielding ErrRootMismatch.
	sp := &scriptedProvider{
		blockNumberResult: 15,
		receiptResult:     &Receipt{Status: 1, TransactionHash: "0x" + repeat("a", 64)},
		rootResult:        [32]byte{0x99},
	}
	c := &Checker{Anchor: a, Provider: sp}

	err := c.Verify(verification.CommitmentProof{ID: "test", Value: value}, verification.Inputs{})
	if !errors.Is(err, ErrRootMismatch) {
		t.Errorf("err = %v, want ErrRootMismatch", err)
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
	p := CommitmentProof{Root: [32]byte{0x42}, ChainID: big.NewInt(1)}
	value, _ := json.Marshal(p)

	err := c.Verify(verification.CommitmentProof{ID: "test", Value: value}, verification.Inputs{})
	if !errors.Is(err, ErrNilAnchor) {
		t.Errorf("err = %v, want ErrNilAnchor", err)
	}
}
