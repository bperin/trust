package commitment

import (
	"context"
	"errors"
	"math/big"
	"strings"
	"testing"

	"github.com/bperin/trust/chain/ethereum"
)

// scriptedProvider is a fully scriptable Provider for verify tests.
type scriptedProvider struct {
	blockNumberResult uint64
	blockNumberErr    error

	receiptResult *Receipt
	receiptErr    error
	lastTxHash    string

	rootResult [32]byte
	rootErr    error
	lastRoot   struct {
		contract ethereum.Address
		blockTag string
	}
}

func (s *scriptedProvider) SendTx(ctx context.Context, rawTx []byte) (string, error) {
	return "", nil
}
func (s *scriptedProvider) Receipt(ctx context.Context, txHash string) (*Receipt, error) {
	s.lastTxHash = txHash
	return s.receiptResult, s.receiptErr
}
func (s *scriptedProvider) BlockNumber(ctx context.Context) (uint64, error) {
	return s.blockNumberResult, s.blockNumberErr
}
func (s *scriptedProvider) Root(ctx context.Context, contract ethereum.Address, blockTag string) ([32]byte, error) {
	s.lastRoot.contract = contract
	s.lastRoot.blockTag = blockTag
	return s.rootResult, s.rootErr
}

func makeProof(t *testing.T, a *Anchor, root [32]byte, blockNum uint64) CommitmentProof {
	t.Helper()
	w := mustWallet(t)
	r := mustReceipt("0x"+strings.Repeat("a", 64), blockNum)
	p, err := Proof(root, a, r, w)
	if err != nil {
		t.Fatalf("Proof: %v", err)
	}
	return p
}

func TestVerify_OnChainSuccess(t *testing.T) {
	a := mustAnchor(t, 1, "0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC")
	root := [32]byte{0x42}
	p := makeProof(t, a, root, 10)

	sp := &scriptedProvider{
		blockNumberResult: 15,
		receiptResult:     &Receipt{Status: 1, TransactionHash: "0x" + strings.Repeat("a", 64)},
		rootResult:        root,
	}

	if err := Verify(context.Background(), a, root, p, sp); err != nil {
		t.Fatalf("Verify: %v", err)
	}
}

func TestVerify_OfflineSuccess(t *testing.T) {
	a := mustAnchor(t, 1, "0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC")
	root := [32]byte{0x42}
	p := makeProof(t, a, root, 10)

	if err := Verify(context.Background(), a, root, p, nil); err != nil {
		t.Fatalf("Verify offline: %v", err)
	}
}

func TestVerify_ChainIDMismatch(t *testing.T) {
	a := mustAnchor(t, 1, "0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC")
	root := [32]byte{0x42}
	p := makeProof(t, a, root, 10)

	t.Run("wrong chain ID", func(t *testing.T) {
		bad := p
		bad.ChainID = big.NewInt(2)
		err := Verify(context.Background(), a, root, bad, nil)
		if !errors.Is(err, ErrChainIDMismatch) {
			t.Errorf("err = %v, want ErrChainIDMismatch", err)
		}
	})

	t.Run("nil chain ID", func(t *testing.T) {
		bad := p
		bad.ChainID = nil
		err := Verify(context.Background(), a, root, bad, nil)
		if !errors.Is(err, ErrChainIDMismatch) {
			t.Errorf("err = %v, want ErrChainIDMismatch", err)
		}
	})

	t.Run("wrong contract", func(t *testing.T) {
		bad := p
		bad.Contract = ethereum.Address{0xff}
		err := Verify(context.Background(), a, root, bad, nil)
		if !errors.Is(err, ErrChainIDMismatch) {
			t.Errorf("err = %v, want ErrChainIDMismatch", err)
		}
	})
}

func TestVerify_OfflineRootMismatch(t *testing.T) {
	a := mustAnchor(t, 1, "0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC")
	root := [32]byte{0x42}
	p := makeProof(t, a, root, 10)

	wrongRoot := [32]byte{0x99}
	err := Verify(context.Background(), a, wrongRoot, p, nil)
	if !errors.Is(err, ErrRootMismatch) {
		t.Errorf("err = %v, want ErrRootMismatch", err)
	}
}

func TestVerify_OnChainRootMismatch(t *testing.T) {
	a := mustAnchor(t, 1, "0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC")
	root := [32]byte{0x42}
	p := makeProof(t, a, root, 10)

	sp := &scriptedProvider{
		blockNumberResult: 15,
		receiptResult:     &Receipt{Status: 1, TransactionHash: "0x" + strings.Repeat("a", 64)},
		rootResult:        [32]byte{0x99}, // different on-chain root
	}

	err := Verify(context.Background(), a, root, p, sp)
	if !errors.Is(err, ErrRootMismatch) {
		t.Errorf("err = %v, want ErrRootMismatch", err)
	}
}

func TestVerify_NotConfirmed(t *testing.T) {
	a := mustAnchor(t, 1, "0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC")
	root := [32]byte{0x42}

	t.Run("head below block number", func(t *testing.T) {
		p := makeProof(t, a, root, 20)
		sp := &scriptedProvider{blockNumberResult: 10}
		err := Verify(context.Background(), a, root, p, sp)
		if !errors.Is(err, ErrNotConfirmed) {
			t.Errorf("err = %v, want ErrNotConfirmed", err)
		}
	})

	t.Run("status 0", func(t *testing.T) {
		p := makeProof(t, a, root, 10)
		sp := &scriptedProvider{
			blockNumberResult: 15,
			receiptResult:     &Receipt{Status: 0, TransactionHash: "0x" + strings.Repeat("a", 64)},
		}
		err := Verify(context.Background(), a, root, p, sp)
		if !errors.Is(err, ErrNotConfirmed) {
			t.Errorf("err = %v, want ErrNotConfirmed", err)
		}
	})

	t.Run("nil receipt", func(t *testing.T) {
		p := makeProof(t, a, root, 10)
		sp := &scriptedProvider{
			blockNumberResult: 15,
			receiptResult:     nil,
		}
		err := Verify(context.Background(), a, root, p, sp)
		if !errors.Is(err, ErrNotConfirmed) {
			t.Errorf("err = %v, want ErrNotConfirmed", err)
		}
	})
}

func TestVerify_BadSignature(t *testing.T) {
	a := mustAnchor(t, 1, "0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC")
	root := [32]byte{0x42}
	p := makeProof(t, a, root, 10)

	// Truncate the signature to make VerifyCommitmentProof fail.
	bad := p
	bad.Signature = bad.Signature[:64]

	err := Verify(context.Background(), a, root, bad, nil)
	if !errors.Is(err, ErrBadSignature) {
		t.Errorf("err = %v, want ErrBadSignature", err)
	}
}

func TestVerify_NilAnchor(t *testing.T) {
	root := [32]byte{0x42}
	p := CommitmentProof{Root: root, ChainID: big.NewInt(1)}
	err := Verify(context.Background(), nil, root, p, nil)
	if !errors.Is(err, ErrNilAnchor) {
		t.Errorf("err = %v, want ErrNilAnchor", err)
	}
}

func TestVerify_BlockNumberBoundary(t *testing.T) {
	a := mustAnchor(t, 1, "0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC")
	root := [32]byte{0x42}
	p := makeProof(t, a, root, 10)

	// head == p.BlockNumber exactly → inclusive, should pass.
	sp := &scriptedProvider{
		blockNumberResult: 10,
		receiptResult:     &Receipt{Status: 1, TransactionHash: "0x" + strings.Repeat("a", 64)},
		rootResult:        root,
	}
	if err := Verify(context.Background(), a, root, p, sp); err != nil {
		t.Fatalf("Verify with head==blockNumber: %v", err)
	}
}

func TestVerify_BlockNumberZero(t *testing.T) {
	a := mustAnchor(t, 1, "0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC")
	root := [32]byte{0x42}
	p := makeProof(t, a, root, 0)

	sp := &scriptedProvider{
		blockNumberResult: 5,
		receiptResult:     &Receipt{Status: 1, TransactionHash: "0x" + strings.Repeat("a", 64)},
		rootResult:        root,
	}
	if err := Verify(context.Background(), a, root, p, sp); err != nil {
		t.Fatalf("Verify: %v", err)
	}
	// FormatQuantity(0) yields "0x0".
	if sp.lastRoot.blockTag != "0x0" {
		t.Errorf("blockTag = %q, want %q", sp.lastRoot.blockTag, "0x0")
	}
}

func TestVerify_CancelledContext(t *testing.T) {
	a := mustAnchor(t, 1, "0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC")
	root := [32]byte{0x42}
	p := makeProof(t, a, root, 10)

	sp := &scriptedProvider{blockNumberErr: context.Canceled}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := Verify(ctx, a, root, p, sp)
	if !errors.Is(err, context.Canceled) {
		t.Errorf("err = %v, want context.Canceled", err)
	}
}

func TestVerify_RootLastByteMismatch(t *testing.T) {
	a := mustAnchor(t, 1, "0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC")
	root := [32]byte{0x42}
	p := makeProof(t, a, root, 10)

	wrongRoot := root
	wrongRoot[31] ^= 0x01
	err := Verify(context.Background(), a, wrongRoot, p, nil)
	if !errors.Is(err, ErrRootMismatch) {
		t.Errorf("err = %v, want ErrRootMismatch", err)
	}
}
