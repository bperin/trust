package commitment

import (
	"context"
	"errors"
	"math/big"
	"strings"
	"testing"
)

func TestNegative_AllSentinels(t *testing.T) {
	w := mustWallet(t)
	a := mustAnchor(t, 1, "0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC")
	root := [32]byte{0x42}
	goodReceipt := mustReceipt("0x"+strings.Repeat("a", 64), 10)

	cases := []struct {
		name     string
		sentinel error
		fn       func() error
	}{
		{
			name:     "ErrNilAnchor",
			sentinel: ErrNilAnchor,
			fn:       func() error { _, err := Proof(root, nil, goodReceipt, w); return err },
		},
		{
			name:     "ErrNilWallet",
			sentinel: ErrNilWallet,
			fn:       func() error { _, err := Proof(root, a, goodReceipt, nil); return err },
		},
		{
			name:     "ErrInvalidAnchor",
			sentinel: ErrInvalidAnchor,
			fn:       func() error { _, err := NewAnchor(big.NewInt(0), a.Contract); return err },
		},
		{
			name:     "ErrMissingTxParams",
			sentinel: ErrMissingTxParams,
			fn: func() error {
				_, err := Publish(context.Background(), a, root, w, &fakeProvider{},
					WithGasLimit(0), WithGasPrice(big.NewInt(1)))
				return err
			},
		},
		{
			name:     "ErrMalformedReceipt",
			sentinel: ErrMalformedReceipt,
			fn:       func() error { _, err := Proof(root, a, mustReceipt("0x1234", 10), w); return err },
		},
		{
			name:     "ErrChainIDMismatch",
			sentinel: ErrChainIDMismatch,
			fn: func() error {
				p := makeProof(t, a, root, 10)
				bad := p
				bad.ChainID = big.NewInt(2)
				return Verify(context.Background(), a, root, bad, nil)
			},
		},
		{
			name:     "ErrNotConfirmed",
			sentinel: ErrNotConfirmed,
			fn: func() error {
				p := makeProof(t, a, root, 10)
				sp := &scriptedProvider{
					blockNumberResult: 15,
					receiptResult:     &Receipt{Status: 0, TransactionHash: "0x" + strings.Repeat("a", 64)},
				}
				return Verify(context.Background(), a, root, p, sp)
			},
		},
		{
			name:     "ErrRootMismatch",
			sentinel: ErrRootMismatch,
			fn: func() error {
				p := makeProof(t, a, root, 10)
				wrongRoot := [32]byte{0x99}
				return Verify(context.Background(), a, wrongRoot, p, nil)
			},
		},
		{
			name:     "ErrBadSignature",
			sentinel: ErrBadSignature,
			fn: func() error {
				p := makeProof(t, a, root, 10)
				bad := p
				bad.Signature = bad.Signature[:64]
				return Verify(context.Background(), a, root, bad, nil)
			},
		},
		{
			name:     "ErrReceiptMismatch",
			sentinel: ErrReceiptMismatch,
			fn: func() error {
				p := makeProof(t, a, root, 10)
				sp := &scriptedProvider{
					blockNumberResult: 15,
					receiptResult:     &Receipt{Status: 1, TransactionHash: "0x" + strings.Repeat("b", 64), BlockNumber: 10},
				}
				return Verify(context.Background(), a, root, p, sp)
			},
		},
		{
			name:     "ErrRootGetterFailed",
			sentinel: ErrRootGetterFailed,
			fn: func() error {
				p := makeProof(t, a, root, 10)
				sp := &scriptedProvider{
					blockNumberResult: 15,
					receiptResult:     &Receipt{Status: 1, TransactionHash: "0x" + strings.Repeat("a", 64), BlockNumber: 10},
					rootResult:        [32]byte{},
					rootErr:           ErrRootGetterFailed,
				}
				return Verify(context.Background(), a, root, p, sp)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.fn()
			if err == nil {
				t.Fatalf("%s: err = nil, want non-nil", tc.name)
			}
			if !errors.Is(err, tc.sentinel) {
				t.Errorf("%s: err = %v, want %v", tc.name, err, tc.sentinel)
			}
		})
	}
}

func TestNegative_SentinelDistinctness(t *testing.T) {
	sentinels := []error{
		ErrNilAnchor, ErrNilWallet, ErrInvalidAnchor, ErrMissingTxParams,
		ErrMalformedReceipt, ErrReceiptMismatch, ErrChainIDMismatch, ErrNotConfirmed,
		ErrRootMismatch, ErrBadSignature, ErrRootGetterFailed,
	}
	for i, a := range sentinels {
		for j, b := range sentinels {
			if i == j {
				continue
			}
			if errors.Is(a, b) {
				t.Errorf("errors.Is(%v, %v) = true, want false", a, b)
			}
		}
	}
}
