package commitment

import (
	"context"
	"math/big"
	"strings"
	"testing"
)

func TestE2E_Offline(t *testing.T) {
	w := mustWallet(t)
	walletAddr, _ := w.Address()
	a := mustAnchor(t, 1, "0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC")
	root := [32]byte{0x42}

	// Publish the root against a fake provider.
	receipt := &Receipt{
		Status:           1,
		BlockHash:        "0xblockhash",
		BlockNumber:      10,
		TransactionHash:  "0x" + strings.Repeat("a", 64),
		TransactionIndex: 0,
		GasUsed:          21000,
		ContractAddress:  "",
		Logs:             []interface{}{},
	}
	fp := &fakeProvider{sendTxResult: "0xtxhash", receiptResult: receipt}
	pubReceipt, err := Publish(context.Background(), a, root, w, fp,
		WithNonce(1), WithGasLimit(21000), WithGasPrice(big.NewInt(1e9)),
	)
	if err != nil {
		t.Fatalf("Publish: %v", err)
	}

	// Build the EIP-712 proof from the returned receipt.
	proof, err := Proof(root, a, pubReceipt, w)
	if err != nil {
		t.Fatalf("Proof: %v", err)
	}

	// Verify offline (nil provider).
	if err := Verify(context.Background(), a, root, proof, nil); err != nil {
		t.Fatalf("Verify offline: %v", err)
	}

	// The recovered signer must equal the wallet address.
	recovered, err := VerifyCommitmentProof(proof)
	if err != nil {
		t.Fatalf("VerifyCommitmentProof: %v", err)
	}
	if recovered != walletAddr {
		t.Errorf("recovered = %x, want %x", recovered, walletAddr)
	}
}

func TestE2E_OnChain(t *testing.T) {
	w := mustWallet(t)
	walletAddr, _ := w.Address()
	a := mustAnchor(t, 1, "0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC")
	root := [32]byte{0x42}

	receipt := &Receipt{
		Status:           1,
		BlockHash:        "0xblockhash",
		BlockNumber:      10,
		TransactionHash:  "0x" + strings.Repeat("a", 64),
		TransactionIndex: 0,
		GasUsed:          21000,
		ContractAddress:  "",
		Logs:             []interface{}{},
	}
	fp := &fakeProvider{sendTxResult: "0xtxhash", receiptResult: receipt}
	pubReceipt, err := Publish(context.Background(), a, root, w, fp,
		WithNonce(1), WithGasLimit(21000), WithGasPrice(big.NewInt(1e9)),
	)
	if err != nil {
		t.Fatalf("Publish: %v", err)
	}

	proof, err := Proof(root, a, pubReceipt, w)
	if err != nil {
		t.Fatalf("Proof: %v", err)
	}

	// On-chain verify: provider returns the committed root and a
	// head above the proof's block number.
	sp := &scriptedProvider{
		blockNumberResult: proof.BlockNumber + 5,
		receiptResult:     &Receipt{Status: 1, TransactionHash: "0x" + strings.Repeat("a", 64)},
		rootResult:        root,
	}
	if err := Verify(context.Background(), a, root, proof, sp); err != nil {
		t.Fatalf("Verify on-chain: %v", err)
	}

	// The on-chain root read must equal the committed root.
	if sp.rootResult != root {
		t.Errorf("on-chain root = %x, want %x", sp.rootResult, root)
	}

	// Recovered signer must equal the wallet address.
	recovered, err := VerifyCommitmentProof(proof)
	if err != nil {
		t.Fatalf("VerifyCommitmentProof: %v", err)
	}
	if recovered != walletAddr {
		t.Errorf("recovered = %x, want %x", recovered, walletAddr)
	}
}

func TestE2E_BlockNumberExact(t *testing.T) {
	w := mustWallet(t)
	a := mustAnchor(t, 1, "0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC")
	root := [32]byte{0x42}

	receipt := &Receipt{
		Status:          1,
		BlockNumber:     10,
		TransactionHash: "0x" + strings.Repeat("a", 64),
	}
	fp := &fakeProvider{sendTxResult: "0xhash", receiptResult: receipt}
	pubReceipt, err := Publish(context.Background(), a, root, w, fp,
		WithGasLimit(1), WithGasPrice(big.NewInt(1)),
	)
	if err != nil {
		t.Fatalf("Publish: %v", err)
	}

	proof, err := Proof(root, a, pubReceipt, w)
	if err != nil {
		t.Fatalf("Proof: %v", err)
	}

	// head == proof.BlockNumber exactly → inclusive, should pass.
	sp := &scriptedProvider{
		blockNumberResult: proof.BlockNumber,
		receiptResult:     &Receipt{Status: 1, TransactionHash: "0x" + strings.Repeat("a", 64)},
		rootResult:        root,
	}
	if err := Verify(context.Background(), a, root, proof, sp); err != nil {
		t.Fatalf("Verify with head==blockNumber: %v", err)
	}
}

func TestE2E_TamperedProofRootOffline(t *testing.T) {
	w := mustWallet(t)
	a := mustAnchor(t, 1, "0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC")
	root := [32]byte{0x42}

	receipt := &Receipt{
		Status:          1,
		BlockNumber:     10,
		TransactionHash: "0x" + strings.Repeat("a", 64),
	}
	fp := &fakeProvider{sendTxResult: "0xhash", receiptResult: receipt}
	pubReceipt, err := Publish(context.Background(), a, root, w, fp,
		WithGasLimit(1), WithGasPrice(big.NewInt(1)),
	)
	if err != nil {
		t.Fatalf("Publish: %v", err)
	}

	proof, err := Proof(root, a, pubReceipt, w)
	if err != nil {
		t.Fatalf("Proof: %v", err)
	}

	// Tamper the expected root — offline Verify must detect the mismatch.
	wrongRoot := root
	wrongRoot[0] ^= 0xff
	err = Verify(context.Background(), a, wrongRoot, proof, nil)
	if !strings.Contains(err.Error(), "root mismatch") {
		t.Errorf("err = %v, want root mismatch", err)
	}
}
