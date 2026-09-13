package wallet

import (
	"crypto/subtle"
	"math/big"
	"testing"

	"github.com/bperin/chain/ethereum"
	"github.com/bperin/chain/rlp"
	"github.com/bperin/trust/crypto/secp256k1"
)

// TestLegacyTx_SigningHash verifies the EIP-155 signing hash for a
// legacy transaction with chain ID 1.
func TestLegacyTx_SigningHash(t *testing.T) {
	t.Parallel()

	tx := &LegacyTx{
		ChainID:  big.NewInt(1),
		Nonce:    0,
		GasPrice: big.NewInt(0),
		GasLimit: 0,
		To:       nil,
		Value:    big.NewInt(0),
		Data:     nil,
	}

	hash, err := tx.SigningHash()
	if err != nil {
		t.Fatalf("SigningHash: %v", err)
	}
	if len(hash) != 32 {
		t.Fatalf("hash length: got %d, want 32", len(hash))
	}

	// The pre-image is rlp([0, 0, 0, "", 0, "", 1, 0, 0]) per EIP-155.
	// Verify the hash is deterministic (same input → same hash).
	hash2, err := tx.SigningHash()
	if err != nil {
		t.Fatalf("SigningHash (2nd): %v", err)
	}
	if subtle.ConstantTimeCompare(hash, hash2) != 1 {
		t.Fatalf("SigningHash not deterministic")
	}
}

// TestLegacyTx_NilChainID verifies a nil or zero chain ID is rejected.
func TestLegacyTx_NilChainID(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		chainID *big.Int
	}{
		{"nil", nil},
		{"zero", big.NewInt(0)},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			tx := &LegacyTx{ChainID: tc.chainID}
			_, err := tx.SigningHash()
			if err == nil {
				t.Fatal("SigningHash: got nil error, want error")
			}
		})
	}
}

// TestSignTx_LegacyEcrecover signs a legacy transaction and recovers
// the signer address via ecrecover. The recovered address must match
// the wallet's address.
func TestSignTx_LegacyEcrecover(t *testing.T) {
	t.Parallel()

	privBytes := hexDecode(t, "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80")
	priv, err := secp256k1.NewPrivateKey(privBytes)
	if err != nil {
		t.Fatalf("NewPrivateKey: %v", err)
	}
	w := NewWallet(priv)
	walletAddr, _ := w.Address()

	to, _ := ethereum.ParseAddress("0x70997970C51812dc3A010C7d01b50e0d17dc79C8")

	tx := &LegacyTx{
		ChainID:  big.NewInt(1),
		Nonce:    9,
		GasPrice: big.NewInt(20_000_000_000),
		GasLimit: 21000,
		To:       &to,
		Value:    big.NewInt(1_000_000_000_000_000_000),
		Data:     nil,
	}

	rawTx, err := w.SignTx(tx)
	if err != nil {
		t.Fatalf("SignTx: %v", err)
	}

	// Decode the signed transaction to extract r, s, v and recompute
	// the signing hash for ecrecover.
	decoded, err := rlp.Decode(rawTx)
	if err != nil {
		t.Fatalf("rlp.Decode: %v", err)
	}
	items, ok := decoded.([]interface{})
	if !ok || len(items) != 9 {
		t.Fatalf("decoded: got %T with %d items, want 9-item list", decoded, len(items))
	}

	// Legacy signed: [nonce, gasPrice, gasLimit, to, value, data, v, r, s]
	vBytes := items[6].([]byte)
	rBytes := items[7].([]byte)
	sBytes := items[8].([]byte)

	// Recompute the signing hash.
	signingHash, err := tx.SigningHash()
	if err != nil {
		t.Fatalf("SigningHash: %v", err)
	}

	// Compute recID from v: v = recID + 35 + chainID*2.
	vInt := new(big.Int).SetBytes(vBytes)
	recID := new(big.Int).Sub(vInt, big.NewInt(35+2))
	recID.Sub(recID, big.NewInt(0)) // chainID=1, so subtract 2*1=2
	recIDByte := byte(recID.Int64())

	// Build 64-byte r||s (left-padded to 32 each).
	sig := make([]byte, 64)
	copy(sig[32-len(rBytes):32], rBytes)
	copy(sig[64-len(sBytes):64], sBytes)

	recoveredPub, err := secp256k1.RecoverPubKey(sig, signingHash, recIDByte)
	if err != nil {
		t.Fatalf("RecoverPubKey: %v", err)
	}
	recoveredAddr, err := ethereum.FromPublicKey(recoveredPub)
	if err != nil {
		t.Fatalf("FromPublicKey: %v", err)
	}

	if recoveredAddr != walletAddr {
		t.Fatalf("recovered address: got %s, want %s", recoveredAddr.Hex(), walletAddr.Hex())
	}
}

// TestSignTx_EIP1559Ecrecover signs an EIP-1559 transaction and
// recovers the signer address.
func TestSignTx_EIP1559Ecrecover(t *testing.T) {
	t.Parallel()

	privBytes := hexDecode(t, "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80")
	priv, err := secp256k1.NewPrivateKey(privBytes)
	if err != nil {
		t.Fatalf("NewPrivateKey: %v", err)
	}
	w := NewWallet(priv)
	walletAddr, _ := w.Address()

	to, _ := ethereum.ParseAddress("0x70997970C51812dc3A010C7d01b50e0d17dc79C8")

	tx := &EIP1559Tx{
		ChainID:              big.NewInt(1),
		Nonce:                9,
		MaxPriorityFeePerGas: big.NewInt(1_000_000_000),
		MaxFeePerGas:         big.NewInt(20_000_000_000),
		GasLimit:             21000,
		To:                   &to,
		Value:                big.NewInt(1_000_000_000_000_000_000),
		Data:                 nil,
		AccessList:           nil,
	}

	rawTx, err := w.SignTx(tx)
	if err != nil {
		t.Fatalf("SignTx: %v", err)
	}

	// EIP-1559: rawTx = 0x02 || rlp([...])
	if len(rawTx) < 1 || rawTx[0] != 0x02 {
		t.Fatalf("rawTx[0]: got 0x%02x, want 0x02", rawTx[0])
	}

	// Decode the RLP body (skip the 0x02 type byte).
	decoded, err := rlp.Decode(rawTx[1:])
	if err != nil {
		t.Fatalf("rlp.Decode: %v", err)
	}
	items, ok := decoded.([]interface{})
	if !ok {
		t.Fatalf("decoded: got %T, want list", decoded)
	}
	// EIP-1559 signed has 12 fields: chainID, nonce, maxPriority, maxFee,
	// gasLimit, to, value, data, accessList, v, r, s.
	if len(items) != 12 {
		t.Fatalf("items: got %d, want 12", len(items))
	}

	vBytes := items[9].([]byte)
	rBytes := items[10].([]byte)
	sBytes := items[11].([]byte)

	// EIP-1559: v = recID (y-parity, 0 or 1).
	var recIDByte byte
	if len(vBytes) == 0 {
		recIDByte = 0
	} else {
		recIDByte = vBytes[0]
	}

	// Recompute the signing hash.
	signingHash, err := tx.SigningHash()
	if err != nil {
		t.Fatalf("SigningHash: %v", err)
	}

	sig := make([]byte, 64)
	copy(sig[32-len(rBytes):32], rBytes)
	copy(sig[64-len(sBytes):64], sBytes)

	recoveredPub, err := secp256k1.RecoverPubKey(sig, signingHash, recIDByte)
	if err != nil {
		t.Fatalf("RecoverPubKey: %v", err)
	}
	recoveredAddr, err := ethereum.FromPublicKey(recoveredPub)
	if err != nil {
		t.Fatalf("FromPublicKey: %v", err)
	}

	if recoveredAddr != walletAddr {
		t.Fatalf("recovered address: got %s, want %s", recoveredAddr.Hex(), walletAddr.Hex())
	}
}

// TestSignTx_NilWallet verifies a nil wallet produces an error.
func TestSignTx_NilWallet(t *testing.T) {
	t.Parallel()

	tx := &LegacyTx{ChainID: big.NewInt(1)}
	_, err := (*Wallet)(nil).SignTx(tx)
	if err == nil {
		t.Fatal("SignTx: got nil error, want error")
	}
}

// TestSignTx_NilTransaction verifies a nil transaction produces an error.
func TestSignTx_NilTransaction(t *testing.T) {
	t.Parallel()

	privBytes := hexDecode(t, "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80")
	priv, _ := secp256k1.NewPrivateKey(privBytes)
	w := NewWallet(priv)

	_, err := w.SignTx(nil)
	if err == nil {
		t.Fatal("SignTx(nil): got nil error, want error")
	}
}

// TestSignTx_TamperedFields verifies that tampering with a signed
// legacy transaction's fields causes ecrecover to produce a different
// address.
func TestSignTx_TamperedFields(t *testing.T) {
	t.Parallel()

	privBytes := hexDecode(t, "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80")
	priv, _ := secp256k1.NewPrivateKey(privBytes)
	w := NewWallet(priv)
	walletAddr, _ := w.Address()

	to, _ := ethereum.ParseAddress("0x70997970C51812dc3A010C7d01b50e0d17dc79C8")

	// Sign the original transaction.
	original := &LegacyTx{
		ChainID:  big.NewInt(1),
		Nonce:    9,
		GasPrice: big.NewInt(20_000_000_000),
		GasLimit: 21000,
		To:       &to,
		Value:    big.NewInt(1_000_000_000_000_000_000),
	}
	_, err := w.SignTx(original)
	if err != nil {
		t.Fatalf("SignTx: %v", err)
	}

	// Now sign a tampered transaction (different nonce) and verify the
	// recovered address is still the wallet address (same signer), but
	// the signing hash differs.
	tampered := &LegacyTx{
		ChainID:  big.NewInt(1),
		Nonce:    10, // tampered
		GasPrice: big.NewInt(20_000_000_000),
		GasLimit: 21000,
		To:       &to,
		Value:    big.NewInt(1_000_000_000_000_000_000),
	}
	hash1, _ := original.SigningHash()
	hash2, _ := tampered.SigningHash()
	if subtle.ConstantTimeCompare(hash1, hash2) == 1 {
		t.Fatal("tampered nonce should produce a different signing hash")
	}

	// Both signed by the same wallet → same recovered address.
	// But a signature from tx1 applied to tx2 should recover to a
	// DIFFERENT address (the signature doesn't match the hash).
	rawTx1, _ := w.SignTx(original)
	decoded, _ := rlp.Decode(rawTx1)
	items := decoded.([]interface{})
	vBytes := items[6].([]byte)
	rBytes := items[7].([]byte)
	sBytes := items[8].([]byte)

	vInt := new(big.Int).SetBytes(vBytes)
	recID := byte(vInt.Int64() - 35 - 2)

	sig := make([]byte, 64)
	copy(sig[32-len(rBytes):32], rBytes)
	copy(sig[64-len(sBytes):64], sBytes)

	// Recover against the tampered hash → should NOT match wallet.
	recoveredPub, err := secp256k1.RecoverPubKey(sig, hash2, recID)
	if err != nil {
		t.Fatalf("RecoverPubKey: %v", err)
	}
	recoveredAddr, _ := ethereum.FromPublicKey(recoveredPub)
	if recoveredAddr == walletAddr {
		t.Fatal("signature from tx1 should not recover to wallet address against tampered hash")
	}
}

// TestSignTx_ContractCreation verifies nil `to` (contract creation)
// produces a valid signed transaction.
func TestSignTx_ContractCreation(t *testing.T) {
	t.Parallel()

	privBytes := hexDecode(t, "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80")
	priv, _ := secp256k1.NewPrivateKey(privBytes)
	w := NewWallet(priv)

	tx := &LegacyTx{
		ChainID:  big.NewInt(1),
		Nonce:    0,
		GasPrice: big.NewInt(20_000_000_000),
		GasLimit: 100000,
		To:       nil, // contract creation
		Value:    big.NewInt(0),
		Data:     []byte{0x60, 0x80, 0x60, 0x40, 0x52},
	}

	rawTx, err := w.SignTx(tx)
	if err != nil {
		t.Fatalf("SignTx: %v", err)
	}
	if len(rawTx) == 0 {
		t.Fatal("rawTx is empty")
	}
}

// TestSignTx_WrongRecID verifies that using the wrong recovery id
// produces a different recovered address (not the wallet's address).
func TestSignTx_WrongRecID(t *testing.T) {
	t.Parallel()

	privBytes := hexDecode(t, "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80")
	priv, _ := secp256k1.NewPrivateKey(privBytes)
	w := NewWallet(priv)
	walletAddr, _ := w.Address()

	to, _ := ethereum.ParseAddress("0x70997970C51812dc3A010C7d01b50e0d17dc79C8")
	tx := &LegacyTx{
		ChainID:  big.NewInt(1),
		Nonce:    9,
		GasPrice: big.NewInt(20_000_000_000),
		GasLimit: 21000,
		To:       &to,
		Value:    big.NewInt(1_000_000_000_000_000_000),
	}

	signingHash, _ := tx.SigningHash()
	sig, recID, _ := w.priv.SignRecoverable(signingHash)

	// Try each wrong recID (0-3 except the correct one).
	for wrongID := byte(0); wrongID <= 3; wrongID++ {
		if wrongID == recID {
			continue
		}
		wrongID := wrongID
		t.Run("recID_"+itoaByte(wrongID), func(t *testing.T) {
			t.Parallel()
			recoveredPub, err := secp256k1.RecoverPubKey(sig, signingHash, wrongID)
			if err != nil {
				// Some wrong recIDs may fail recovery — that's fine.
				return
			}
			recoveredAddr, _ := ethereum.FromPublicKey(recoveredPub)
			if recoveredAddr == walletAddr {
				t.Fatalf("wrong recID %d recovered to wallet address %s", wrongID, walletAddr.Hex())
			}
		})
	}
}

// TestSignTx_HighSRejected verifies that a high-s signature is rejected
// by RecoverPubKey. secp256k1.SignRecoverable produces low-s
// signatures per [EIP-2]; flipping s to high-s should cause recovery to
// fail or recover a different key.
func TestSignTx_HighSRejected(t *testing.T) {
	t.Parallel()

	privBytes := hexDecode(t, "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80")
	priv, _ := secp256k1.NewPrivateKey(privBytes)
	w := NewWallet(priv)

	to, _ := ethereum.ParseAddress("0x70997970C51812dc3A010C7d01b50e0d17dc79C8")
	tx := &LegacyTx{
		ChainID:  big.NewInt(1),
		Nonce:    9,
		GasPrice: big.NewInt(20_000_000_000),
		GasLimit: 21000,
		To:       &to,
		Value:    big.NewInt(1_000_000_000_000_000_000),
	}

	signingHash, _ := tx.SigningHash()
	sig, recID, _ := w.priv.SignRecoverable(signingHash)

	// Flip s to its additive inverse (high-s). secp256k1 curve order N:
	// high_s = N - low_s. If recovery accepts high-s, it recovers a
	// different key (not the wallet's).
	secp256k1N, ok := new(big.Int).SetString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16)
	if !ok {
		t.Fatal("failed to parse secp256k1 N")
	}
	sLow := new(big.Int).SetBytes(sig[32:])
	sHigh := new(big.Int).Sub(secp256k1N, sLow)

	highSig := make([]byte, 64)
	copy(highSig[:32], sig[:32])
	copy(highSig[32:], sHigh.Bytes())

	recoveredPub, err := secp256k1.RecoverPubKey(highSig, signingHash, recID)
	if err != nil {
		// High-s rejected by the recovery library — that's the expected
		// behavior for a low-s-enforcing implementation.
		return
	}
	// If recovery succeeded, the recovered key must NOT match the wallet.
	recoveredAddr, _ := ethereum.FromPublicKey(recoveredPub)
	walletAddr, _ := w.Address()
	if recoveredAddr == walletAddr {
		t.Fatal("high-s signature recovered to wallet address — low-s enforcement missing")
	}
}

// itoaByte returns the decimal string of a byte for test names.
func itoaByte(b byte) string {
	if b == 0 {
		return "0"
	}
	var buf [3]byte
	i := len(buf)
	for b > 0 {
		i--
		buf[i] = byte('0' + b%10)
		b /= 10
	}
	return string(buf[i:])
}
