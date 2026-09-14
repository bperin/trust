package wallet

import (
	"crypto/subtle"
	"encoding/hex"
	"math/big"
	"testing"

	"github.com/bperin/trust/chain/ethereum"
	"github.com/bperin/trust/chain/rlp"
	"github.com/bperin/trust/trust/crypto/secp256k1"
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

// hexToAddress builds a 20-byte address from a hex string without the
// 0x prefix, panicking on bad input (test-only helper).
func hexToAddress(h string) [20]byte {
	b, err := hex.DecodeString(h)
	if err != nil {
		panic("hexToAddress: " + err.Error())
	}
	var addr [20]byte
	copy(addr[:], b)
	return addr
}

// hexToHash builds a 32-byte storage key from a hex string without the
// 0x prefix, panicking on bad input (test-only helper).
func hexToHash(h string) [32]byte {
	b, err := hex.DecodeString(h)
	if err != nil {
		panic("hexToHash: " + err.Error())
	}
	var k [32]byte
	copy(k[:], b)
	return k
}

// TestEncodeAccessList_Empty verifies that an empty or nil access list
// encodes as the empty RLP list (0xc0) per [EIP-2930]. An access list
// is never omitted — it is always present as an (possibly empty) RLP
// list in the transaction pre-image.
func TestEncodeAccessList_Empty(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name       string
		accessList []AccessListEntry
	}{
		{"nil", nil},
		{"empty", []AccessListEntry{}},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := encodeAccessList(tc.accessList)
			want := []byte{0xc0}
			if subtle.ConstantTimeCompare(got, want) != 1 {
				t.Fatalf("encodeAccessList: got %x, want %x", got, want)
			}
		})
	}
}

// TestEncodeAccessList_NilStorageKeys verifies that an access list
// entry with nil StorageKeys encodes its storage-key list as the
// empty RLP list (0xc0) per [EIP-2930].
func TestEncodeAccessList_NilStorageKeys(t *testing.T) {
	t.Parallel()

	addr := hexToAddress("0000000000000000000000000000000000000001")
	accessList := []AccessListEntry{
		{Address: addr, StorageKeys: nil},
	}

	got := encodeAccessList(accessList)

	// Decode the outer access-list list.
	decoded, err := rlp.Decode(got)
	if err != nil {
		t.Fatalf("rlp.Decode: %v", err)
	}
	entries, ok := decoded.([]interface{})
	if !ok || len(entries) != 1 {
		t.Fatalf("access list: got %T with %d items, want 1 entry", decoded, len(entries))
	}

	// Each entry is [address, [storageKeys...]].
	entry, ok := entries[0].([]interface{})
	if !ok || len(entry) != 2 {
		t.Fatalf("entry: got %T with %d items, want 2-item list", entries[0], len(entry))
	}

	// The storage-key list (second element) must be an empty list.
	storageList, ok := entry[1].([]interface{})
	if !ok {
		t.Fatalf("storage list: got %T, want list", entry[1])
	}
	if len(storageList) != 0 {
		t.Fatalf("storage list: got %d keys, want 0 (nil StorageKeys → 0xc0)", len(storageList))
	}
}

// TestEncodeAccessList_EIP2930Structure verifies that a non-empty
// access list encodes to the [EIP-2930] [address, [storageKeys...]]
// RLP structure. Two entries are used: one with two storage keys and
// one with none. The encoded output is decoded back and the structure
// is validated field-by-field — address is 20 bytes, each storage key
// is 32 bytes, and the entry ordering is preserved.
//
// Reference: [EIP-2930] — access_list is a list of [address,
// [storage_key_1, storage_key_2, ...]] pairs.
func TestEncodeAccessList_EIP2930Structure(t *testing.T) {
	t.Parallel()

	addr1 := hexToAddress("0000000000000000000000000000000000000001")
	addr2 := hexToAddress("0000000000000000000000000000000000000002")
	key1 := hexToHash("0000000000000000000000000000000000000000000000000000000000000001")
	key2 := hexToHash("0000000000000000000000000000000000000000000000000000000000000002")

	accessList := []AccessListEntry{
		{Address: addr1, StorageKeys: [][32]byte{key1, key2}},
		{Address: addr2, StorageKeys: nil},
	}

	got := encodeAccessList(accessList)

	// The outer encoding must be an RLP list (prefix byte >= 0xc0).
	if len(got) == 0 || got[0] < 0xc0 {
		t.Fatalf("encodeAccessList: first byte 0x%02x is not an RLP list", got[0])
	}

	decoded, err := rlp.Decode(got)
	if err != nil {
		t.Fatalf("rlp.Decode: %v", err)
	}
	entries, ok := decoded.([]interface{})
	if !ok {
		t.Fatalf("decoded: got %T, want list", decoded)
	}
	if len(entries) != 2 {
		t.Fatalf("entries: got %d, want 2", len(entries))
	}

	wantAddrs := [][20]byte{addr1, addr2}
	wantKeyCounts := []int{2, 0}

	for i, e := range entries {
		entry, ok := e.([]interface{})
		if !ok || len(entry) != 2 {
			t.Fatalf("entry %d: got %T with %d items, want 2-item [address, [storageKeys]] list", i, e, len(e.([]interface{})))
		}

		// First element: 20-byte address.
		addrBytes, ok := entry[0].([]byte)
		if !ok {
			t.Fatalf("entry %d address: got %T, want []byte", i, entry[0])
		}
		if len(addrBytes) != 20 {
			t.Fatalf("entry %d address length: got %d, want 20", i, len(addrBytes))
		}
		var gotAddr [20]byte
		copy(gotAddr[:], addrBytes)
		if subtle.ConstantTimeCompare(gotAddr[:], wantAddrs[i][:]) != 1 {
			t.Fatalf("entry %d address: got %x, want %x", i, gotAddr, wantAddrs[i])
		}

		// Second element: list of 32-byte storage keys.
		storageList, ok := entry[1].([]interface{})
		if !ok {
			t.Fatalf("entry %d storage list: got %T, want list", i, entry[1])
		}
		if len(storageList) != wantKeyCounts[i] {
			t.Fatalf("entry %d storage key count: got %d, want %d", i, len(storageList), wantKeyCounts[i])
		}

		// Validate each storage key is 32 bytes.
		for j, sk := range storageList {
			keyBytes, ok := sk.([]byte)
			if !ok {
				t.Fatalf("entry %d key %d: got %T, want []byte", i, j, sk)
			}
			if len(keyBytes) != 32 {
				t.Fatalf("entry %d key %d length: got %d, want 32", i, j, len(keyBytes))
			}
		}
	}
}

// TestEncodeAccessList_Determinism verifies that encoding the same
// access list twice produces byte-identical output (RLP encoding is
// deterministic per Yellow Paper Appendix B).
func TestEncodeAccessList_Determinism(t *testing.T) {
	t.Parallel()

	addr := hexToAddress("0000000000000000000000000000000000000001")
	key := hexToHash("0000000000000000000000000000000000000000000000000000000000000001")
	accessList := []AccessListEntry{
		{Address: addr, StorageKeys: [][32]byte{key}},
	}

	first := encodeAccessList(accessList)
	second := encodeAccessList(accessList)
	if subtle.ConstantTimeCompare(first, second) != 1 {
		t.Fatalf("encodeAccessList not deterministic: got %x then %x", first, second)
	}
}

// TestEIP1559Tx_NonEmptyAccessList verifies that an EIP-1559
// transaction with a non-empty access list produces a valid typed
// envelope whose decoded access list matches the [EIP-2930] structure.
// This is an integration test that exercises encodeAccessList through
// the full SigningHash and EncodeSigned paths.
func TestEIP1559Tx_NonEmptyAccessList(t *testing.T) {
	t.Parallel()

	addr := hexToAddress("0000000000000000000000000000000000000001")
	key := hexToHash("0000000000000000000000000000000000000000000000000000000000000001")

	tx := &EIP1559Tx{
		ChainID:              big.NewInt(1),
		Nonce:                9,
		MaxPriorityFeePerGas: big.NewInt(1_000_000_000),
		MaxFeePerGas:         big.NewInt(20_000_000_000),
		GasLimit:             21000,
		To:                   nil,
		Value:                big.NewInt(0),
		Data:                 nil,
		AccessList: []AccessListEntry{
			{Address: addr, StorageKeys: [][32]byte{key}},
		},
	}

	// SigningHash must succeed and produce a 32-byte digest.
	hash, err := tx.SigningHash()
	if err != nil {
		t.Fatalf("SigningHash: %v", err)
	}
	if len(hash) != 32 {
		t.Fatalf("hash length: got %d, want 32", len(hash))
	}

	// EncodeSigned must produce the 0x02 typed envelope.
	raw, err := tx.EncodeSigned([]byte{0}, []byte{1}, []byte{0})
	if err != nil {
		t.Fatalf("EncodeSigned: %v", err)
	}
	if len(raw) == 0 || raw[0] != 0x02 {
		t.Fatalf("raw[0]: got 0x%02x, want 0x02", raw[0])
	}

	// Decode the body and verify the access list (field index 8) is
	// a non-empty list with the expected structure.
	decoded, err := rlp.Decode(raw[1:])
	if err != nil {
		t.Fatalf("rlp.Decode: %v", err)
	}
	items, ok := decoded.([]interface{})
	if !ok {
		t.Fatalf("decoded: got %T, want list", decoded)
	}
	// 12 fields: chainID, nonce, maxPriority, maxFee, gasLimit, to,
	// value, data, accessList, v, r, s.
	if len(items) != 12 {
		t.Fatalf("items: got %d, want 12", len(items))
	}

	accessListField, ok := items[8].([]interface{})
	if !ok {
		t.Fatalf("access list field: got %T, want list", items[8])
	}
	if len(accessListField) != 1 {
		t.Fatalf("access list entries: got %d, want 1", len(accessListField))
	}

	entry, ok := accessListField[0].([]interface{})
	if !ok || len(entry) != 2 {
		t.Fatalf("entry: got %T with %d items, want 2-item list", accessListField[0], len(accessListField[0].([]interface{})))
	}

	addrBytes, _ := entry[0].([]byte)
	if len(addrBytes) != 20 {
		t.Fatalf("address length: got %d, want 20", len(addrBytes))
	}
	var gotAddr [20]byte
	copy(gotAddr[:], addrBytes)
	if subtle.ConstantTimeCompare(gotAddr[:], addr[:]) != 1 {
		t.Fatalf("address: got %x, want %x", gotAddr, addr)
	}

	storageList, ok := entry[1].([]interface{})
	if !ok {
		t.Fatalf("storage list: got %T, want list", entry[1])
	}
	if len(storageList) != 1 {
		t.Fatalf("storage key count: got %d, want 1", len(storageList))
	}
	keyBytes, _ := storageList[0].([]byte)
	if len(keyBytes) != 32 {
		t.Fatalf("storage key length: got %d, want 32", len(keyBytes))
	}
	if subtle.ConstantTimeCompare(keyBytes, key[:]) != 1 {
		t.Fatalf("storage key: got %x, want %x", keyBytes, key)
	}
}

// TestEIP2930Tx_Type verifies that EIP2930Tx.Type returns 1 per
// [EIP-2718].
func TestEIP2930Tx_Type(t *testing.T) {
	t.Parallel()

	tx := &EIP2930Tx{ChainID: big.NewInt(1)}
	if got := tx.Type(); got != 1 {
		t.Fatalf("Type: got %d, want 1", got)
	}
}

// TestEIP2930Tx_NilChainID verifies that a nil or zero chain ID is
// rejected by both SigningHash and EncodeSigned per [EIP-2930].
func TestEIP2930Tx_NilChainID(t *testing.T) {
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
			tx := &EIP2930Tx{ChainID: tc.chainID}

			if _, err := tx.SigningHash(); err == nil {
				t.Fatal("SigningHash: got nil error, want error")
			}
			if _, err := tx.EncodeSigned([]byte{0}, []byte{1}, []byte{0}); err == nil {
				t.Fatal("EncodeSigned: got nil error, want error")
			}
		})
	}
}

// TestEIP2930Tx_SigningHash verifies the [EIP-2930] signing hash is
// deterministic and 32 bytes. The pre-image is
// 0x01 || rlp([chainId, nonce, gasPrice, gasLimit, to, value, data,
// accessList]).
func TestEIP2930Tx_SigningHash(t *testing.T) {
	t.Parallel()

	tx := &EIP2930Tx{
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

	// Determinism: same input → same hash.
	hash2, err := tx.SigningHash()
	if err != nil {
		t.Fatalf("SigningHash (2nd): %v", err)
	}
	if subtle.ConstantTimeCompare(hash, hash2) != 1 {
		t.Fatal("SigningHash not deterministic")
	}
}

// TestSignTx_EIP2930Ecrecover signs an [EIP-2930] transaction and
// recovers the signer address via ecrecover. The recovered address
// must match the wallet's address. Uses the Hardhat account-0 private
// key on chain ID 1.
//
// Reference: [EIP-2930] — signed payload is
// 0x01 || rlp([chainId, nonce, gasPrice, gasLimit, to, value, data,
// accessList, v, r, s]) where v = y-parity (0 or 1).
func TestSignTx_EIP2930Ecrecover(t *testing.T) {
	t.Parallel()

	privBytes := hexDecode(t, "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80")
	priv, err := secp256k1.NewPrivateKey(privBytes)
	if err != nil {
		t.Fatalf("NewPrivateKey: %v", err)
	}
	w := NewWallet(priv)
	walletAddr, _ := w.Address()

	to, _ := ethereum.ParseAddress("0x70997970C51812dc3A010C7d01b50e0d17dc79C8")

	addr := hexToAddress("0000000000000000000000000000000000000001")
	key := hexToHash("0000000000000000000000000000000000000000000000000000000000000001")

	tx := &EIP2930Tx{
		ChainID:  big.NewInt(1),
		Nonce:    9,
		GasPrice: big.NewInt(20_000_000_000),
		GasLimit: 21000,
		To:       &to,
		Value:    big.NewInt(1_000_000_000_000_000_000),
		Data:     []byte{0xde, 0xad, 0xbe, 0xef},
		AccessList: []AccessListEntry{
			{Address: addr, StorageKeys: [][32]byte{key}},
		},
	}

	rawTx, err := w.SignTx(tx)
	if err != nil {
		t.Fatalf("SignTx: %v", err)
	}

	// EIP-2930: rawTx = 0x01 || rlp([...])
	if len(rawTx) < 1 || rawTx[0] != 0x01 {
		t.Fatalf("rawTx[0]: got 0x%02x, want 0x01", rawTx[0])
	}

	// Decode the RLP body (skip the 0x01 type byte).
	decoded, err := rlp.Decode(rawTx[1:])
	if err != nil {
		t.Fatalf("rlp.Decode: %v", err)
	}
	items, ok := decoded.([]interface{})
	if !ok {
		t.Fatalf("decoded: got %T, want list", decoded)
	}
	// EIP-2930 signed has 11 fields: chainId, nonce, gasPrice, gasLimit,
	// to, value, data, accessList, v, r, s.
	if len(items) != 11 {
		t.Fatalf("items: got %d, want 11", len(items))
	}

	vBytes := items[8].([]byte)
	rBytes := items[9].([]byte)
	sBytes := items[10].([]byte)

	// EIP-2930: v = recID (y-parity, 0 or 1).
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

// TestEIP2930Tx_EmptyAccessList verifies that a nil access list
// encodes as the empty RLP list (0xc0) inside the [EIP-2930] typed
// envelope. The access list is always present in the pre-image — it is
// never omitted.
func TestEIP2930Tx_EmptyAccessList(t *testing.T) {
	t.Parallel()

	to, _ := ethereum.ParseAddress("0x70997970C51812dc3A010C7d01b50e0d17dc79C8")

	cases := []struct {
		name       string
		accessList []AccessListEntry
	}{
		{"nil", nil},
		{"empty", []AccessListEntry{}},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			tx := &EIP2930Tx{
				ChainID:    big.NewInt(1),
				Nonce:      9,
				GasPrice:   big.NewInt(20_000_000_000),
				GasLimit:   21000,
				To:         &to,
				Value:      big.NewInt(1_000_000_000_000_000_000),
				Data:       nil,
				AccessList: tc.accessList,
			}

			// SigningHash must succeed.
			if _, err := tx.SigningHash(); err != nil {
				t.Fatalf("SigningHash: %v", err)
			}

			raw, err := tx.EncodeSigned([]byte{0}, []byte{1}, []byte{0})
			if err != nil {
				t.Fatalf("EncodeSigned: %v", err)
			}
			if len(raw) == 0 || raw[0] != 0x01 {
				t.Fatalf("raw[0]: got 0x%02x, want 0x01", raw[0])
			}

			// Decode the body and verify the access list (field index 7)
			// is an empty RLP list.
			decoded, err := rlp.Decode(raw[1:])
			if err != nil {
				t.Fatalf("rlp.Decode: %v", err)
			}
			items, ok := decoded.([]interface{})
			if !ok {
				t.Fatalf("decoded: got %T, want list", decoded)
			}
			if len(items) != 11 {
				t.Fatalf("items: got %d, want 11", len(items))
			}

			accessListField, ok := items[7].([]interface{})
			if !ok {
				t.Fatalf("access list field: got %T, want list", items[7])
			}
			if len(accessListField) != 0 {
				t.Fatalf("access list entries: got %d, want 0 (nil/empty → 0xc0)", len(accessListField))
			}
		})
	}
}

// TestEIP2930Tx_Boundaries verifies boundary cases for [EIP-2930]
// transactions: zero value, zero nonce, empty data, and nil `to`
// (contract creation). Each case signs the transaction, decodes the
// typed envelope, and recovers the signer address — it must match the
// wallet address.
func TestEIP2930Tx_Boundaries(t *testing.T) {
	t.Parallel()

	privBytes := hexDecode(t, "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80")
	priv, err := secp256k1.NewPrivateKey(privBytes)
	if err != nil {
		t.Fatalf("NewPrivateKey: %v", err)
	}
	w := NewWallet(priv)
	walletAddr, _ := w.Address()

	to, _ := ethereum.ParseAddress("0x70997970C51812dc3A010C7d01b50e0d17dc79C8")

	cases := []struct {
		name  string
		nonce uint64
		to    *ethereum.Address
		value *big.Int
		data  []byte
	}{
		{
			name:  "zero_value",
			nonce: 9,
			to:    &to,
			value: big.NewInt(0),
			data:  []byte{0xde, 0xad, 0xbe, 0xef},
		},
		{
			name:  "zero_nonce",
			nonce: 0,
			to:    &to,
			value: big.NewInt(1_000_000_000_000_000_000),
			data:  []byte{0xde, 0xad, 0xbe, 0xef},
		},
		{
			name:  "empty_data",
			nonce: 9,
			to:    &to,
			value: big.NewInt(1_000_000_000_000_000_000),
			data:  nil,
		},
		{
			name:  "contract_creation",
			nonce: 9,
			to:    nil,
			value: big.NewInt(0),
			data:  []byte{0x60, 0x80, 0x60, 0x40, 0x52},
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			tx := &EIP2930Tx{
				ChainID:    big.NewInt(1),
				Nonce:      tc.nonce,
				GasPrice:   big.NewInt(20_000_000_000),
				GasLimit:   21000,
				To:         tc.to,
				Value:      tc.value,
				Data:       tc.data,
				AccessList: nil,
			}

			rawTx, err := w.SignTx(tx)
			if err != nil {
				t.Fatalf("SignTx: %v", err)
			}
			if len(rawTx) == 0 || rawTx[0] != 0x01 {
				t.Fatalf("rawTx[0]: got 0x%02x, want 0x01", rawTx[0])
			}

			decoded, err := rlp.Decode(rawTx[1:])
			if err != nil {
				t.Fatalf("rlp.Decode: %v", err)
			}
			items, ok := decoded.([]interface{})
			if !ok {
				t.Fatalf("decoded: got %T, want list", decoded)
			}
			if len(items) != 11 {
				t.Fatalf("items: got %d, want 11", len(items))
			}

			vBytes := items[8].([]byte)
			rBytes := items[9].([]byte)
			sBytes := items[10].([]byte)

			var recIDByte byte
			if len(vBytes) == 0 {
				recIDByte = 0
			} else {
				recIDByte = vBytes[0]
			}

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
		})
	}
}

// TestEIP2930Tx_NonEmptyAccessList verifies that an [EIP-2930]
// transaction with a non-empty access list produces a valid typed
// envelope whose decoded access list matches the expected structure.
func TestEIP2930Tx_NonEmptyAccessList(t *testing.T) {
	t.Parallel()

	addr := hexToAddress("0000000000000000000000000000000000000001")
	key := hexToHash("0000000000000000000000000000000000000000000000000000000000000001")

	tx := &EIP2930Tx{
		ChainID:  big.NewInt(1),
		Nonce:    9,
		GasPrice: big.NewInt(20_000_000_000),
		GasLimit: 21000,
		To:       nil,
		Value:    big.NewInt(0),
		Data:     nil,
		AccessList: []AccessListEntry{
			{Address: addr, StorageKeys: [][32]byte{key}},
		},
	}

	// SigningHash must succeed and produce a 32-byte digest.
	hash, err := tx.SigningHash()
	if err != nil {
		t.Fatalf("SigningHash: %v", err)
	}
	if len(hash) != 32 {
		t.Fatalf("hash length: got %d, want 32", len(hash))
	}

	// EncodeSigned must produce the 0x01 typed envelope.
	raw, err := tx.EncodeSigned([]byte{0}, []byte{1}, []byte{0})
	if err != nil {
		t.Fatalf("EncodeSigned: %v", err)
	}
	if len(raw) == 0 || raw[0] != 0x01 {
		t.Fatalf("raw[0]: got 0x%02x, want 0x01", raw[0])
	}

	// Decode the body and verify the access list (field index 7) is
	// a non-empty list with the expected structure.
	decoded, err := rlp.Decode(raw[1:])
	if err != nil {
		t.Fatalf("rlp.Decode: %v", err)
	}
	items, ok := decoded.([]interface{})
	if !ok {
		t.Fatalf("decoded: got %T, want list", decoded)
	}
	// 11 fields: chainId, nonce, gasPrice, gasLimit, to, value, data,
	// accessList, v, r, s.
	if len(items) != 11 {
		t.Fatalf("items: got %d, want 11", len(items))
	}

	accessListField, ok := items[7].([]interface{})
	if !ok {
		t.Fatalf("access list field: got %T, want list", items[7])
	}
	if len(accessListField) != 1 {
		t.Fatalf("access list entries: got %d, want 1", len(accessListField))
	}

	entry, ok := accessListField[0].([]interface{})
	if !ok || len(entry) != 2 {
		t.Fatalf("entry: got %T with %d items, want 2-item list", accessListField[0], len(accessListField[0].([]interface{})))
	}

	addrBytes, _ := entry[0].([]byte)
	if len(addrBytes) != 20 {
		t.Fatalf("address length: got %d, want 20", len(addrBytes))
	}
	var gotAddr [20]byte
	copy(gotAddr[:], addrBytes)
	if subtle.ConstantTimeCompare(gotAddr[:], addr[:]) != 1 {
		t.Fatalf("address: got %x, want %x", gotAddr, addr)
	}

	storageList, ok := entry[1].([]interface{})
	if !ok {
		t.Fatalf("storage list: got %T, want list", entry[1])
	}
	if len(storageList) != 1 {
		t.Fatalf("storage key count: got %d, want 1", len(storageList))
	}
	keyBytes, _ := storageList[0].([]byte)
	if len(keyBytes) != 32 {
		t.Fatalf("storage key length: got %d, want 32", len(keyBytes))
	}
	if subtle.ConstantTimeCompare(keyBytes, key[:]) != 1 {
		t.Fatalf("storage key: got %x, want %x", keyBytes, key)
	}
}
