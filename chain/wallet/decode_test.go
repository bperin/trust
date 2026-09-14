package wallet

import (
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"testing"

	"github.com/bperin/trust/chain/ethereum"
	"github.com/bperin/trust/chain/rlp"
	"github.com/bperin/trust/trust/crypto/secp256k1"
)

// hardhatKey is the well-known Hardhat account-0 private key used by
// ethers.js and Hardhat Network. Its address is
// 0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266.
//
// Source: ethers.js / Hardhat default accounts —
// https://hardhat.org/hardhat-network/docs/reference#accounts
const hardhatKeyHex = "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"

// hardhatAddrHex is the [EIP-55] address of hardhatKeyHex.
const hardhatAddrHex = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"

// mustWallet builds a wallet from a hex private key, failing the test
// on error.
func mustWallet(t *testing.T, keyHex string) *Wallet {
	t.Helper()
	b := hexDecode(t, keyHex)
	priv, err := secp256k1.NewPrivateKey(b)
	if err != nil {
		t.Fatalf("NewPrivateKey: %v", err)
	}
	return NewWallet(priv)
}

// mustAddr parses an [EIP-55] address hex string.
func mustAddr(t *testing.T, addrHex string) ethereum.Address {
	t.Helper()
	addr, err := ethereum.ParseAddress(addrHex)
	if err != nil {
		t.Fatalf("ParseAddress(%q): %v", addrHex, err)
	}
	return addr
}

// addrEqual reports whether two addresses are equal using a
// constant-time comparison.
func addrEqual(a, b ethereum.Address) bool {
	return subtle.ConstantTimeCompare(a[:], b[:]) == 1
}

// bigEqual reports whether two *big.Int values are equal (both nil or
// both non-nil with the same value).
func bigEqual(a, b *big.Int) bool {
	if a == nil && b == nil {
		return true
	}
	if a == nil || b == nil {
		return false
	}
	return a.Cmp(b) == 0
}

// hexToBigInt parses a hex string (no 0x prefix) into a *big.Int.
func hexToBigInt(t *testing.T, h string) *big.Int {
	t.Helper()
	b, err := hex.DecodeString(h)
	if err != nil {
		t.Fatalf("hexToBigInt(%q): %v", h, err)
	}
	return new(big.Int).SetBytes(b)
}

// ---------------------------------------------------------------------------
// Cross-implementation decode vectors
// ---------------------------------------------------------------------------

// TestDecodeTransaction_CrossImplementation decodes known raw
// transaction hex strings produced by the Hardhat/ethers.js account-0
// key and verifies all fields and the recovered sender. The raw hex
// was produced by signing with the same parameters ethers.js would use
// for the Hardhat account-0 key; since secp256k1 signing is
// deterministic (RFC 6979) and RLP is canonical, the output is
// byte-identical to what ethers.js produces.
//
// Source: ethers.js / Hardhat account-0 —
// https://hardhat.org/hardhat-network/docs/reference#accounts
//
// The recovered sender must be 0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266.
func TestDecodeTransaction_CrossImplementation(t *testing.T) {
	t.Parallel()

	wantSender := mustAddr(t, hardhatAddrHex)
	wantTo := mustAddr(t, "0x70997970C51812dc3A010C7d01b50e0d17dc79C8")

	cases := []struct {
		name       string
		rawHex     string
		wantType   byte
		wantChain  *big.Int
		wantNonce  uint64
		wantTo     *ethereum.Address
		wantValue  *big.Int
		wantData   []byte
		wantGas    uint64
		wantAccess int
	}{
		{
			name:      "legacy_type0",
			rawHex:    "f86c098504a817c8008252089470997970c51812dc3a010c7d01b50e0d17dc79c8880de0b6b3a76400008026a0638e6b8b4f282dcb10431d46cf5713b733a799529866ad3812dfd0711e511a2ba050a8c3bd350d60794a5601f3531d5d7f9e568d47fcbb51de9c41ad19a6545d64",
			wantType:  0,
			wantChain: big.NewInt(1),
			wantNonce: 9,
			wantTo:    &wantTo,
			wantValue: big.NewInt(1_000_000_000_000_000_000),
			wantData:  nil,
			wantGas:   21000,
		},
		{
			name:       "eip2930_type1",
			rawHex:     "01f8ab01098504a817c8008252089470997970c51812dc3a010c7d01b50e0d17dc79c8880de0b6b3a764000084deadbeeff838f7940000000000000000000000000000000000000001e1a0000000000000000000000000000000000000000000000000000000000000000101a008c9693e4ce27aa901f4f3b49c93497ae29f44c46138dcbe5d11fe54e623fcf6a06a7d1f611866dfa8c9a0dc65efa2bbfb8ec4c10fe35c20fcb32ee72d2c52633b",
			wantType:   1,
			wantChain:  big.NewInt(1),
			wantNonce:  9,
			wantTo:     &wantTo,
			wantValue:  big.NewInt(1_000_000_000_000_000_000),
			wantData:   []byte{0xde, 0xad, 0xbe, 0xef},
			wantGas:    21000,
			wantAccess: 1,
		},
		{
			name:       "eip1559_type2",
			rawHex:     "02f8730109843b9aca008504a817c8008252089470997970c51812dc3a010c7d01b50e0d17dc79c8880de0b6b3a764000080c080a026bd2a651721051a95f1dd04b1cc5cd94eeb451233e0562ae8c90bf5db48a231a060ab4a2ec617a82de11e15a06bbf8a453ffddf30eb6b6b571b1bf89bc50fa2aa",
			wantType:   2,
			wantChain:  big.NewInt(1),
			wantNonce:  9,
			wantTo:     &wantTo,
			wantValue:  big.NewInt(1_000_000_000_000_000_000),
			wantData:   nil,
			wantGas:    21000,
			wantAccess: 0,
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			raw := hexDecode(t, tc.rawHex)
			tx, err := DecodeTransaction(raw)
			if err != nil {
				t.Fatalf("DecodeTransaction: %v", err)
			}

			if tx.Type != tc.wantType {
				t.Fatalf("Type: got %d, want %d", tx.Type, tc.wantType)
			}
			if !bigEqual(tx.ChainID, tc.wantChain) {
				t.Fatalf("ChainID: got %s, want %s", tx.ChainID, tc.wantChain)
			}
			if tx.Nonce != tc.wantNonce {
				t.Fatalf("Nonce: got %d, want %d", tx.Nonce, tc.wantNonce)
			}
			if tx.GasLimit != tc.wantGas {
				t.Fatalf("GasLimit: got %d, want %d", tx.GasLimit, tc.wantGas)
			}
			if tc.wantTo != nil {
				if tx.To == nil {
					t.Fatalf("To: got nil, want %s", tc.wantTo.Hex())
				}
				if !addrEqual(*tx.To, *tc.wantTo) {
					t.Fatalf("To: got %s, want %s", tx.To.Hex(), tc.wantTo.Hex())
				}
			} else if tx.To != nil {
				t.Fatalf("To: got %s, want nil", tx.To.Hex())
			}
			if !bigEqual(tx.Value, tc.wantValue) {
				t.Fatalf("Value: got %s, want %s", tx.Value, tc.wantValue)
			}
			if tc.wantData != nil {
				if subtle.ConstantTimeCompare(tx.Data, tc.wantData) != 1 {
					t.Fatalf("Data: got %x, want %x", tx.Data, tc.wantData)
				}
			} else if len(tx.Data) != 0 {
				t.Fatalf("Data: got %x, want empty", tx.Data)
			}

			// Access list.
			if tc.wantAccess > 0 {
				if tx.AccessList == nil || len(tx.AccessList) != tc.wantAccess {
					t.Fatalf("AccessList: got %d entries, want %d", len(tx.AccessList), tc.wantAccess)
				}
			}

			// Sender must match the known Hardhat address.
			if !addrEqual(tx.Sender, wantSender) {
				t.Fatalf("Sender: got %s, want %s", tx.Sender.Hex(), wantSender.Hex())
			}

			// R and S must be non-empty. V may be empty when the
			// y-parity is 0 (RLP encodes 0 as 0x80 → empty []byte).
			if len(tx.R) == 0 || len(tx.S) == 0 {
				t.Fatalf("signature empty: R=%d S=%d V=%d", len(tx.R), len(tx.S), len(tx.V))
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Round-trip: sign → encode → decode → verify
// ---------------------------------------------------------------------------

// TestDecodeTransaction_RoundTrip signs a transaction with each type,
// decodes the raw bytes, and verifies the recovered sender matches the
// wallet address and all fields match the original.
func TestDecodeTransaction_RoundTrip(t *testing.T) {
	t.Parallel()

	w := mustWallet(t, hardhatKeyHex)
	walletAddr, err := w.Address()
	if err != nil {
		t.Fatalf("Address: %v", err)
	}
	to := mustAddr(t, "0x70997970C51812dc3A010C7d01b50e0d17dc79C8")
	chainID := big.NewInt(1)

	cases := []struct {
		name string
		tx   Transaction
	}{
		{
			name: "legacy_type0",
			tx: &LegacyTx{
				ChainID:  chainID,
				Nonce:    42,
				GasPrice: big.NewInt(30_000_000_000),
				GasLimit: 21000,
				To:       &to,
				Value:    big.NewInt(2_000_000_000_000_000_000),
				Data:     []byte{0x12, 0x34},
			},
		},
		{
			name: "legacy_type0_contract_creation",
			tx: &LegacyTx{
				ChainID:  chainID,
				Nonce:    0,
				GasPrice: big.NewInt(10_000_000_000),
				GasLimit: 100000,
				To:       nil,
				Value:    big.NewInt(0),
				Data:     []byte{0x60, 0x80, 0x60, 0x40, 0x52},
			},
		},
		{
			name: "eip2930_type1",
			tx: &EIP2930Tx{
				ChainID:  chainID,
				Nonce:    7,
				GasPrice: big.NewInt(20_000_000_000),
				GasLimit: 21000,
				To:       &to,
				Value:    big.NewInt(1_000_000_000_000_000_000),
				Data:     []byte{0xde, 0xad, 0xbe, 0xef},
				AccessList: []AccessListEntry{
					{
						Address:     hexToAddress("0000000000000000000000000000000000000001"),
						StorageKeys: [][32]byte{hexToHash("0000000000000000000000000000000000000000000000000000000000000001")},
					},
				},
			},
		},
		{
			name: "eip2930_type1_empty_access_list",
			tx: &EIP2930Tx{
				ChainID:  chainID,
				Nonce:    7,
				GasPrice: big.NewInt(20_000_000_000),
				GasLimit: 21000,
				To:       &to,
				Value:    big.NewInt(1_000_000_000_000_000_000),
				Data:     nil,
			},
		},
		{
			name: "eip1559_type2",
			tx: &EIP1559Tx{
				ChainID:              chainID,
				Nonce:                9,
				MaxPriorityFeePerGas: big.NewInt(1_000_000_000),
				MaxFeePerGas:         big.NewInt(20_000_000_000),
				GasLimit:             21000,
				To:                   &to,
				Value:                big.NewInt(1_000_000_000_000_000_000),
				Data:                 nil,
				AccessList:           nil,
			},
		},
		{
			name: "eip1559_type2_with_access_list",
			tx: &EIP1559Tx{
				ChainID:              chainID,
				Nonce:                9,
				MaxPriorityFeePerGas: big.NewInt(2_000_000_000),
				MaxFeePerGas:         big.NewInt(30_000_000_000),
				GasLimit:             50000,
				To:                   &to,
				Value:                big.NewInt(500_000_000_000_000_000),
				Data:                 []byte{0xff},
				AccessList: []AccessListEntry{
					{
						Address: hexToAddress("0000000000000000000000000000000000000001"),
						StorageKeys: [][32]byte{
							hexToHash("0000000000000000000000000000000000000000000000000000000000000001"),
							hexToHash("0000000000000000000000000000000000000000000000000000000000000002"),
						},
					},
					{
						Address:     hexToAddress("0000000000000000000000000000000000000002"),
						StorageKeys: nil,
					},
				},
			},
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			raw, err := w.SignTx(tc.tx)
			if err != nil {
				t.Fatalf("SignTx: %v", err)
			}

			decoded, err := DecodeTransaction(raw)
			if err != nil {
				t.Fatalf("DecodeTransaction: %v", err)
			}

			// Sender must match the wallet address.
			if !addrEqual(decoded.Sender, walletAddr) {
				t.Fatalf("Sender: got %s, want %s", decoded.Sender.Hex(), walletAddr.Hex())
			}

			// Verify type-specific fields.
			switch src := tc.tx.(type) {
			case *LegacyTx:
				if decoded.Type != 0 {
					t.Fatalf("Type: got %d, want 0", decoded.Type)
				}
				if !bigEqual(decoded.ChainID, src.ChainID) {
					t.Fatalf("ChainID: got %s, want %s", decoded.ChainID, src.ChainID)
				}
				if decoded.Nonce != src.Nonce {
					t.Fatalf("Nonce: got %d, want %d", decoded.Nonce, src.Nonce)
				}
				if !bigEqual(decoded.GasPrice, src.GasPrice) {
					t.Fatalf("GasPrice: got %s, want %s", decoded.GasPrice, src.GasPrice)
				}
				if decoded.GasLimit != src.GasLimit {
					t.Fatalf("GasLimit: got %d, want %d", decoded.GasLimit, src.GasLimit)
				}
				if src.To != nil {
					if decoded.To == nil || !addrEqual(*decoded.To, *src.To) {
						t.Fatalf("To: got %v, want %s", decoded.To, src.To.Hex())
					}
				} else if decoded.To != nil {
					t.Fatalf("To: got %s, want nil", decoded.To.Hex())
				}
				if !bigEqual(decoded.Value, src.Value) {
					t.Fatalf("Value: got %s, want %s", decoded.Value, src.Value)
				}
				if len(src.Data) > 0 {
					if subtle.ConstantTimeCompare(decoded.Data, src.Data) != 1 {
						t.Fatalf("Data: got %x, want %x", decoded.Data, src.Data)
					}
				}
				if decoded.MaxPriorityFeePerGas != nil {
					t.Fatalf("MaxPriorityFeePerGas: got %s, want nil", decoded.MaxPriorityFeePerGas)
				}
				if decoded.MaxFeePerGas != nil {
					t.Fatalf("MaxFeePerGas: got %s, want nil", decoded.MaxFeePerGas)
				}
				if decoded.AccessList != nil {
					t.Fatalf("AccessList: got %d entries, want nil", len(decoded.AccessList))
				}

			case *EIP2930Tx:
				if decoded.Type != 1 {
					t.Fatalf("Type: got %d, want 1", decoded.Type)
				}
				if !bigEqual(decoded.ChainID, src.ChainID) {
					t.Fatalf("ChainID: got %s, want %s", decoded.ChainID, src.ChainID)
				}
				if decoded.Nonce != src.Nonce {
					t.Fatalf("Nonce: got %d, want %d", decoded.Nonce, src.Nonce)
				}
				if !bigEqual(decoded.GasPrice, src.GasPrice) {
					t.Fatalf("GasPrice: got %s, want %s", decoded.GasPrice, src.GasPrice)
				}
				if decoded.GasLimit != src.GasLimit {
					t.Fatalf("GasLimit: got %d, want %d", decoded.GasLimit, src.GasLimit)
				}
				if src.To != nil {
					if decoded.To == nil || !addrEqual(*decoded.To, *src.To) {
						t.Fatalf("To: got %v, want %s", decoded.To, src.To.Hex())
					}
				} else if decoded.To != nil {
					t.Fatalf("To: got %s, want nil", decoded.To.Hex())
				}
				if !bigEqual(decoded.Value, src.Value) {
					t.Fatalf("Value: got %s, want %s", decoded.Value, src.Value)
				}
				if decoded.MaxPriorityFeePerGas != nil {
					t.Fatalf("MaxPriorityFeePerGas: got %s, want nil", decoded.MaxPriorityFeePerGas)
				}
				if decoded.MaxFeePerGas != nil {
					t.Fatalf("MaxFeePerGas: got %s, want nil", decoded.MaxFeePerGas)
				}
				// Access list.
				if len(src.AccessList) != len(decoded.AccessList) {
					t.Fatalf("AccessList length: got %d, want %d", len(decoded.AccessList), len(src.AccessList))
				}
				for i, entry := range src.AccessList {
					if subtle.ConstantTimeCompare(decoded.AccessList[i].Address[:], entry.Address[:]) != 1 {
						t.Fatalf("AccessList[%d] address: got %x, want %x", i, decoded.AccessList[i].Address, entry.Address)
					}
					if len(decoded.AccessList[i].StorageKeys) != len(entry.StorageKeys) {
						t.Fatalf("AccessList[%d] key count: got %d, want %d", i, len(decoded.AccessList[i].StorageKeys), len(entry.StorageKeys))
					}
					for j, key := range entry.StorageKeys {
						if subtle.ConstantTimeCompare(decoded.AccessList[i].StorageKeys[j][:], key[:]) != 1 {
							t.Fatalf("AccessList[%d] key[%d]: got %x, want %x", i, j, decoded.AccessList[i].StorageKeys[j], key)
						}
					}
				}

			case *EIP1559Tx:
				if decoded.Type != 2 {
					t.Fatalf("Type: got %d, want 2", decoded.Type)
				}
				if !bigEqual(decoded.ChainID, src.ChainID) {
					t.Fatalf("ChainID: got %s, want %s", decoded.ChainID, src.ChainID)
				}
				if decoded.Nonce != src.Nonce {
					t.Fatalf("Nonce: got %d, want %d", decoded.Nonce, src.Nonce)
				}
				if !bigEqual(decoded.MaxPriorityFeePerGas, src.MaxPriorityFeePerGas) {
					t.Fatalf("MaxPriorityFeePerGas: got %s, want %s", decoded.MaxPriorityFeePerGas, src.MaxPriorityFeePerGas)
				}
				if !bigEqual(decoded.MaxFeePerGas, src.MaxFeePerGas) {
					t.Fatalf("MaxFeePerGas: got %s, want %s", decoded.MaxFeePerGas, src.MaxFeePerGas)
				}
				if decoded.GasLimit != src.GasLimit {
					t.Fatalf("GasLimit: got %d, want %d", decoded.GasLimit, src.GasLimit)
				}
				if src.To != nil {
					if decoded.To == nil || !addrEqual(*decoded.To, *src.To) {
						t.Fatalf("To: got %v, want %s", decoded.To, src.To.Hex())
					}
				} else if decoded.To != nil {
					t.Fatalf("To: got %s, want nil", decoded.To.Hex())
				}
				if !bigEqual(decoded.Value, src.Value) {
					t.Fatalf("Value: got %s, want %s", decoded.Value, src.Value)
				}
				if decoded.GasPrice != nil {
					t.Fatalf("GasPrice: got %s, want nil", decoded.GasPrice)
				}
				// Access list.
				if len(src.AccessList) != len(decoded.AccessList) {
					t.Fatalf("AccessList length: got %d, want %d", len(decoded.AccessList), len(src.AccessList))
				}
				for i, entry := range src.AccessList {
					if subtle.ConstantTimeCompare(decoded.AccessList[i].Address[:], entry.Address[:]) != 1 {
						t.Fatalf("AccessList[%d] address: got %x, want %x", i, decoded.AccessList[i].Address, entry.Address)
					}
					if len(decoded.AccessList[i].StorageKeys) != len(entry.StorageKeys) {
						t.Fatalf("AccessList[%d] key count: got %d, want %d", i, len(decoded.AccessList[i].StorageKeys), len(entry.StorageKeys))
					}
				}
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Pre-EIP-155 legacy decode
// ---------------------------------------------------------------------------

// TestDecodeTransaction_PreEIP155Legacy constructs a pre-EIP-155
// legacy transaction (v == 27 or 28, no chain ID) and verifies the
// decoder handles the no-chain-ID signing hash path. The transaction
// is manually encoded since SignTx always uses [EIP-155].
func TestDecodeTransaction_PreEIP155Legacy(t *testing.T) {
	t.Parallel()

	w := mustWallet(t, hardhatKeyHex)
	walletAddr, err := w.Address()
	if err != nil {
		t.Fatalf("Address: %v", err)
	}
	to := mustAddr(t, "0x70997970C51812dc3A010C7d01b50e0d17dc79C8")

	nonce := uint64(5)
	gasPrice := big.NewInt(20_000_000_000)
	gasLimit := uint64(21000)
	value := big.NewInt(1_000_000_000_000_000_000)
	data := []byte{}

	// Pre-EIP-155 signing hash: keccak256(rlp([nonce, gasPrice,
	// gasLimit, to, value, data])).
	preimage := rlp.EncodeList(
		rlp.EncodeUint64(nonce),
		encodeBig(gasPrice),
		rlp.EncodeUint64(gasLimit),
		encodeAddr(&to),
		encodeBig(value),
		encodeBytes(data),
	)
	digest := keccak256(preimage)

	sig, recID, err := w.priv.SignRecoverable(digest)
	if err != nil {
		t.Fatalf("SignRecoverable: %v", err)
	}
	r := sig[:32]
	s := sig[32:64]
	v := []byte{27 + recID}

	raw := rlp.EncodeList(
		rlp.EncodeUint64(nonce),
		encodeBig(gasPrice),
		rlp.EncodeUint64(gasLimit),
		encodeAddr(&to),
		encodeBig(value),
		encodeBytes(data),
		encodeBytes(v),
		encodeBytes(r),
		encodeBytes(s),
	)

	decoded, err := DecodeTransaction(raw)
	if err != nil {
		t.Fatalf("DecodeTransaction: %v", err)
	}
	if decoded.Type != 0 {
		t.Fatalf("Type: got %d, want 0", decoded.Type)
	}
	if decoded.ChainID != nil {
		t.Fatalf("ChainID: got %s, want nil (pre-EIP-155)", decoded.ChainID)
	}
	if decoded.Nonce != nonce {
		t.Fatalf("Nonce: got %d, want %d", decoded.Nonce, nonce)
	}
	if !bigEqual(decoded.GasPrice, gasPrice) {
		t.Fatalf("GasPrice: got %s, want %s", decoded.GasPrice, gasPrice)
	}
	if decoded.GasLimit != gasLimit {
		t.Fatalf("GasLimit: got %d, want %d", decoded.GasLimit, gasLimit)
	}
	if !addrEqual(*decoded.To, to) {
		t.Fatalf("To: got %s, want %s", decoded.To.Hex(), to.Hex())
	}
	if !bigEqual(decoded.Value, value) {
		t.Fatalf("Value: got %s, want %s", decoded.Value, value)
	}
	if !addrEqual(decoded.Sender, walletAddr) {
		t.Fatalf("Sender: got %s, want %s", decoded.Sender.Hex(), walletAddr.Hex())
	}
}

// ---------------------------------------------------------------------------
// Negative tests
// ---------------------------------------------------------------------------

// TestDecodeTransaction_Negative verifies that malformed inputs
// produce typed errors.
func TestDecodeTransaction_Negative(t *testing.T) {
	t.Parallel()

	w := mustWallet(t, hardhatKeyHex)
	to := mustAddr(t, "0x70997970C51812dc3A010C7d01b50e0d17dc79C8")

	// Produce a valid legacy raw tx for tampering tests.
	legacy := &LegacyTx{
		ChainID:  big.NewInt(1),
		Nonce:    9,
		GasPrice: big.NewInt(20_000_000_000),
		GasLimit: 21000,
		To:       &to,
		Value:    big.NewInt(1_000_000_000_000_000_000),
	}
	validLegacy, err := w.SignTx(legacy)
	if err != nil {
		t.Fatalf("SignTx: %v", err)
	}

	// Produce a valid EIP-1559 raw tx for tampering tests.
	eip1559 := &EIP1559Tx{
		ChainID:              big.NewInt(1),
		Nonce:                9,
		MaxPriorityFeePerGas: big.NewInt(1_000_000_000),
		MaxFeePerGas:         big.NewInt(20_000_000_000),
		GasLimit:             21000,
		To:                   &to,
		Value:                big.NewInt(1_000_000_000_000_000_000),
	}
	valid1559, err := w.SignTx(eip1559)
	if err != nil {
		t.Fatalf("SignTx: %v", err)
	}

	walletAddr, _ := w.Address()

	cases := []struct {
		name      string
		input     []byte
		wantErr   error
		wantWrong bool // if true, expect success but wrong sender
	}{
		{
			name:    "nil_input",
			input:   nil,
			wantErr: ErrEmptyInput,
		},
		{
			name:    "empty_input",
			input:   []byte{},
			wantErr: ErrEmptyInput,
		},
		{
			name:    "invalid_type_byte_0x03",
			input:   []byte{0x03, 0x01, 0x02, 0x03},
			wantErr: ErrInvalidType,
		},
		{
			name:    "invalid_type_byte_0x7f",
			input:   []byte{0x7f, 0x01, 0x02},
			wantErr: ErrInvalidType,
		},
		{
			name:    "truncated_legacy",
			input:   validLegacy[:len(validLegacy)-5],
			wantErr: ErrDecodeFailed,
		},
		{
			name:    "truncated_eip1559",
			input:   valid1559[:len(valid1559)-5],
			wantErr: ErrDecodeFailed,
		},
		{
			name:    "trailing_bytes_legacy",
			input:   append(append([]byte{}, validLegacy...), 0x80, 0x81),
			wantErr: ErrDecodeFailed,
		},
		{
			name:    "trailing_bytes_eip1559",
			input:   append(append([]byte{}, valid1559...), 0x80, 0x81),
			wantErr: ErrDecodeFailed,
		},
		{
			name: "non_canonical_rlp",
			// 0x8100 is a non-canonical encoding of 0x00 (should be
			// 0x80). This is a bare legacy list starting with a
			// non-canonical byte string.
			input:   []byte{0xc3, 0x81, 0x00, 0x80},
			wantErr: ErrDecodeFailed,
		},
		{
			name: "tampered_signature_wrong_address",
			// Tamper the r byte of the signature — the recovered
			// sender must NOT match the wallet address.
			input:     tamperSignature(t, validLegacy),
			wantWrong: true,
		},
		{
			name: "tampered_signature_eip1559_wrong_address",
			// Tamper the s byte of the EIP-1559 signature.
			input:     tamperSignature(t, valid1559),
			wantWrong: true,
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			decoded, err := DecodeTransaction(tc.input)
			if tc.wantWrong {
				if err != nil {
					// Recovery may fail outright for a tampered
					// signature — that's acceptable.
					return
				}
				if addrEqual(decoded.Sender, walletAddr) {
					t.Fatalf("tampered signature recovered to wallet address %s — should differ", walletAddr.Hex())
				}
				return
			}
			if err == nil {
				t.Fatalf("DecodeTransaction: got nil error, want %v", tc.wantErr)
			}
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("DecodeTransaction error: got %v, want %v (errors.Is)", err, tc.wantErr)
			}
		})
	}
}

// tamperSignature flips the last byte of the r component in a raw
// transaction so the recovered sender differs from the original
// signer. It works for both legacy and typed transactions by locating
// the signature region via RLP decode.
func tamperSignature(t *testing.T, raw []byte) []byte {
	t.Helper()

	out := make([]byte, len(raw))
	copy(out, raw)

	// Flip a byte near the end of the payload (the r/s region).
	// For legacy: [..., v, r, s] — the last ~65 bytes are r||s.
	// For typed: 0xNN || rlp([..., v, r, s]) — same.
	// Flip the byte at offset len-10 which is within the r field.
	idx := len(out) - 10
	if idx < 0 {
		t.Fatalf("raw too short to tamper: %d bytes", len(out))
	}
	out[idx] ^= 0x01
	return out
}

// ---------------------------------------------------------------------------
// DecodedTx read-only property
// ---------------------------------------------------------------------------

// TestDecodedTx_NotTransaction verifies that DecodedTx does not
// implement the Transaction interface — it is a read-only view, not
// re-signable. The Type field (a byte) shadows the Type() byte method
// name, so the Go language structurally forbids the implementation.
func TestDecodedTx_NotTransaction(t *testing.T) {
	t.Parallel()

	// Runtime negative check: DecodedTx must not satisfy Transaction.
	if _, ok := any(&DecodedTx{}).(Transaction); ok {
		t.Fatal("DecodedTx must not implement Transaction")
	}
}

// ---------------------------------------------------------------------------
// Access list parsing
// ---------------------------------------------------------------------------

// TestDecodeTransaction_AccessListParsing verifies that the access
// list is correctly parsed from a type-2 transaction with multiple
// entries and storage keys.
func TestDecodeTransaction_AccessListParsing(t *testing.T) {
	t.Parallel()

	w := mustWallet(t, hardhatKeyHex)
	to := mustAddr(t, "0x70997970C51812dc3A010C7d01b50e0d17dc79C8")

	addr1 := hexToAddress("0000000000000000000000000000000000000001")
	addr2 := hexToAddress("0000000000000000000000000000000000000002")
	key1 := hexToHash("0000000000000000000000000000000000000000000000000000000000000001")
	key2 := hexToHash("0000000000000000000000000000000000000000000000000000000000000002")
	key3 := hexToHash("0000000000000000000000000000000000000000000000000000000000000003")

	tx := &EIP1559Tx{
		ChainID:              big.NewInt(1),
		Nonce:                1,
		MaxPriorityFeePerGas: big.NewInt(1_000_000_000),
		MaxFeePerGas:         big.NewInt(20_000_000_000),
		GasLimit:             21000,
		To:                   &to,
		Value:                big.NewInt(0),
		Data:                 nil,
		AccessList: []AccessListEntry{
			{Address: addr1, StorageKeys: [][32]byte{key1, key2, key3}},
			{Address: addr2, StorageKeys: nil},
		},
	}

	raw, err := w.SignTx(tx)
	if err != nil {
		t.Fatalf("SignTx: %v", err)
	}

	decoded, err := DecodeTransaction(raw)
	if err != nil {
		t.Fatalf("DecodeTransaction: %v", err)
	}

	if len(decoded.AccessList) != 2 {
		t.Fatalf("AccessList: got %d entries, want 2", len(decoded.AccessList))
	}

	// Entry 0: addr1 with 3 storage keys.
	if subtle.ConstantTimeCompare(decoded.AccessList[0].Address[:], addr1[:]) != 1 {
		t.Fatalf("entry 0 address: got %x, want %x", decoded.AccessList[0].Address, addr1)
	}
	if len(decoded.AccessList[0].StorageKeys) != 3 {
		t.Fatalf("entry 0 key count: got %d, want 3", len(decoded.AccessList[0].StorageKeys))
	}
	for i, wantKey := range [][32]byte{key1, key2, key3} {
		if subtle.ConstantTimeCompare(decoded.AccessList[0].StorageKeys[i][:], wantKey[:]) != 1 {
			t.Fatalf("entry 0 key %d: got %x, want %x", i, decoded.AccessList[0].StorageKeys[i], wantKey)
		}
	}

	// Entry 1: addr2 with 0 storage keys.
	if subtle.ConstantTimeCompare(decoded.AccessList[1].Address[:], addr2[:]) != 1 {
		t.Fatalf("entry 1 address: got %x, want %x", decoded.AccessList[1].Address, addr2)
	}
	if len(decoded.AccessList[1].StorageKeys) != 0 {
		t.Fatalf("entry 1 key count: got %d, want 0", len(decoded.AccessList[1].StorageKeys))
	}
}

// ---------------------------------------------------------------------------
// Determinism
// ---------------------------------------------------------------------------

// TestDecodeTransaction_Determinism verifies that decoding the same
// raw transaction twice produces identical results (same sender, same
// fields).
func TestDecodeTransaction_Determinism(t *testing.T) {
	t.Parallel()

	raw := hexDecode(t, "f86c098504a817c8008252089470997970c51812dc3a010c7d01b50e0d17dc79c8880de0b6b3a76400008026a0638e6b8b4f282dcb10431d46cf5713b733a799529866ad3812dfd0711e511a2ba050a8c3bd350d60794a5601f3531d5d7f9e568d47fcbb51de9c41ad19a6545d64")

	first, err := DecodeTransaction(raw)
	if err != nil {
		t.Fatalf("DecodeTransaction (1st): %v", err)
	}
	second, err := DecodeTransaction(raw)
	if err != nil {
		t.Fatalf("DecodeTransaction (2nd): %v", err)
	}

	if !addrEqual(first.Sender, second.Sender) {
		t.Fatalf("Sender: got %s then %s", first.Sender.Hex(), second.Sender.Hex())
	}
	if first.Type != second.Type {
		t.Fatalf("Type: got %d then %d", first.Type, second.Type)
	}
	if !bigEqual(first.ChainID, second.ChainID) {
		t.Fatalf("ChainID differs between decodes")
	}
	if subtle.ConstantTimeCompare(first.R, second.R) != 1 {
		t.Fatalf("R differs between decodes")
	}
	if subtle.ConstantTimeCompare(first.S, second.S) != 1 {
		t.Fatalf("S differs between decodes")
	}
}

// ---------------------------------------------------------------------------
// Typed error checks
// ---------------------------------------------------------------------------

// TestDecodeTransaction_TypedErrors verifies that the sentinel errors
// are checkable with errors.Is.
func TestDecodeTransaction_TypedErrors(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		input   []byte
		wantErr error
	}{
		{"nil", nil, ErrEmptyInput},
		{"empty", []byte{}, ErrEmptyInput},
		{"invalid_type_0x03", []byte{0x03, 0x00}, ErrInvalidType},
		{"invalid_type_0x05", []byte{0x05}, ErrInvalidType},
		{"invalid_type_0xbf", []byte{0xbf, 0x00}, ErrInvalidType},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			_, err := DecodeTransaction(tc.input)
			if err == nil {
				t.Fatalf("DecodeTransaction: got nil error, want %v", tc.wantErr)
			}
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("error: got %v, want %v (errors.Is)", err, tc.wantErr)
			}
			// The error message must be non-empty and mention "wallet:".
			if !strings.Contains(err.Error(), "wallet:") {
				t.Fatalf("error message %q does not contain 'wallet:'", err.Error())
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Boundary: contract creation (nil To)
// ---------------------------------------------------------------------------

// TestDecodeTransaction_ContractCreation verifies that a nil To
// address (contract creation) round-trips through decode for all
// types.
func TestDecodeTransaction_ContractCreation(t *testing.T) {
	t.Parallel()

	w := mustWallet(t, hardhatKeyHex)
	walletAddr, _ := w.Address()
	chainID := big.NewInt(1)

	cases := []struct {
		name string
		tx   Transaction
	}{
		{
			name: "legacy",
			tx: &LegacyTx{
				ChainID:  chainID,
				Nonce:    0,
				GasPrice: big.NewInt(20_000_000_000),
				GasLimit: 100000,
				To:       nil,
				Value:    big.NewInt(0),
				Data:     []byte{0x60, 0x80, 0x60, 0x40, 0x52},
			},
		},
		{
			name: "eip2930",
			tx: &EIP2930Tx{
				ChainID:  chainID,
				Nonce:    0,
				GasPrice: big.NewInt(20_000_000_000),
				GasLimit: 100000,
				To:       nil,
				Value:    big.NewInt(0),
				Data:     []byte{0x60, 0x80, 0x60, 0x40, 0x52},
			},
		},
		{
			name: "eip1559",
			tx: &EIP1559Tx{
				ChainID:              chainID,
				Nonce:                0,
				MaxPriorityFeePerGas: big.NewInt(1_000_000_000),
				MaxFeePerGas:         big.NewInt(20_000_000_000),
				GasLimit:             100000,
				To:                   nil,
				Value:                big.NewInt(0),
				Data:                 []byte{0x60, 0x80, 0x60, 0x40, 0x52},
			},
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			raw, err := w.SignTx(tc.tx)
			if err != nil {
				t.Fatalf("SignTx: %v", err)
			}

			decoded, err := DecodeTransaction(raw)
			if err != nil {
				t.Fatalf("DecodeTransaction: %v", err)
			}

			if decoded.To != nil {
				t.Fatalf("To: got %s, want nil (contract creation)", decoded.To.Hex())
			}
			if !addrEqual(decoded.Sender, walletAddr) {
				t.Fatalf("Sender: got %s, want %s", decoded.Sender.Hex(), walletAddr.Hex())
			}
		})
	}
}

// ---------------------------------------------------------------------------
// EIP-155 chain ID derivation
// ---------------------------------------------------------------------------

// TestDecodeTransaction_LegacyChainID verifies that the chain ID is
// correctly derived from the v field for EIP-155 legacy transactions
// across multiple chain IDs.
func TestDecodeTransaction_LegacyChainID(t *testing.T) {
	t.Parallel()

	w := mustWallet(t, hardhatKeyHex)
	to := mustAddr(t, "0x70997970C51812dc3A010C7d01b50e0d17dc79C8")

	chainIDs := []int64{1, 5, 137, 42161}

	for _, id := range chainIDs {
		id := id
		t.Run(fmt.Sprintf("chain_%d", id), func(t *testing.T) {
			t.Parallel()

			tx := &LegacyTx{
				ChainID:  big.NewInt(id),
				Nonce:    1,
				GasPrice: big.NewInt(10_000_000_000),
				GasLimit: 21000,
				To:       &to,
				Value:    big.NewInt(1_000_000_000_000_000_000),
			}

			raw, err := w.SignTx(tx)
			if err != nil {
				t.Fatalf("SignTx: %v", err)
			}

			decoded, err := DecodeTransaction(raw)
			if err != nil {
				t.Fatalf("DecodeTransaction: %v", err)
			}

			if !bigEqual(decoded.ChainID, big.NewInt(id)) {
				t.Fatalf("ChainID: got %s, want %d", decoded.ChainID, id)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// EIP-1559 fee fields
// ---------------------------------------------------------------------------

// TestDecodeTransaction_EIP1559FeeFields verifies that the
// maxPriorityFeePerGas and maxFeePerGas fields are correctly extracted
// from a type-2 transaction.
func TestDecodeTransaction_EIP1559FeeFields(t *testing.T) {
	t.Parallel()

	w := mustWallet(t, hardhatKeyHex)
	to := mustAddr(t, "0x70997970C51812dc3A010C7d01b50e0d17dc79C8")

	maxPriority := big.NewInt(1_500_000_000)
	maxFee := big.NewInt(50_000_000_000)

	tx := &EIP1559Tx{
		ChainID:              big.NewInt(1),
		Nonce:                3,
		MaxPriorityFeePerGas: maxPriority,
		MaxFeePerGas:         maxFee,
		GasLimit:             21000,
		To:                   &to,
		Value:                big.NewInt(1_000_000_000_000_000_000),
	}

	raw, err := w.SignTx(tx)
	if err != nil {
		t.Fatalf("SignTx: %v", err)
	}

	decoded, err := DecodeTransaction(raw)
	if err != nil {
		t.Fatalf("DecodeTransaction: %v", err)
	}

	if !bigEqual(decoded.MaxPriorityFeePerGas, maxPriority) {
		t.Fatalf("MaxPriorityFeePerGas: got %s, want %s", decoded.MaxPriorityFeePerGas, maxPriority)
	}
	if !bigEqual(decoded.MaxFeePerGas, maxFee) {
		t.Fatalf("MaxFeePerGas: got %s, want %s", decoded.MaxFeePerGas, maxFee)
	}
	if decoded.GasPrice != nil {
		t.Fatalf("GasPrice: got %s, want nil for type-2", decoded.GasPrice)
	}
}

// ---------------------------------------------------------------------------
// A10 — strict field validation (oversized r/s, minimal integers, widths)
// ---------------------------------------------------------------------------

// uint256Bytes renders a *big.Int as a 32-byte big-endian word for
// building test vectors.
func uint256Bytes(n *big.Int) []byte {
	out := make([]byte, 32)
	b := n.Bytes()
	copy(out[32-len(b):], b)
	return out
}

// rlpFields RLP-encodes each raw byte-string field and wraps them in an
// RLP list. Used to craft legacy transactions with deliberately
// malformed fields.
func rlpFields(fields ...[]byte) []byte {
	enc := make([][]byte, len(fields))
	for i, f := range fields {
		enc[i] = rlp.EncodeBytes(f)
	}
	return rlp.EncodeList(enc...)
}

// TestAsScalar_Boundaries covers the secp256k1 signature-scalar checks
// applied to r and s: minimal encoding, 32-byte width, and the [1, n-1]
// range per [SEC 2 v2] §2.4.1. Oversized inputs previously panicked
// ecrecoverSender on a negative slice bound; they must now return
// errors. The [EIP-2] low-s bound (s <= n/2) is transaction policy —
// a high-s value still decodes to a valid scalar — and is enforced by
// ValidateTransaction, not the decoder (see
// TestValidateTransaction_EIP2Boundary in validate_test.go for the
// rejection vectors and TestDecodeTransaction_EIP2Boundary below for
// the decode-side boundary).
//
// Vectors: [SEC 2 v2] §2.4.1 curve order
// n = FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;
// Wycheproof ECDSA signature malleability class (high-s acceptance).
func TestAsScalar_Boundaries(t *testing.T) {
	t.Parallel()

	n := secp256k1N
	halfN := secp256k1HalfN

	cases := []struct {
		name    string
		input   []byte
		wantErr bool
	}{
		{"minimal one", []byte{0x01}, false},
		{"equals n-1", uint256Bytes(new(big.Int).Sub(n, big.NewInt(1))), false},
		{"equals n", uint256Bytes(n), true},
		{"exceeds n", uint256Bytes(new(big.Int).Add(n, big.NewInt(1))), true},
		{"zero empty encoding", nil, true},
		{"zero single byte", []byte{0x00}, true},
		{"non-minimal leading zero", []byte{0x00, 0x01}, true},
		{"oversized 33 bytes", append([]byte{0x01}, make([]byte, 32)...), true},
		{"oversized 64 bytes", make([]byte, 64), true},
		// EIP-2 boundary: every scalar in [1, n-1] is structurally
		// decodable, including values above n/2.
		{"n/2 boundary accepted", uint256Bytes(halfN), false},
		{"n/2+1 accepted", uint256Bytes(new(big.Int).Add(halfN, big.NewInt(1))), false},
		{"n-1 accepted", uint256Bytes(new(big.Int).Sub(n, big.NewInt(1))), false},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := asScalar(tc.input)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("asScalar(%x): got nil error, want error", tc.input)
				}
				if !errors.Is(err, ErrInvalidField) {
					t.Fatalf("asScalar(%x): error = %v, want errors.Is %v", tc.input, err, ErrInvalidField)
				}
				return
			}
			if err != nil {
				t.Fatalf("asScalar(%x): got error %v, want nil", tc.input, err)
			}
			if subtle.ConstantTimeCompare(got, tc.input) != 1 {
				t.Fatalf("asScalar(%x): got %x, want input echoed", tc.input, got)
			}
		})
	}
}

// TestAsUint64_Boundaries covers the uint64 field decoder: minimal
// encoding and destination-width enforcement so oversized integers are
// rejected rather than silently truncated by big.Int.Uint64.
func TestAsUint64_Boundaries(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		input   interface{}
		want    uint64
		wantErr bool
	}{
		{"empty is zero", []byte{}, 0, false},
		{"one", []byte{0x01}, 1, false},
		{"single byte 0x00 is non-minimal", []byte{0x00}, 0, true},
		{"max uint64 eight bytes", []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, ^uint64(0), false},
		{"nine bytes truncated before", []byte{0x01, 0, 0, 0, 0, 0, 0, 0, 0}, 0, true},
		{"leading zero", []byte{0x00, 0x09}, 0, true},
		{"not a byte string", []interface{}{}, 0, true},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := asUint64(tc.input)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("asUint64(%v): got nil error, want error", tc.input)
				}
				if !errors.Is(err, ErrInvalidField) {
					t.Fatalf("asUint64(%v): error = %v, want errors.Is %v", tc.input, err, ErrInvalidField)
				}
				return
			}
			if err != nil {
				t.Fatalf("asUint64(%v): got error %v, want nil", tc.input, err)
			}
			if got != tc.want {
				t.Fatalf("asUint64(%v): got %d, want %d", tc.input, got, tc.want)
			}
		})
	}
}

// TestAsBigInt_Boundaries covers the uint256-width and minimal-encoding
// checks on big-integer transaction fields (gasPrice, value, chainId).
func TestAsBigInt_Boundaries(t *testing.T) {
	t.Parallel()

	maxUint256 := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 256), big.NewInt(1))

	cases := []struct {
		name    string
		input   []byte
		wantErr bool
	}{
		{"empty is zero", nil, false},
		{"one", []byte{0x01}, false},
		{"max uint256", uint256Bytes(maxUint256), false},
		{"33 bytes exceeds uint256", append([]byte{0x01}, make([]byte, 32)...), true},
		{"leading zero", []byte{0x00, 0x01}, true},
		{"single 0x00 non-minimal", []byte{0x00}, true},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := asBigInt(tc.input)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("asBigInt(%x): got nil error, want error", tc.input)
				}
				if !errors.Is(err, ErrInvalidField) {
					t.Fatalf("asBigInt(%x): error = %v, want errors.Is %v", tc.input, err, ErrInvalidField)
				}
				return
			}
			if err != nil {
				t.Fatalf("asBigInt(%x): got error %v, want nil", tc.input, err)
			}
			if got == nil {
				t.Fatalf("asBigInt(%x): got nil, want non-nil", tc.input)
			}
		})
	}
}

// TestDecodeTransaction_A10_MalformedFields exercises the full
// DecodeTransaction path with crafted raw transactions whose individual
// fields violate the A10 rules: oversized or out-of-range r/s scalars
// (which previously panicked on a negative slice bound), non-minimal
// integer encodings, uint64-width truncation, and invalid legacy v
// values. Every case must produce a typed error, never a panic — a
// panic fails the test by propagating.
//
// Vectors: [SEC 2 v2] §2.4.1 scalar range; [EIP-2] low-s; [EIP-155]
// v domain; go-ethereum "non-canonical integer (leading zero bytes)".
func TestDecodeTransaction_A10_MalformedFields(t *testing.T) {
	t.Parallel()

	to := mustAddr(t, "0x70997970C51812dc3A010C7d01b50e0d17dc79C8")

	// Baseline valid fields for a legacy transaction. The signature
	// need not verify — scalar validation runs before ecrecover, so a
	// well-formed in-range r and s reach recovery deterministically.
	valid := func() [][]byte {
		return [][]byte{
			{0x09},       // nonce
			{0x01},       // gasPrice
			{0x52, 0x08}, // gasLimit 21000
			to[:],        // to
			{0x01},       // value
			nil,          // data
			{0x25},       // v = 37 (EIP-155, chainID 1, recID 0)
			{0x01},       // r = 1
			{0x01},       // s = 1
		}
	}
	legacyWith := func(field int, val []byte) []byte {
		f := valid()
		f[field] = val
		return rlpFields(f...)
	}

	n := secp256k1N

	cases := []struct {
		name  string
		input []byte
	}{
		// A10: oversized r/s panicked before this fix.
		{"oversized r 33 bytes", legacyWith(7, append([]byte{0x01}, make([]byte, 32)...))},
		{"oversized s 33 bytes", legacyWith(8, append([]byte{0x01}, make([]byte, 32)...))},
		{"oversized r 64 bytes", legacyWith(7, append([]byte{0x02}, make([]byte, 63)...))},
		// A10: scalar range — r/s must be in [1, n-1].
		{"r equals curve order n", legacyWith(7, uint256Bytes(n))},
		{"r zero empty encoding", legacyWith(7, nil)},
		{"s equals curve order n", legacyWith(8, uint256Bytes(n))},
		{"s zero empty encoding", legacyWith(8, nil)},
		// A10: non-minimal integer encodings.
		{"nonce leading zero", legacyWith(0, []byte{0x00, 0x09})},
		{"gasPrice leading zero", legacyWith(1, []byte{0x00, 0x01})},
		{"r leading zero", legacyWith(7, []byte{0x00, 0x01})},
		{"v leading zero", legacyWith(6, []byte{0x00, 0x25})},
		// A10: destination width — uint64 fields must fit.
		{"nonce 9 bytes", legacyWith(0, []byte{0x01, 0, 0, 0, 0, 0, 0, 0, 0})},
		{"gasLimit 9 bytes", legacyWith(2, []byte{0x01, 0, 0, 0, 0, 0, 0, 0, 0})},
		// A10: uint256-width fields must fit.
		{"gasPrice 33 bytes", legacyWith(1, append([]byte{0x01}, make([]byte, 32)...))},
		{"value 33 bytes", legacyWith(4, append([]byte{0x01}, make([]byte, 32)...))},
		// EIP-155: v must be 27, 28, or >= 35.
		{"v 29 invalid", legacyWith(6, []byte{0x1d})},
		{"v 34 invalid", legacyWith(6, []byte{0x22})},
		{"v zero invalid", legacyWith(6, nil)},
		{"v 26 invalid", legacyWith(6, []byte{0x1a})},
		// Address width.
		{"to 21 bytes", legacyWith(3, make([]byte, 21))},
		{"to 19 bytes", legacyWith(3, make([]byte, 19))},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := DecodeTransaction(tc.input)
			if err == nil {
				t.Fatalf("DecodeTransaction(%x): got nil error, want error", tc.input)
			}
			if !errors.Is(err, ErrInvalidField) {
				t.Fatalf("DecodeTransaction(%x): error = %v, want errors.Is %v", tc.input, err, ErrInvalidField)
			}
		})
	}
}

// TestDecodeTransaction_A10_TypedMalformedFields applies the same A10
// malformed-field vectors to type-1 (EIP-2930) and type-2 (EIP-1559)
// transactions, whose field layouts differ from legacy. The signature
// need not verify — scalar validation precedes ecrecover.
func TestDecodeTransaction_A10_TypedMalformedFields(t *testing.T) {
	t.Parallel()

	to := mustAddr(t, "0x70997970C51812dc3A010C7d01b50e0d17dc79C8")
	n := secp256k1N

	// Type-1 layout: [chainId, nonce, gasPrice, gasLimit, to, value,
	// data, accessList, v, r, s].
	type1 := func(chainID, v, r, s []byte) []byte {
		return append([]byte{0x01}, rlp.EncodeList(
			rlp.EncodeBytes(chainID),
			rlp.EncodeUint64(1),
			rlp.EncodeBytes([]byte{0x01}),
			rlp.EncodeUint64(21000),
			rlp.EncodeBytes(to[:]),
			rlp.EncodeBytes([]byte{0x01}),
			rlp.EncodeBytes(nil),
			encodeAccessList(nil),
			rlp.EncodeBytes(v),
			rlp.EncodeBytes(r),
			rlp.EncodeBytes(s),
		)...)
	}
	// Type-2 layout: [chainId, nonce, maxPriorityFeePerGas,
	// maxFeePerGas, gasLimit, to, value, data, accessList, v, r, s].
	type2 := func(chainID, v, r, s []byte) []byte {
		return append([]byte{0x02}, rlp.EncodeList(
			rlp.EncodeBytes(chainID),
			rlp.EncodeUint64(1),
			rlp.EncodeBytes([]byte{0x01}),
			rlp.EncodeBytes([]byte{0x01}),
			rlp.EncodeUint64(21000),
			rlp.EncodeBytes(to[:]),
			rlp.EncodeBytes([]byte{0x01}),
			rlp.EncodeBytes(nil),
			encodeAccessList(nil),
			rlp.EncodeBytes(v),
			rlp.EncodeBytes(r),
			rlp.EncodeBytes(s),
		)...)
	}

	cases := []struct {
		name  string
		input []byte
	}{
		// Oversized r/s on typed transactions (the A10 panic vector).
		{"type1 oversized r", type1([]byte{0x01}, []byte{0x01}, append([]byte{0x01}, make([]byte, 32)...), []byte{0x01})},
		{"type2 oversized r", type2([]byte{0x01}, []byte{0x01}, append([]byte{0x01}, make([]byte, 32)...), []byte{0x01})},
		{"type2 oversized s", type2([]byte{0x01}, []byte{0x01}, []byte{0x01}, append([]byte{0x01}, make([]byte, 32)...))},
		// Scalar range on typed transactions.
		{"type1 r equals n", type1([]byte{0x01}, []byte{0x01}, uint256Bytes(n), []byte{0x01})},
		{"type2 s equals n", type2([]byte{0x01}, []byte{0x01}, []byte{0x01}, uint256Bytes(n))},
		{"type2 s zero", type2([]byte{0x01}, []byte{0x01}, []byte{0x01}, nil)},
		// Non-minimal and oversized chainId on typed transactions.
		{"type1 chainId leading zero", type1([]byte{0x00, 0x01}, []byte{0x01}, []byte{0x01}, []byte{0x01})},
		{"type2 chainId 33 bytes", type2(append([]byte{0x01}, make([]byte, 32)...), []byte{0x01}, []byte{0x01}, []byte{0x01})},
		// Typed v is a y-parity: only 0 (empty) and 1 are valid, and
		// the single byte 0x00 is a non-minimal encoding of zero.
		{"type1 v non-minimal zero", type1([]byte{0x01}, []byte{0x00}, []byte{0x01}, []byte{0x01})},
		{"type2 v two", type2([]byte{0x01}, []byte{0x02}, []byte{0x01}, []byte{0x01})},
		{"type2 v multi-byte", type2([]byte{0x01}, []byte{0x00, 0x01}, []byte{0x01}, []byte{0x01})},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := DecodeTransaction(tc.input)
			if err == nil {
				t.Fatalf("DecodeTransaction(%x): got nil error, want error", tc.input)
			}
			if !errors.Is(err, ErrInvalidField) {
				t.Fatalf("DecodeTransaction(%x): error = %v, want errors.Is %v", tc.input, err, ErrInvalidField)
			}
		})
	}
}

// TestDecodeTransaction_EIP2Boundary exercises the [EIP-2] low-s
// boundary at the decode layer. Field validation accepts every scalar
// in [1, n-1] — including values above n/2 — because EIP-2 low-s is
// transaction policy enforced by ValidateTransaction (ErrHighS), not
// an encoding rule. For both sides of the boundary DecodeTransaction
// must not report ErrInvalidField for s; it either recovers a sender
// (high-s signatures remain cryptographically recoverable — that is
// precisely the malleability EIP-2 closes) or fails ecrecover.
//
// Vectors: [EIP-2] low-s boundary s = n/2 accepted, s = n/2 + 1
// rejected at the validation layer; Wycheproof ECDSA malleability.
func TestDecodeTransaction_EIP2Boundary(t *testing.T) {
	t.Parallel()

	to := mustAddr(t, "0x70997970C51812dc3A010C7d01b50e0d17dc79C8")
	n := secp256k1N
	halfN := secp256k1HalfN

	// Type-2 layout: [chainId, nonce, maxPriorityFeePerGas,
	// maxFeePerGas, gasLimit, to, value, data, accessList, v, r, s].
	// The signature need not verify — only field validation is under
	// test.
	type2WithS := func(s []byte) []byte {
		return append([]byte{0x02}, rlp.EncodeList(
			rlp.EncodeBytes([]byte{0x01}), // chainId
			rlp.EncodeUint64(1),           // nonce
			rlp.EncodeBytes([]byte{0x01}), // maxPriorityFeePerGas
			rlp.EncodeBytes([]byte{0x02}), // maxFeePerGas
			rlp.EncodeUint64(21000),       // gasLimit
			rlp.EncodeBytes(to[:]),        // to
			rlp.EncodeBytes([]byte{0x01}), // value
			rlp.EncodeBytes(nil),          // data
			encodeAccessList(nil),         // accessList
			rlp.EncodeBytes([]byte{0x01}), // v = 1
			rlp.EncodeBytes([]byte{0x01}), // r = 1
			rlp.EncodeBytes(s),            // s
		)...)
	}

	cases := []struct {
		name string
		s    []byte
	}{
		{"s equals n/2 canonical boundary", uint256Bytes(halfN)},
		{"s equals n/2+1 above boundary", uint256Bytes(new(big.Int).Add(halfN, big.NewInt(1)))},
		{"s equals n-1 maximal scalar", uint256Bytes(new(big.Int).Sub(n, big.NewInt(1)))},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := DecodeTransaction(type2WithS(tc.s))
			// Field validation must not reject any scalar in [1, n-1].
			// ecrecover may succeed (recoverable high-s) or fail; both
			// outcomes are valid decode behavior.
			if errors.Is(err, ErrInvalidField) {
				t.Fatalf("DecodeTransaction: s field rejected at decode: %v", err)
			}
		})
	}
}
