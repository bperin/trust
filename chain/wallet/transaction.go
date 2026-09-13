package wallet

import (
	"fmt"
	"math/big"

	"github.com/bperin/chain/ethereum"
	"github.com/bperin/chain/rlp"
	"github.com/bperin/trust/crypto/hash"
)

// Transaction is the [EIP-2718] typed-transaction interface. Each
// concrete transaction type implements this interface so the wallet's
// SignTx dispatch is type-agnostic. Adding a future transaction type
// (e.g. [EIP-4844] type 3) is a new struct — no wallet change.
//
//   - Type returns the [EIP-2718] transaction type byte.
//   - SigningHash returns the 32-byte Keccak-256 digest the signer
//     signs.
//   - EncodeSigned returns the fully RLP-encoded signed transaction
//     ready for broadcast.
type Transaction interface {
	Type() byte
	SigningHash() ([]byte, error)
	EncodeSigned(r, s, v []byte) ([]byte, error)
}

// encodeBig encodes a *big.Int as an RLP byte string using Ethereum's
// integer convention (minimal big-endian, leading zeros stripped).
// A nil or zero big.Int encodes as the empty byte string (0x80).
func encodeBig(n *big.Int) []byte {
	if n == nil || n.Sign() == 0 {
		return rlp.EncodeBytes(nil)
	}
	return rlp.EncodeBytes(n.Bytes())
}

// encodeAddr encodes an Ethereum address as a 20-byte RLP byte string.
// A nil address (contract creation) encodes as the empty byte string.
func encodeAddr(addr *ethereum.Address) []byte {
	if addr == nil {
		return rlp.EncodeBytes(nil)
	}
	return rlp.EncodeBytes(addr[:])
}

// encodeBytes encodes a byte slice as an RLP byte string.
func encodeBytes(b []byte) []byte {
	return rlp.EncodeBytes(b)
}

// keccak256 returns the 32-byte Keccak-256 digest of data.
func keccak256(data []byte) []byte {
	return hash.NewKeccak256().SumBytes(data)
}

// LegacyTx is a type-0 legacy transaction with [EIP-155] chain-ID
// replay protection. The signed v field is computed as
// recID + 35 + chainID*2 per [EIP-155].
type LegacyTx struct {
	ChainID    *big.Int
	Nonce      uint64
	GasPrice   *big.Int
	GasLimit   uint64
	To         *ethereum.Address // nil = contract creation
	Value      *big.Int
	Data       []byte
	AccessList [][]byte // unused for legacy; present for interface parity
}

// Type returns 0 (legacy) per [EIP-2718].
func (tx *LegacyTx) Type() byte { return 0 }

// SigningHash returns the Keccak-256 digest of the RLP-encoded
// pre-image [nonce, gasPrice, gasLimit, to, value, data, chainID, 0, 0]
// per [EIP-155]. The two trailing zeros are the placeholder r and s
// fields that make the pre-image distinct from the signed form.
func (tx *LegacyTx) SigningHash() ([]byte, error) {
	if tx.ChainID == nil || tx.ChainID.Sign() == 0 {
		return nil, fmt.Errorf("wallet: legacy tx requires non-zero chain ID")
	}
	preimage := rlp.EncodeList(
		rlp.EncodeUint64(tx.Nonce),
		encodeBig(tx.GasPrice),
		rlp.EncodeUint64(tx.GasLimit),
		encodeAddr(tx.To),
		encodeBig(tx.Value),
		encodeBytes(tx.Data),
		encodeBig(tx.ChainID),
		rlp.EncodeUint64(0),
		rlp.EncodeUint64(0),
	)
	return keccak256(preimage), nil
}

// EncodeSigned returns the RLP-encoded signed legacy transaction:
// [nonce, gasPrice, gasLimit, to, value, data, v, r, s] where
// v = recID + 35 + chainID*2 per [EIP-155].
func (tx *LegacyTx) EncodeSigned(r, s, v []byte) ([]byte, error) {
	if tx.ChainID == nil || tx.ChainID.Sign() == 0 {
		return nil, fmt.Errorf("wallet: legacy tx requires non-zero chain ID")
	}
	return rlp.EncodeList(
		rlp.EncodeUint64(tx.Nonce),
		encodeBig(tx.GasPrice),
		rlp.EncodeUint64(tx.GasLimit),
		encodeAddr(tx.To),
		encodeBig(tx.Value),
		encodeBytes(tx.Data),
		encodeBytes(v),
		encodeBytes(r),
		encodeBytes(s),
	), nil
}

// EIP1559Tx is a type-2 [EIP-1559] fee-market transaction wrapped in an
// [EIP-2718] typed envelope. The signed v field is the y-parity
// (0 or 1), not the legacy [EIP-155] form.
type EIP1559Tx struct {
	ChainID              *big.Int
	Nonce                uint64
	MaxPriorityFeePerGas *big.Int
	MaxFeePerGas         *big.Int
	GasLimit             uint64
	To                   *ethereum.Address // nil = contract creation
	Value                *big.Int
	Data                 []byte
	AccessList           [][]byte
}

// Type returns 2 ([EIP-1559]) per [EIP-2718].
func (tx *EIP1559Tx) Type() byte { return 2 }

// SigningHash returns the Keccak-256 digest of the [EIP-2718] typed
// pre-image: 0x02 || rlp([chainID, nonce, maxPriorityFeePerGas,
// maxFeePerGas, gasLimit, to, value, data, accessList]).
func (tx *EIP1559Tx) SigningHash() ([]byte, error) {
	if tx.ChainID == nil || tx.ChainID.Sign() == 0 {
		return nil, fmt.Errorf("wallet: eip-1559 tx requires non-zero chain ID")
	}
	accessListEnc := encodeAccessList(tx.AccessList)
	preimage := append([]byte{0x02},
		rlp.EncodeList(
			encodeBig(tx.ChainID),
			rlp.EncodeUint64(tx.Nonce),
			encodeBig(tx.MaxPriorityFeePerGas),
			encodeBig(tx.MaxFeePerGas),
			rlp.EncodeUint64(tx.GasLimit),
			encodeAddr(tx.To),
			encodeBig(tx.Value),
			encodeBytes(tx.Data),
			accessListEnc,
		)...,
	)
	return keccak256(preimage), nil
}

// EncodeSigned returns the [EIP-2718] typed envelope:
// 0x02 || rlp([chainID, nonce, maxPriorityFeePerGas, maxFeePerGas,
// gasLimit, to, value, data, accessList, v, r, s]) where v = recID
// (y-parity, 0 or 1) per [EIP-1559].
func (tx *EIP1559Tx) EncodeSigned(r, s, v []byte) ([]byte, error) {
	if tx.ChainID == nil || tx.ChainID.Sign() == 0 {
		return nil, fmt.Errorf("wallet: eip-1559 tx requires non-zero chain ID")
	}
	accessListEnc := encodeAccessList(tx.AccessList)
	body := rlp.EncodeList(
		encodeBig(tx.ChainID),
		rlp.EncodeUint64(tx.Nonce),
		encodeBig(tx.MaxPriorityFeePerGas),
		encodeBig(tx.MaxFeePerGas),
		rlp.EncodeUint64(tx.GasLimit),
		encodeAddr(tx.To),
		encodeBig(tx.Value),
		encodeBytes(tx.Data),
		accessListEnc,
		encodeBytes(v),
		encodeBytes(r),
		encodeBytes(s),
	)
	return append([]byte{0x02}, body...), nil
}

// encodeAccessList encodes the [EIP-2930] access list as an RLP list
// of address+storage-keys pairs. An empty or nil access list encodes
// as an empty RLP list (0xc0).
func encodeAccessList(accessList [][]byte) []byte {
	if len(accessList) == 0 {
		return rlp.EncodeList()
	}
	items := make([][]byte, 0, len(accessList))
	for _, entry := range accessList {
		// Each entry is itself a list [address, [storageKeys...]].
		// For simplicity, we encode each raw entry as a byte string
		// inside the access-list list. A full implementation would
		// parse structured entries; this minimal form is sufficient
		// for the empty-access-list case used by EIP-1559.
		items = append(items, encodeBytes(entry))
	}
	return rlp.EncodeList(items...)
}
