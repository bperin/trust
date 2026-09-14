package wallet

import (
	"fmt"
	"math/big"

	"github.com/bperin/trust/chain/ethereum"
	"github.com/bperin/trust/chain/rlp"
	"github.com/bperin/trust/crypto/hash"
)

// Transaction is an [EIP-2718] typed transaction. Type returns the
// transaction type byte, SigningHash returns the Keccak-256 digest to
// sign, and EncodeSigned returns the signed RLP encoding ready for
// broadcast.
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
// replay protection: the signed v field is recID + 35 + chainID*2.
// Legacy transactions carry no access list.
type LegacyTx struct {
	ChainID  *big.Int
	Nonce    uint64
	GasPrice *big.Int
	GasLimit uint64
	To       *ethereum.Address // nil = contract creation
	Value    *big.Int
	Data     []byte
}

// Type returns 0 (legacy).
func (tx *LegacyTx) Type() byte { return 0 }

// SigningHash returns the Keccak-256 digest of the RLP-encoded
// pre-image [nonce, gasPrice, gasLimit, to, value, data, chainID, 0, 0]
// per [EIP-155]. The two trailing zeros are placeholder r and s fields.
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

// AccessListEntry is an [EIP-2930] access list entry: a contract
// address and the storage keys the transaction may access. An empty
// StorageKeys list warms only the account.
type AccessListEntry struct {
	Address     [20]byte
	StorageKeys [][32]byte
}

// EIP1559Tx is a type-2 [EIP-1559] fee-market transaction. The signed
// v field is the y-parity (0 or 1), not the legacy [EIP-155] form.
type EIP1559Tx struct {
	ChainID              *big.Int
	Nonce                uint64
	MaxPriorityFeePerGas *big.Int
	MaxFeePerGas         *big.Int
	GasLimit             uint64
	To                   *ethereum.Address // nil = contract creation
	Value                *big.Int
	Data                 []byte
	AccessList           []AccessListEntry
}

// Type returns 2 ([EIP-1559]).
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
// gasLimit, to, value, data, accessList, v, r, s]) where v is the
// y-parity.
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
		encodeBig(new(big.Int).SetBytes(v)),
		encodeBytes(r),
		encodeBytes(s),
	)
	return append([]byte{0x02}, body...), nil
}

// EIP2930Tx is a type-1 [EIP-2930] access-list transaction. It keeps
// the legacy gas-price fee model and adds an access list. The signed
// v field is the y-parity (0 or 1), not the legacy [EIP-155] form.
type EIP2930Tx struct {
	ChainID    *big.Int
	Nonce      uint64
	GasPrice   *big.Int
	GasLimit   uint64
	To         *ethereum.Address // nil = contract creation
	Value      *big.Int
	Data       []byte
	AccessList []AccessListEntry
}

// Type returns 1 ([EIP-2930]).
func (tx *EIP2930Tx) Type() byte { return 1 }

// SigningHash returns the Keccak-256 digest of the [EIP-2718] typed
// pre-image: 0x01 || rlp([chainId, nonce, gasPrice, gasLimit, to,
// value, data, accessList]). A nil access list encodes as the empty
// RLP list (0xc0).
func (tx *EIP2930Tx) SigningHash() ([]byte, error) {
	if tx.ChainID == nil || tx.ChainID.Sign() == 0 {
		return nil, fmt.Errorf("wallet: eip-2930 tx requires non-zero chain ID")
	}
	accessListEnc := encodeAccessList(tx.AccessList)
	preimage := append([]byte{0x01},
		rlp.EncodeList(
			encodeBig(tx.ChainID),
			rlp.EncodeUint64(tx.Nonce),
			encodeBig(tx.GasPrice),
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
// 0x01 || rlp([chainId, nonce, gasPrice, gasLimit, to, value, data,
// accessList, v, r, s]) where v is the y-parity.
func (tx *EIP2930Tx) EncodeSigned(r, s, v []byte) ([]byte, error) {
	if tx.ChainID == nil || tx.ChainID.Sign() == 0 {
		return nil, fmt.Errorf("wallet: eip-2930 tx requires non-zero chain ID")
	}
	accessListEnc := encodeAccessList(tx.AccessList)
	body := rlp.EncodeList(
		encodeBig(tx.ChainID),
		rlp.EncodeUint64(tx.Nonce),
		encodeBig(tx.GasPrice),
		rlp.EncodeUint64(tx.GasLimit),
		encodeAddr(tx.To),
		encodeBig(tx.Value),
		encodeBytes(tx.Data),
		accessListEnc,
		encodeBig(new(big.Int).SetBytes(v)),
		encodeBytes(r),
		encodeBytes(s),
	)
	return append([]byte{0x01}, body...), nil
}

// encodeAccessList encodes the access list as an RLP list of
// [address, [storageKeys...]] pairs. An empty or nil access list
// encodes as the empty RLP list (0xc0).
func encodeAccessList(accessList []AccessListEntry) []byte {
	if len(accessList) == 0 {
		return rlp.EncodeList()
	}
	items := make([][]byte, 0, len(accessList))
	for _, entry := range accessList {
		// Each entry is rlp([address, [storageKey1, storageKey2, ...]]).
		storageItems := make([][]byte, 0, len(entry.StorageKeys))
		for _, key := range entry.StorageKeys {
			storageItems = append(storageItems, rlp.EncodeBytes(key[:]))
		}
		items = append(items, rlp.EncodeList(
			rlp.EncodeBytes(entry.Address[:]),
			rlp.EncodeList(storageItems...),
		))
	}
	return rlp.EncodeList(items...)
}
