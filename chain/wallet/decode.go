package wallet

import (
	"errors"
	"fmt"
	"math/big"

	"github.com/bperin/trust/chain/ethereum"
	"github.com/bperin/trust/chain/rlp"
	"github.com/bperin/trust/trust/crypto/secp256k1"
)

// Sentinel errors returned by DecodeTransaction. Check with errors.Is;
// wrap with fmt.Errorf and %w at boundaries.
var (
	// ErrEmptyInput indicates the raw transaction input was empty or nil.
	ErrEmptyInput = errors.New("wallet: empty transaction input")
	// ErrInvalidType indicates the [EIP-2718] type byte was not a
	// recognized transaction type (0 legacy, 1 EIP-2930, 2 EIP-1559).
	ErrInvalidType = errors.New("wallet: invalid transaction type byte")
	// ErrDecodeFailed indicates the RLP payload could not be decoded.
	ErrDecodeFailed = errors.New("wallet: rlp decode failed")
	// ErrInvalidField indicates a decoded field had the wrong type,
	// length, or structure.
	ErrInvalidField = errors.New("wallet: invalid transaction field")
	// ErrRecoverFailed indicates ecrecover could not recover a public
	// key from the signature and signing hash.
	ErrRecoverFailed = errors.New("wallet: ecrecover failed")
)

// DecodedTx is a read-only view of a decoded [EIP-2718] typed
// transaction. It carries all transaction fields, the r/s/v signature
// components, and the sender address recovered via ecrecover.
//
// DecodedTx does NOT implement [Transaction] — it is not re-signable
// or re-encodable. It is the output of [DecodeTransaction] for
// inspection, verification, and display. The Type byte discriminates
// the transaction family:
//
//   - 0: legacy ([EIP-155]) — GasPrice, V, R, S populated;
//     MaxPriorityFeePerGas, MaxFeePerGas, AccessList are zero/nil.
//   - 1: [EIP-2930] — GasPrice, AccessList, V, R, S populated;
//     MaxPriorityFeePerGas, MaxFeePerGas are nil.
//   - 2: [EIP-1559] — MaxPriorityFeePerGas, MaxFeePerGas, AccessList,
//     V, R, S populated; GasPrice is nil.
//
// For legacy transactions, ChainID is derived from v per [EIP-155]:
// v == 27 or 28 indicates a pre-EIP-155 transaction with no chain ID
// (ChainID is nil); otherwise ChainID = (v - 35) / 2.
//
// [EIP-2718]: https://eips.ethereum.org/EIPS/eip-2718
// [EIP-155]: https://eips.ethereum.org/EIPS/eip-155
// [EIP-2930]: https://eips.ethereum.org/EIPS/eip-2930
// [EIP-1559]: https://eips.ethereum.org/EIPS/eip-1559
type DecodedTx struct {
	// Type is the [EIP-2718] transaction type byte (0, 1, or 2).
	Type byte
	// ChainID is the [EIP-155] chain ID. Nil for pre-EIP-155 legacy
	// transactions (v == 27 or 28).
	ChainID *big.Int
	// Nonce is the account nonce.
	Nonce uint64
	// GasPrice is the legacy/type-1 gas price. Nil for type-2.
	GasPrice *big.Int
	// MaxPriorityFeePerGas is the [EIP-1559] priority fee. Nil for
	// type-0 and type-1.
	MaxPriorityFeePerGas *big.Int
	// MaxFeePerGas is the [EIP-1559] max fee per gas. Nil for type-0
	// and type-1.
	MaxFeePerGas *big.Int
	// GasLimit is the gas limit.
	GasLimit uint64
	// To is the recipient address. Nil for contract creation.
	To *ethereum.Address
	// Value is the ether value transferred.
	Value *big.Int
	// Data is the calldata.
	Data []byte
	// AccessList is the [EIP-2930] access list. Nil for legacy.
	AccessList []AccessListEntry
	// V is the raw decoded v field. For legacy this is the [EIP-155]
	// form (recID + 35 + chainID*2); for type-1 and type-2 it is the
	// y-parity (0 or 1).
	V []byte
	// R is the r component of the signature.
	R []byte
	// S is the s component of the signature.
	S []byte
	// Sender is the [EIP-55] address recovered via ecrecover.
	Sender ethereum.Address
}

// DecodeTransaction decodes a raw [EIP-2718] typed transaction into a
// read-only [DecodedTx]. It dispatches on the first byte:
//
//   - >= 0xc0 → legacy (type 0, bare RLP list per the Yellow Paper)
//   - 0x01    → [EIP-2930] typed transaction
//   - 0x02    → [EIP-1559] typed transaction
//   - else    → [ErrInvalidType]
//
// For each type, the payload is RLP-decoded, all fields are extracted
// with careful type assertions (rlp.Decode returns interface{} —
// []byte for byte strings, []interface{} for lists), the signing hash
// is recomputed, and the sender is recovered via ecrecover
// ([SEC 1 v2] §4.3.3) and derived to an [EIP-55] address.
//
// Empty or nil input returns [ErrEmptyInput].
//
// [EIP-2718]: https://eips.ethereum.org/EIPS/eip-2718
func DecodeTransaction(raw []byte) (*DecodedTx, error) {
	if len(raw) == 0 {
		return nil, ErrEmptyInput
	}
	switch {
	case raw[0] >= 0xc0:
		return decodeLegacy(raw)
	case raw[0] == 0x01:
		return decodeEIP2930(raw[1:])
	case raw[0] == 0x02:
		return decodeEIP1559(raw[1:])
	default:
		return nil, fmt.Errorf("%w: 0x%02x", ErrInvalidType, raw[0])
	}
}

// decodeLegacy decodes a type-0 legacy transaction:
// rlp([nonce, gasPrice, gasLimit, to, value, data, v, r, s]).
//
// The chain ID is derived from v per [EIP-155]: v == 27 or 28 indicates
// a pre-EIP-155 transaction (no chain ID); otherwise
// chainID = (v - 35) / 2 and recID = (v - 35) % 2.
//
// The signing hash is recomputed as:
//   - EIP-155:      keccak256(rlp([nonce, gasPrice, gasLimit, to, value, data, chainID, 0, 0]))
//   - pre-EIP-155:  keccak256(rlp([nonce, gasPrice, gasLimit, to, value, data]))
func decodeLegacy(raw []byte) (*DecodedTx, error) {
	decoded, err := rlp.Decode(raw)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrDecodeFailed, err)
	}
	items, err := asList(decoded)
	if err != nil {
		return nil, err
	}
	if len(items) != 9 {
		return nil, fmt.Errorf("%w: legacy tx has %d fields, want 9", ErrInvalidField, len(items))
	}

	// [nonce, gasPrice, gasLimit, to, value, data, v, r, s]
	nonce, err := asUint64(items[0])
	if err != nil {
		return nil, fieldErr(0, "nonce", err)
	}
	gasPrice, err := asBigInt(items[1])
	if err != nil {
		return nil, fieldErr(1, "gasPrice", err)
	}
	gasLimit, err := asUint64(items[2])
	if err != nil {
		return nil, fieldErr(2, "gasLimit", err)
	}
	to, err := asAddress(items[3])
	if err != nil {
		return nil, fieldErr(3, "to", err)
	}
	value, err := asBigInt(items[4])
	if err != nil {
		return nil, fieldErr(4, "value", err)
	}
	data, err := asBytes(items[5])
	if err != nil {
		return nil, fieldErr(5, "data", err)
	}
	vBytes, err := asBytes(items[6])
	if err != nil {
		return nil, fieldErr(6, "v", err)
	}
	rBytes, err := asBytes(items[7])
	if err != nil {
		return nil, fieldErr(7, "r", err)
	}
	sBytes, err := asBytes(items[8])
	if err != nil {
		return nil, fieldErr(8, "s", err)
	}

	v := new(big.Int).SetBytes(vBytes)

	tx := &DecodedTx{
		Type:     0,
		Nonce:    nonce,
		GasPrice: gasPrice,
		GasLimit: gasLimit,
		To:       to,
		Value:    value,
		Data:     copyBytes(data),
		V:        copyBytes(vBytes),
		R:        copyBytes(rBytes),
		S:        copyBytes(sBytes),
	}

	// Derive chain ID and recovery id from v per [EIP-155].
	var recID byte
	var digest []byte
	if v.Cmp(big.NewInt(27)) == 0 || v.Cmp(big.NewInt(28)) == 0 {
		// Pre-EIP-155: no chain ID.
		recID = byte(v.Int64() - 27)
		preimage := rlp.EncodeList(
			rlp.EncodeUint64(nonce),
			encodeBig(gasPrice),
			rlp.EncodeUint64(gasLimit),
			encodeAddr(to),
			encodeBig(value),
			encodeBytes(data),
		)
		digest = keccak256(preimage)
	} else {
		// EIP-155: chainID = (v - 35) / 2, recID = (v - 35) % 2.
		chainID := new(big.Int).Sub(v, big.NewInt(35))
		recID = byte(new(big.Int).Mod(chainID, big.NewInt(2)).Int64())
		chainID.Div(chainID, big.NewInt(2))
		tx.ChainID = chainID
		preimage := rlp.EncodeList(
			rlp.EncodeUint64(nonce),
			encodeBig(gasPrice),
			rlp.EncodeUint64(gasLimit),
			encodeAddr(to),
			encodeBig(value),
			encodeBytes(data),
			encodeBig(chainID),
			rlp.EncodeUint64(0),
			rlp.EncodeUint64(0),
		)
		digest = keccak256(preimage)
	}

	sender, err := ecrecoverSender(rBytes, sBytes, recID, digest)
	if err != nil {
		return nil, err
	}
	tx.Sender = sender
	return tx, nil
}

// decodeEIP2930 decodes a type-1 [EIP-2930] transaction (0x01 prefix
// stripped): rlp([chainId, nonce, gasPrice, gasLimit, to, value, data,
// accessList, v, r, s]).
//
// The signing hash is recomputed as
// keccak256(0x01 || rlp([chainId, nonce, gasPrice, gasLimit, to,
// value, data, accessList])). The v field is the y-parity (0 or 1).
func decodeEIP2930(body []byte) (*DecodedTx, error) {
	decoded, err := rlp.Decode(body)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrDecodeFailed, err)
	}
	items, err := asList(decoded)
	if err != nil {
		return nil, err
	}
	if len(items) != 11 {
		return nil, fmt.Errorf("%w: eip-2930 tx has %d fields, want 11", ErrInvalidField, len(items))
	}

	// [chainId, nonce, gasPrice, gasLimit, to, value, data, accessList, v, r, s]
	chainID, err := asBigInt(items[0])
	if err != nil {
		return nil, fieldErr(0, "chainId", err)
	}
	nonce, err := asUint64(items[1])
	if err != nil {
		return nil, fieldErr(1, "nonce", err)
	}
	gasPrice, err := asBigInt(items[2])
	if err != nil {
		return nil, fieldErr(2, "gasPrice", err)
	}
	gasLimit, err := asUint64(items[3])
	if err != nil {
		return nil, fieldErr(3, "gasLimit", err)
	}
	to, err := asAddress(items[4])
	if err != nil {
		return nil, fieldErr(4, "to", err)
	}
	value, err := asBigInt(items[5])
	if err != nil {
		return nil, fieldErr(5, "value", err)
	}
	data, err := asBytes(items[6])
	if err != nil {
		return nil, fieldErr(6, "data", err)
	}
	accessList, err := parseAccessList(items[7])
	if err != nil {
		return nil, fieldErr(7, "accessList", err)
	}
	vBytes, err := asBytes(items[8])
	if err != nil {
		return nil, fieldErr(8, "v", err)
	}
	rBytes, err := asBytes(items[9])
	if err != nil {
		return nil, fieldErr(9, "r", err)
	}
	sBytes, err := asBytes(items[10])
	if err != nil {
		return nil, fieldErr(10, "s", err)
	}

	tx := &DecodedTx{
		Type:       1,
		ChainID:    chainID,
		Nonce:      nonce,
		GasPrice:   gasPrice,
		GasLimit:   gasLimit,
		To:         to,
		Value:      value,
		Data:       copyBytes(data),
		AccessList: accessList,
		V:          copyBytes(vBytes),
		R:          copyBytes(rBytes),
		S:          copyBytes(sBytes),
	}

	// Recompute the signing hash: 0x01 || rlp([chainId, nonce,
	// gasPrice, gasLimit, to, value, data, accessList]).
	preimage := append([]byte{0x01},
		rlp.EncodeList(
			encodeBig(chainID),
			rlp.EncodeUint64(nonce),
			encodeBig(gasPrice),
			rlp.EncodeUint64(gasLimit),
			encodeAddr(to),
			encodeBig(value),
			encodeBytes(data),
			encodeAccessList(accessList),
		)...,
	)
	digest := keccak256(preimage)

	recID, err := yParity(vBytes)
	if err != nil {
		return nil, err
	}
	sender, err := ecrecoverSender(rBytes, sBytes, recID, digest)
	if err != nil {
		return nil, err
	}
	tx.Sender = sender
	return tx, nil
}

// decodeEIP1559 decodes a type-2 [EIP-1559] transaction (0x02 prefix
// stripped): rlp([chainId, nonce, maxPriorityFeePerGas, maxFeePerGas,
// gasLimit, to, value, data, accessList, v, r, s]).
//
// The signing hash is recomputed as
// keccak256(0x02 || rlp([chainId, nonce, maxPriorityFeePerGas,
// maxFeePerGas, gasLimit, to, value, data, accessList])). The v field
// is the y-parity (0 or 1).
func decodeEIP1559(body []byte) (*DecodedTx, error) {
	decoded, err := rlp.Decode(body)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrDecodeFailed, err)
	}
	items, err := asList(decoded)
	if err != nil {
		return nil, err
	}
	if len(items) != 12 {
		return nil, fmt.Errorf("%w: eip-1559 tx has %d fields, want 12", ErrInvalidField, len(items))
	}

	// [chainId, nonce, maxPriorityFeePerGas, maxFeePerGas, gasLimit,
	// to, value, data, accessList, v, r, s]
	chainID, err := asBigInt(items[0])
	if err != nil {
		return nil, fieldErr(0, "chainId", err)
	}
	nonce, err := asUint64(items[1])
	if err != nil {
		return nil, fieldErr(1, "nonce", err)
	}
	maxPriorityFee, err := asBigInt(items[2])
	if err != nil {
		return nil, fieldErr(2, "maxPriorityFeePerGas", err)
	}
	maxFee, err := asBigInt(items[3])
	if err != nil {
		return nil, fieldErr(3, "maxFeePerGas", err)
	}
	gasLimit, err := asUint64(items[4])
	if err != nil {
		return nil, fieldErr(4, "gasLimit", err)
	}
	to, err := asAddress(items[5])
	if err != nil {
		return nil, fieldErr(5, "to", err)
	}
	value, err := asBigInt(items[6])
	if err != nil {
		return nil, fieldErr(6, "value", err)
	}
	data, err := asBytes(items[7])
	if err != nil {
		return nil, fieldErr(7, "data", err)
	}
	accessList, err := parseAccessList(items[8])
	if err != nil {
		return nil, fieldErr(8, "accessList", err)
	}
	vBytes, err := asBytes(items[9])
	if err != nil {
		return nil, fieldErr(9, "v", err)
	}
	rBytes, err := asBytes(items[10])
	if err != nil {
		return nil, fieldErr(10, "r", err)
	}
	sBytes, err := asBytes(items[11])
	if err != nil {
		return nil, fieldErr(11, "s", err)
	}

	tx := &DecodedTx{
		Type:                 2,
		ChainID:              chainID,
		Nonce:                nonce,
		MaxPriorityFeePerGas: maxPriorityFee,
		MaxFeePerGas:         maxFee,
		GasLimit:             gasLimit,
		To:                   to,
		Value:                value,
		Data:                 copyBytes(data),
		AccessList:           accessList,
		V:                    copyBytes(vBytes),
		R:                    copyBytes(rBytes),
		S:                    copyBytes(sBytes),
	}

	// Recompute the signing hash: 0x02 || rlp([chainId, nonce,
	// maxPriorityFeePerGas, maxFeePerGas, gasLimit, to, value, data,
	// accessList]).
	preimage := append([]byte{0x02},
		rlp.EncodeList(
			encodeBig(chainID),
			rlp.EncodeUint64(nonce),
			encodeBig(maxPriorityFee),
			encodeBig(maxFee),
			rlp.EncodeUint64(gasLimit),
			encodeAddr(to),
			encodeBig(value),
			encodeBytes(data),
			encodeAccessList(accessList),
		)...,
	)
	digest := keccak256(preimage)

	recID, err := yParity(vBytes)
	if err != nil {
		return nil, err
	}
	sender, err := ecrecoverSender(rBytes, sBytes, recID, digest)
	if err != nil {
		return nil, err
	}
	tx.Sender = sender
	return tx, nil
}

// yParity extracts the recovery id (0 or 1) from the decoded v field of
// a type-1 or type-2 transaction. The v field encodes the y-parity
// directly; an empty byte string (RLP 0x80) is treated as 0.
func yParity(v []byte) (byte, error) {
	if len(v) == 0 {
		return 0, nil
	}
	if len(v) != 1 {
		return 0, fmt.Errorf("%w: y-parity v field length %d, want 1", ErrInvalidField, len(v))
	}
	if v[0] > 1 {
		return 0, fmt.Errorf("%w: y-parity %d, want 0 or 1", ErrInvalidField, v[0])
	}
	return v[0], nil
}

// ecrecoverSender recovers the [EIP-55] sender address from the r, s
// signature components, the recovery id, and the 32-byte signing
// digest via [SEC 1 v2] §4.3.3 secp256k1 public-key recovery.
func ecrecoverSender(r, s []byte, recID byte, digest []byte) (ethereum.Address, error) {
	sig := make([]byte, 64)
	copy(sig[32-len(r):32], r)
	copy(sig[64-len(s):64], s)
	pub, err := secp256k1.RecoverPubKey(sig, digest, recID)
	if err != nil {
		return ethereum.Address{}, fmt.Errorf("%w: %v", ErrRecoverFailed, err)
	}
	addr, err := ethereum.FromPublicKey(pub)
	if err != nil {
		return ethereum.Address{}, fmt.Errorf("%w: %v", ErrRecoverFailed, err)
	}
	return addr, nil
}

// parseAccessList parses the [EIP-2930] access list from a decoded RLP
// list into a []AccessListEntry. Each entry is [address,
// [storageKey1, ...]] where address is 20 bytes and each storage key
// is 32 bytes.
func parseAccessList(v interface{}) ([]AccessListEntry, error) {
	entries, err := asList(v)
	if err != nil {
		return nil, err
	}
	result := make([]AccessListEntry, 0, len(entries))
	for i, e := range entries {
		entry, err := asList(e)
		if err != nil {
			return nil, fmt.Errorf("entry %d: %w", i, err)
		}
		if len(entry) != 2 {
			return nil, fmt.Errorf("%w: entry %d has %d items, want 2", ErrInvalidField, i, len(entry))
		}
		addrBytes, err := asBytes(entry[0])
		if err != nil {
			return nil, fmt.Errorf("entry %d address: %w", i, err)
		}
		if len(addrBytes) != 20 {
			return nil, fmt.Errorf("%w: entry %d address length %d, want 20", ErrInvalidField, i, len(addrBytes))
		}
		var addr [20]byte
		copy(addr[:], addrBytes)

		storageList, err := asList(entry[1])
		if err != nil {
			return nil, fmt.Errorf("entry %d storage keys: %w", i, err)
		}
		keys := make([][32]byte, 0, len(storageList))
		for j, sk := range storageList {
			keyBytes, err := asBytes(sk)
			if err != nil {
				return nil, fmt.Errorf("entry %d key %d: %w", i, j, err)
			}
			if len(keyBytes) != 32 {
				return nil, fmt.Errorf("%w: entry %d key %d length %d, want 32", ErrInvalidField, i, j, len(keyBytes))
			}
			var key [32]byte
			copy(key[:], keyBytes)
			keys = append(keys, key)
		}
		result = append(result, AccessListEntry{Address: addr, StorageKeys: keys})
	}
	return result, nil
}

// asBytes asserts v is an RLP byte string ([]byte).
func asBytes(v interface{}) ([]byte, error) {
	b, ok := v.([]byte)
	if !ok {
		return nil, fmt.Errorf("%w: expected []byte, got %T", ErrInvalidField, v)
	}
	return b, nil
}

// asList asserts v is an RLP list ([]interface{}).
func asList(v interface{}) ([]interface{}, error) {
	l, ok := v.([]interface{})
	if !ok {
		return nil, fmt.Errorf("%w: expected list, got %T", ErrInvalidField, v)
	}
	return l, nil
}

// asUint64 decodes an RLP byte string as a uint64 using Ethereum's
// minimal big-endian integer convention.
func asUint64(v interface{}) (uint64, error) {
	b, err := asBytes(v)
	if err != nil {
		return 0, err
	}
	return new(big.Int).SetBytes(b).Uint64(), nil
}

// asBigInt decodes an RLP byte string as a *big.Int using Ethereum's
// minimal big-endian integer convention. An empty byte string is zero.
func asBigInt(v interface{}) (*big.Int, error) {
	b, err := asBytes(v)
	if err != nil {
		return nil, err
	}
	return new(big.Int).SetBytes(b), nil
}

// asAddress decodes an RLP byte string as an Ethereum address. An
// empty byte string is a nil address (contract creation). A non-empty
// byte string must be exactly 20 bytes.
func asAddress(v interface{}) (*ethereum.Address, error) {
	b, err := asBytes(v)
	if err != nil {
		return nil, err
	}
	if len(b) == 0 {
		return nil, nil
	}
	if len(b) != 20 {
		return nil, fmt.Errorf("%w: address length %d, want 20", ErrInvalidField, len(b))
	}
	var addr ethereum.Address
	copy(addr[:], b)
	return &addr, nil
}

// copyBytes returns a copy of b so the caller's decoded slice does not
// alias the input buffer.
func copyBytes(b []byte) []byte {
	if b == nil {
		return nil
	}
	out := make([]byte, len(b))
	copy(out, b)
	return out
}

// fieldErr wraps a field-decode error with the field index and name.
func fieldErr(idx int, name string, err error) error {
	return fmt.Errorf("%w: field %d (%s): %v", ErrInvalidField, idx, name, err)
}
