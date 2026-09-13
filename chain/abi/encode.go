package abi

import (
	"errors"
	"fmt"
	"math/big"
)

// Sentinel errors returned by EncodeArgs. Check with errors.Is.
var (
	// ErrArgCountMismatch is returned when the number of types and
	// values do not match.
	ErrArgCountMismatch = errors.New("abi: argument count mismatch")
	// ErrWrongValueType is returned when a value's Go type does not
	// match the ABIType it is being encoded against.
	ErrWrongValueType = errors.New("abi: wrong value type")
	// ErrUint256Overflow is returned when a uint256 value is negative
	// or exceeds 2^256-1.
	ErrUint256Overflow = errors.New("abi: uint256 overflow")
)

// maxUint256 is 2^256-1.
var maxUint256 = new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 256), big.NewInt(1))

// EncodeArgs ABI-encodes a list of typed values following the
// [Solidity ABI Specification v2] head/tail layout.
//
// Static types (uint256, address, bytes32, bool) are encoded inline as
// a single 32-byte word in the head. Dynamic types (string, bytes,
// uint256[], address[]) place a 32-byte big-endian offset in the head
// and the length-prefixed payload in the tail. Offsets are relative to
// the start of the head section (the start of the encoded tuple).
//
// Value-type mapping (enforced by explicit type switch, no reflection):
//
//   - ABITypeUint256       → *big.Int
//   - ABITypeAddress       → [20]byte
//   - ABITypeBytes32       → [32]byte
//   - ABITypeBool          → bool
//   - ABITypeString        → string
//   - ABITypeBytes         → []byte
//   - ABITypeUint256Array  → []*big.Int
//   - ABITypeAddressArray  → [][20]byte
//
// A nil *big.Int is treated as zero. A negative or >2^256-1 big.Int
// returns ErrUint256Overflow. Mismatched type/value counts return
// ErrArgCountMismatch. A value whose Go type does not match its
// ABIType returns ErrWrongValueType wrapped with the type name.
//
// [Solidity ABI Specification v2]: https://docs.soliditylang.org/en/latest/abi-spec.html
func EncodeArgs(types []ABIType, values []interface{}) ([]byte, error) {
	if len(types) != len(values) {
		return nil, fmt.Errorf("%w: %d types, %d values", ErrArgCountMismatch, len(types), len(values))
	}

	// First pass: encode each value into its head word (static) or tail
	// blob (dynamic). This avoids a second pass over the values and
	// keeps the offset computation a simple running sum.
	heads := make([][wordSize]byte, len(types))
	tails := make([][]byte, len(types))

	for i, t := range types {
		switch t {
		case ABITypeUint256:
			v, ok := values[i].(*big.Int)
			if !ok {
				return nil, fmt.Errorf("%w: argument %d: uint256 expects *big.Int, got %T", ErrWrongValueType, i, values[i])
			}
			word, err := encodeUint256(v)
			if err != nil {
				return nil, fmt.Errorf("argument %d: %w", i, err)
			}
			heads[i] = word
		case ABITypeAddress:
			v, ok := values[i].([20]byte)
			if !ok {
				return nil, fmt.Errorf("%w: argument %d: address expects [20]byte, got %T", ErrWrongValueType, i, values[i])
			}
			heads[i] = encodeAddress(v)
		case ABITypeBytes32:
			v, ok := values[i].([32]byte)
			if !ok {
				return nil, fmt.Errorf("%w: argument %d: bytes32 expects [32]byte, got %T", ErrWrongValueType, i, values[i])
			}
			heads[i] = v
		case ABITypeBool:
			v, ok := values[i].(bool)
			if !ok {
				return nil, fmt.Errorf("%w: argument %d: bool expects bool, got %T", ErrWrongValueType, i, values[i])
			}
			heads[i] = encodeBool(v)
		case ABITypeString:
			v, ok := values[i].(string)
			if !ok {
				return nil, fmt.Errorf("%w: argument %d: string expects string, got %T", ErrWrongValueType, i, values[i])
			}
			tails[i] = encodeBytesPayload([]byte(v))
		case ABITypeBytes:
			v, ok := values[i].([]byte)
			if !ok {
				return nil, fmt.Errorf("%w: argument %d: bytes expects []byte, got %T", ErrWrongValueType, i, values[i])
			}
			tails[i] = encodeBytesPayload(v)
		case ABITypeUint256Array:
			v, ok := values[i].([]*big.Int)
			if !ok {
				return nil, fmt.Errorf("%w: argument %d: uint256[] expects []*big.Int, got %T", ErrWrongValueType, i, values[i])
			}
			tail, err := encodeUint256Array(v)
			if err != nil {
				return nil, fmt.Errorf("argument %d: %w", i, err)
			}
			tails[i] = tail
		case ABITypeAddressArray:
			v, ok := values[i].([][20]byte)
			if !ok {
				return nil, fmt.Errorf("%w: argument %d: address[] expects [][20]byte, got %T", ErrWrongValueType, i, values[i])
			}
			tails[i] = encodeAddressArray(v)
		default:
			return nil, fmt.Errorf("%w: argument %d: unsupported ABIType %d", ErrUnknownABIType, i, int(t))
		}
	}

	// Second pass: assemble head + tail. For dynamic types, write the
	// running tail offset (relative to the start of the head) into the
	// head word. The head is exactly len(types) words.
	headLen := len(types) * wordSize
	out := make([]byte, 0, headLen+totalLen(tails))
	tailOffset := headLen
	for i, t := range types {
		if t.isDynamic() {
			heads[i] = encodeUint256FromUint64(uint64(tailOffset))
			tailOffset += len(tails[i])
		}
		out = append(out, heads[i][:]...)
	}
	for i := range types {
		out = append(out, tails[i]...)
	}
	return out, nil
}

// totalLen returns the sum of the lengths of the tail blobs.
func totalLen(tails [][]byte) int {
	n := 0
	for _, t := range tails {
		n += len(t)
	}
	return n
}

// encodeUint256 encodes v as a 32-byte big-endian word. A nil *big.Int
// is treated as zero. Negative values and values exceeding 2^256-1
// return ErrUint256Overflow.
func encodeUint256(v *big.Int) ([32]byte, error) {
	var word [32]byte
	if v == nil {
		return word, nil
	}
	if v.Sign() < 0 || v.Cmp(maxUint256) > 0 {
		return word, ErrUint256Overflow
	}
	// big.Int.Bytes is big-endian, minimal length. Left-pad to 32 bytes.
	b := v.Bytes()
	if len(b) > wordSize {
		return word, ErrUint256Overflow
	}
	copy(word[wordSize-len(b):], b)
	return word, nil
}

// encodeUint256FromUint64 encodes an offset/length as a 32-byte
// big-endian word. Used for head offsets and dynamic-type lengths,
// which are always small enough to fit in a uint64.
func encodeUint256FromUint64(v uint64) [32]byte {
	var word [32]byte
	for i := 0; i < 8; i++ {
		word[wordSize-1-i] = byte(v >> (8 * i))
	}
	return word
}

// encodeAddress encodes a 20-byte address right-aligned in a 32-byte
// word (12 zero bytes of left padding), per the ABI spec.
func encodeAddress(v [20]byte) [32]byte {
	var word [32]byte
	copy(word[wordSize-20:], v[:])
	return word
}

// encodeBool encodes a bool as a 32-byte word: all zeros for false,
// 1 in the last byte for true.
func encodeBool(v bool) [32]byte {
	var word [32]byte
	if v {
		word[wordSize-1] = 1
	}
	return word
}

// encodeBytesPayload encodes a dynamic bytes/string payload: a 32-byte
// big-endian length prefix followed by the data right-padded to a
// multiple of 32 bytes. This is the tail encoding for both string and
// bytes.
func encodeBytesPayload(data []byte) []byte {
	lengthWord := encodeUint256FromUint64(uint64(len(data)))
	padded := make([]byte, paddedLen(len(data)))
	copy(padded, data)
	return append(lengthWord[:], padded...)
}

// encodeUint256Array encodes a uint256[] payload: a 32-byte length
// prefix followed by each element as a 32-byte big-endian word.
func encodeUint256Array(arr []*big.Int) ([]byte, error) {
	out := make([]byte, 0, wordSize+len(arr)*wordSize)
	lengthWord := encodeUint256FromUint64(uint64(len(arr)))
	out = append(out, lengthWord[:]...)
	for i, v := range arr {
		word, err := encodeUint256(v)
		if err != nil {
			return nil, fmt.Errorf("element %d: %w", i, err)
		}
		out = append(out, word[:]...)
	}
	return out, nil
}

// encodeAddressArray encodes an address[] payload: a 32-byte length
// prefix followed by each address right-aligned in a 32-byte word.
func encodeAddressArray(arr [][20]byte) []byte {
	out := make([]byte, 0, wordSize+len(arr)*wordSize)
	lengthWord := encodeUint256FromUint64(uint64(len(arr)))
	out = append(out, lengthWord[:]...)
	for _, v := range arr {
		word := encodeAddress(v)
		out = append(out, word[:]...)
	}
	return out
}

// paddedLen returns n rounded up to the next multiple of wordSize. A
// zero-length input rounds to 0 (no padding word is appended for an
// empty bytes/string), matching the ABI spec: the tail of an empty
// dynamic type is just the 32-byte length word.
func paddedLen(n int) int {
	if n == 0 {
		return 0
	}
	r := n % wordSize
	if r == 0 {
		return n
	}
	return n + wordSize - r
}
