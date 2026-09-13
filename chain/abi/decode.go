package abi

import (
	"errors"
	"fmt"
	"math/big"
)

// Sentinel errors returned by DecodeArgs. Check with errors.Is.
var (
	// ErrShortData is returned when the input is too short to contain
	// the head section (one word per type) or a referenced tail payload.
	ErrShortData = errors.New("abi: short data")
	// ErrBadOffset is returned when a dynamic-type offset points
	// outside the data or is not word-aligned.
	ErrBadOffset = errors.New("abi: bad offset")
	// ErrBadLength is returned when a dynamic-type length prefix is
	// negative, overflows the remaining data, or is inconsistent with
	// the available payload.
	ErrBadLength = errors.New("abi: bad length")
)

// DecodeArgs reverses EncodeArgs: it decodes an ABI v2 head/tail blob
// into a slice of typed Go values, one per requested type.
//
// The returned Go types match EncodeArgs's value-type mapping:
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
// Dynamic-type offsets are read from the head and resolved relative to
// the start of the data (the start of the head section), per the
// [Solidity ABI Specification v2]. Short, misaligned, or
// out-of-range inputs return a wrapped error; no panics are produced
// on malformed input.
//
// [Solidity ABI Specification v2]: https://docs.soliditylang.org/en/latest/abi-spec.html
func DecodeArgs(types []ABIType, data []byte) ([]interface{}, error) {
	headLen := len(types) * wordSize
	if len(data) < headLen {
		return nil, fmt.Errorf("%w: need %d head bytes, got %d", ErrShortData, headLen, len(data))
	}

	out := make([]interface{}, len(types))
	for i, t := range types {
		head := data[i*wordSize : (i+1)*wordSize]
		switch t {
		case ABITypeUint256:
			out[i] = decodeUint256(head)
		case ABITypeAddress:
			out[i] = decodeAddress(head)
		case ABITypeBytes32:
			var b [32]byte
			copy(b[:], head)
			out[i] = b
		case ABITypeBool:
			out[i] = decodeBool(head)
		case ABITypeString:
			s, err := decodeString(data, head)
			if err != nil {
				return nil, fmt.Errorf("argument %d: %w", i, err)
			}
			out[i] = s
		case ABITypeBytes:
			b, err := decodeBytes(data, head)
			if err != nil {
				return nil, fmt.Errorf("argument %d: %w", i, err)
			}
			out[i] = b
		case ABITypeUint256Array:
			arr, err := decodeUint256Array(data, head)
			if err != nil {
				return nil, fmt.Errorf("argument %d: %w", i, err)
			}
			out[i] = arr
		case ABITypeAddressArray:
			arr, err := decodeAddressArray(data, head)
			if err != nil {
				return nil, fmt.Errorf("argument %d: %w", i, err)
			}
			out[i] = arr
		default:
			return nil, fmt.Errorf("%w: argument %d: unsupported ABIType %d", ErrUnknownABIType, i, int(t))
		}
	}
	return out, nil
}

// decodeUint256 reads a 32-byte big-endian word into a *big.Int. The
// word is treated as an unsigned 256-bit value.
func decodeUint256(word []byte) *big.Int {
	return new(big.Int).SetBytes(word)
}

// decodeAddress reads the last 20 bytes of a 32-byte word into a
// [20]byte.
func decodeAddress(word []byte) [20]byte {
	var addr [20]byte
	copy(addr[:], word[wordSize-20:])
	return addr
}

// decodeBool reads a 32-byte word as a bool: any non-zero last byte is
// true. Per the ABI spec the value is 0 or 1, but we treat any non-zero
// trailing byte as true to tolerate non-canonical encodings without
// panicking.
func decodeBool(word []byte) bool {
	return word[wordSize-1] != 0
}

// resolveOffset reads a 32-byte offset word, validates it against the
// data bounds and word alignment, and returns the tail slice starting
// at that offset. Offsets are relative to the start of data.
func resolveOffset(data, head []byte) ([]byte, error) {
	offBig := new(big.Int).SetBytes(head)
	if !offBig.IsInt64() {
		return nil, fmt.Errorf("%w: offset not representable as int64", ErrBadOffset)
	}
	off := offBig.Int64()
	if off < 0 {
		return nil, fmt.Errorf("%w: negative offset %d", ErrBadOffset, off)
	}
	if off%wordSize != 0 {
		return nil, fmt.Errorf("%w: offset %d not word-aligned", ErrBadOffset, off)
	}
	if int(off) > len(data) {
		return nil, fmt.Errorf("%w: offset %d exceeds data length %d", ErrBadOffset, off, len(data))
	}
	return data[off:], nil
}

// readLength reads a 32-byte big-endian length prefix from the start of
// tail and validates it against the remaining bytes. Returns the
// length and the payload slice (tail[wordSize:]). A length that
// overflows the platform int returns ErrBadLength; a length that
// exceeds the remaining payload bytes returns ErrShortData (the
// length itself is valid, the data is just truncated).
func readLength(tail []byte) (int, []byte, error) {
	if len(tail) < wordSize {
		return 0, nil, fmt.Errorf("%w: missing length word", ErrShortData)
	}
	length := new(big.Int).SetBytes(tail[:wordSize])
	if !length.IsInt64() {
		return 0, nil, fmt.Errorf("%w: length %s overflows int", ErrBadLength, length.String())
	}
	n := length.Int64()
	if n < 0 {
		return 0, nil, fmt.Errorf("%w: negative length %d", ErrBadLength, n)
	}
	rest := tail[wordSize:]
	if int(n) > len(rest) {
		return 0, nil, fmt.Errorf("%w: declared length %d exceeds remaining %d bytes", ErrShortData, n, len(rest))
	}
	return int(n), rest, nil
}

// decodeString resolves the offset, reads the length-prefixed UTF-8
// payload, and returns it as a string.
func decodeString(data, head []byte) (string, error) {
	tail, err := resolveOffset(data, head)
	if err != nil {
		return "", err
	}
	length, rest, err := readLength(tail)
	if err != nil {
		return "", err
	}
	return string(rest[:length]), nil
}

// decodeBytes resolves the offset, reads the length-prefixed payload,
// and returns a copy (so the caller may mutate it without aliasing the
// input).
func decodeBytes(data, head []byte) ([]byte, error) {
	tail, err := resolveOffset(data, head)
	if err != nil {
		return nil, err
	}
	length, rest, err := readLength(tail)
	if err != nil {
		return nil, err
	}
	out := make([]byte, length)
	copy(out, rest[:length])
	return out, nil
}

// decodeUint256Array resolves the offset, reads the length prefix, and
// decodes that many 32-byte words into []*big.Int.
func decodeUint256Array(data, head []byte) ([]*big.Int, error) {
	tail, err := resolveOffset(data, head)
	if err != nil {
		return nil, err
	}
	length, rest, err := readLength(tail)
	if err != nil {
		return nil, err
	}
	need := length * wordSize
	if len(rest) < need {
		return nil, fmt.Errorf("%w: array needs %d bytes, have %d", ErrShortData, need, len(rest))
	}
	arr := make([]*big.Int, length)
	for i := 0; i < length; i++ {
		arr[i] = decodeUint256(rest[i*wordSize : (i+1)*wordSize])
	}
	return arr, nil
}

// decodeAddressArray resolves the offset, reads the length prefix, and
// decodes that many 32-byte words into [][20]byte.
func decodeAddressArray(data, head []byte) ([][20]byte, error) {
	tail, err := resolveOffset(data, head)
	if err != nil {
		return nil, err
	}
	length, rest, err := readLength(tail)
	if err != nil {
		return nil, err
	}
	need := length * wordSize
	if len(rest) < need {
		return nil, fmt.Errorf("%w: array needs %d bytes, have %d", ErrShortData, need, len(rest))
	}
	arr := make([][20]byte, length)
	for i := 0; i < length; i++ {
		arr[i] = decodeAddress(rest[i*wordSize : (i+1)*wordSize])
	}
	return arr, nil
}
