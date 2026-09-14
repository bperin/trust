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
	// ErrNonZeroPadding is returned when a padding region that must be
	// zero contains a non-zero byte.
	ErrNonZeroPadding = errors.New("abi: non-zero padding")
	// ErrBadBool is returned when a bool word is not the canonical
	// encoding of false (all zeros) or true (1 in the last byte).
	ErrBadBool = errors.New("abi: invalid bool encoding")
)

// DecodeArgs decodes an ABI head/tail blob into a slice of typed Go
// values, one per requested type. It is the inverse of EncodeArgs and
// returns the same Go types.
//
// Short, misaligned, or out-of-range input returns an error.
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
			addr, err := decodeAddress(head)
			if err != nil {
				return nil, fmt.Errorf("argument %d: %w", i, err)
			}
			out[i] = addr
		case ABITypeBytes32:
			var b [32]byte
			copy(b[:], head)
			out[i] = b
		case ABITypeBool:
			b, err := decodeBool(head)
			if err != nil {
				return nil, fmt.Errorf("argument %d: %w", i, err)
			}
			out[i] = b
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

// checkZeroPadding returns ErrNonZeroPadding if b contains a non-zero
// byte.
func checkZeroPadding(b []byte, what string) error {
	for i, c := range b {
		if c != 0 {
			return fmt.Errorf("%w: %s byte %d is 0x%02x", ErrNonZeroPadding, what, i, c)
		}
	}
	return nil
}

// decodeAddress reads the last 20 bytes of a 32-byte word. Non-zero
// left padding returns ErrNonZeroPadding.
func decodeAddress(word []byte) ([20]byte, error) {
	if err := checkZeroPadding(word[:wordSize-20], "address left padding"); err != nil {
		return [20]byte{}, err
	}
	var addr [20]byte
	copy(addr[:], word[wordSize-20:])
	return addr, nil
}

// decodeBool reads a 32-byte word as a bool. All zeros is false and 1
// in the last byte is true; anything else returns ErrBadBool or
// ErrNonZeroPadding.
func decodeBool(word []byte) (bool, error) {
	if err := checkZeroPadding(word[:wordSize-1], "bool padding"); err != nil {
		return false, err
	}
	switch word[wordSize-1] {
	case 0:
		return false, nil
	case 1:
		return true, nil
	default:
		return false, fmt.Errorf("%w: value byte 0x%02x, want 0x00 or 0x01", ErrBadBool, word[wordSize-1])
	}
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

// readLength reads a 32-byte big-endian length prefix from the start
// of tail and returns the length and the payload slice
// (tail[wordSize:]). A length that overflows int returns ErrBadLength;
// a length exceeding the remaining payload returns ErrShortData.
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

// checkTailPadding verifies that the payload in rest[:length] is
// followed by zero right padding out to paddedLen(length) bytes.
func checkTailPadding(rest []byte, length int) error {
	padded := paddedLen(length)
	if len(rest) < padded {
		return fmt.Errorf("%w: payload of %d bytes missing %d-byte right padding", ErrShortData, length, padded-length)
	}
	return checkZeroPadding(rest[length:padded], "tail padding")
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
	if err := checkTailPadding(rest, length); err != nil {
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
	if err := checkTailPadding(rest, length); err != nil {
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
		addr, err := decodeAddress(rest[i*wordSize : (i+1)*wordSize])
		if err != nil {
			return nil, fmt.Errorf("element %d: %w", i, err)
		}
		arr[i] = addr
	}
	return arr, nil
}
