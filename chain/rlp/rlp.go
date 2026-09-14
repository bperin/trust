// Package rlp implements Recursive Length Prefix (RLP) serialization
// per the Ethereum Yellow Paper, Appendix B.
//
// RLP is the canonical serialization format for Ethereum: it encodes byte
// strings and nested lists of byte strings into a self-describing byte
// stream. This package owns serialization only — it has no knowledge of
// transaction types, chain IDs, or signing.
package rlp

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// Sentinel errors returned by Decode. Wrap with fmt.Errorf and %w at
// boundaries; check with errors.Is.
var (
	// ErrTruncated indicates the input ended before a complete RLP item
	// could be parsed.
	ErrTruncated = errors.New("rlp: input truncated")
	// ErrInvalidEncoding indicates a structurally or canonically invalid
	// RLP encoding (bad prefix, non-minimal length, non-canonical form).
	ErrInvalidEncoding = errors.New("rlp: invalid encoding")
	// ErrTrailingBytes indicates bytes remained after a single top-level
	// item was decoded.
	ErrTrailingBytes = errors.New("rlp: trailing bytes after value")
	// ErrInputTooLarge indicates the input exceeded [MaxInputLen] bytes.
	ErrInputTooLarge = errors.New("rlp: input too large")
	// ErrNestingLimit indicates the input exceeded [MaxNestingDepth]
	// levels of list nesting.
	ErrNestingLimit = errors.New("rlp: nesting depth limit exceeded")
)

// Bounds on input accepted by Decode.
const (
	// MaxInputLen is the maximum byte length accepted by Decode.
	MaxInputLen = 10 << 20 // 10 MiB
	// MaxNestingDepth is the maximum list nesting depth accepted by
	// Decode.
	MaxNestingDepth = 64
)

// EncodeBytes encodes b as an RLP byte string per Yellow Paper Appendix B:
//
//   - Empty byte string → 0x80.
//   - Single byte < 0x80 → the byte itself.
//   - 1–55 bytes → [0x80+len] || bytes.
//   - >55 bytes → [0xb7+len-of-len] || [len as big-endian] || bytes.
//
// A nil slice is treated as an empty byte string and encodes to 0x80.
func EncodeBytes(b []byte) []byte {
	switch {
	case len(b) == 0:
		return []byte{0x80}
	case len(b) == 1 && b[0] < 0x80:
		return []byte{b[0]}
	case len(b) <= 55:
		out := make([]byte, 1+len(b))
		out[0] = byte(0x80 + len(b))
		copy(out[1:], b)
		return out
	default:
		lenBytes := uintToBytes(uint64(len(b)))
		out := make([]byte, 1+len(lenBytes)+len(b))
		out[0] = byte(0xb7 + len(lenBytes))
		copy(out[1:], lenBytes)
		copy(out[1+len(lenBytes):], b)
		return out
	}
}

// EncodeList encodes an RLP list from already-RLP-encoded item bytes.
// The caller composes nested structures by passing the output of
// EncodeBytes, EncodeUint64, or EncodeList as items:
//
//	EncodeList(EncodeBytes([]byte("cat")), EncodeList(EncodeBytes([]byte("dog"))))
//
// Per Yellow Paper Appendix B:
//
//   - Total payload ≤55 bytes → [0xc0+len] || items.
//   - Total payload >55 bytes → [0xf7+len-of-len] || [len] || items.
//
// An empty list (no items) encodes to 0xc0.
func EncodeList(items ...[]byte) []byte {
	total := 0
	for _, item := range items {
		total += len(item)
	}
	switch {
	case total <= 55:
		out := make([]byte, 1+total)
		out[0] = byte(0xc0 + total)
		off := 1
		for _, item := range items {
			copy(out[off:], item)
			off += len(item)
		}
		return out
	default:
		lenBytes := uintToBytes(uint64(total))
		out := make([]byte, 1+len(lenBytes)+total)
		out[0] = byte(0xf7 + len(lenBytes))
		copy(out[1:], lenBytes)
		off := 1 + len(lenBytes)
		for _, item := range items {
			copy(out[off:], item)
			off += len(item)
		}
		return out
	}
}

// EncodeUint64 encodes n as an RLP byte string using Ethereum's integer
// convention: minimal big-endian with leading zero bytes stripped. Zero
// encodes as an empty byte string (0x80); 1024 encodes as 0x820400.
func EncodeUint64(n uint64) []byte {
	if n == 0 {
		return EncodeBytes(nil)
	}
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], n)
	i := 0
	for i < 7 && buf[i] == 0 {
		i++
	}
	return EncodeBytes(buf[i:])
}

// Decode decodes a single RLP item from b. It returns []byte for byte
// strings and []interface{} for lists whose elements are themselves
// []byte or []interface{}.
//
// Decode enforces canonical form and returns an error for truncated
// input, non-canonical encodings, or trailing bytes after the top-level
// item.
func Decode(b []byte) (interface{}, error) {
	if len(b) == 0 {
		return nil, ErrTruncated
	}
	if len(b) > MaxInputLen {
		return nil, fmt.Errorf("%w: %d bytes exceeds limit %d", ErrInputTooLarge, len(b), MaxInputLen)
	}
	val, rest, err := decodeItem(b, 0)
	if err != nil {
		return nil, err
	}
	if len(rest) > 0 {
		return nil, ErrTrailingBytes
	}
	return val, nil
}

// uintToBytes returns n as minimal big-endian bytes (no leading zeros).
// Zero returns an empty slice.
func uintToBytes(n uint64) []byte {
	if n == 0 {
		return []byte{}
	}
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], n)
	i := 0
	for i < 7 && buf[i] == 0 {
		i++
	}
	return buf[i:]
}

// decodeLength parses a big-endian length from b and rejects
// non-minimal encodings (leading zeros).
func decodeLength(b []byte) (uint64, error) {
	if len(b) == 0 {
		return 0, ErrTruncated
	}
	if len(b) > 1 && b[0] == 0 {
		return 0, fmt.Errorf("%w: leading zero in length", ErrInvalidEncoding)
	}
	var n uint64
	for _, c := range b {
		n = (n << 8) | uint64(c)
	}
	return n, nil
}

// decodeItem decodes one RLP item from b, returning the decoded value
// and the unconsumed remainder. depth is the number of enclosing lists
// containing this item; a list item at depth >= MaxNestingDepth is
// rejected with ErrNestingLimit.
func decodeItem(b []byte, depth int) (interface{}, []byte, error) {
	if len(b) == 0 {
		return nil, nil, ErrTruncated
	}
	prefix := b[0]

	// Any list item (prefix >= 0xc0) adds one level of nesting; an item
	// nested inside MaxNestingDepth lists is rejected.
	if prefix >= 0xc0 && depth >= MaxNestingDepth {
		return nil, nil, fmt.Errorf("%w: max %d", ErrNestingLimit, MaxNestingDepth)
	}

	// Single byte in [0x00, 0x7f]: the byte itself.
	if prefix <= 0x7f {
		return []byte{prefix}, b[1:], nil
	}

	// Byte string, 0–55 bytes: [0x80+len] || bytes.
	if prefix <= 0xb7 {
		length := int(prefix - 0x80)
		if len(b) < 1+length {
			return nil, nil, ErrTruncated
		}
		str := b[1 : 1+length]
		// Canonical: a 1-byte string with value < 0x80 must be encoded
		// as the single byte itself, not as 0x81 || byte.
		if length == 1 && str[0] < 0x80 {
			return nil, nil, fmt.Errorf("%w: non-canonical single byte", ErrInvalidEncoding)
		}
		return str, b[1+length:], nil
	}

	// Byte string, >55 bytes: [0xb7+len-of-len] || [len] || bytes.
	if prefix <= 0xbf {
		lenOfLen := int(prefix - 0xb7)
		if len(b) < 1+lenOfLen {
			return nil, nil, ErrTruncated
		}
		length, err := decodeLength(b[1 : 1+lenOfLen])
		if err != nil {
			return nil, nil, err
		}
		// Canonical: long form must only be used when length > 55.
		if length <= 55 {
			return nil, nil, fmt.Errorf("%w: non-canonical long-form byte string", ErrInvalidEncoding)
		}
		if uint64(len(b)) < 1+uint64(lenOfLen)+length {
			return nil, nil, ErrTruncated
		}
		end := 1 + lenOfLen + int(length)
		return b[1+lenOfLen : end], b[end:], nil
	}

	// List, 0–55 bytes payload: [0xc0+len] || items.
	if prefix <= 0xf7 {
		length := int(prefix - 0xc0)
		if len(b) < 1+length {
			return nil, nil, ErrTruncated
		}
		payload := b[1 : 1+length]
		list, err := decodeListItems(payload, depth+1)
		if err != nil {
			return nil, nil, err
		}
		return list, b[1+length:], nil
	}

	// List, >55 bytes payload: [0xf7+len-of-len] || [len] || items.
	lenOfLen := int(prefix - 0xf7)
	if len(b) < 1+lenOfLen {
		return nil, nil, ErrTruncated
	}
	length, err := decodeLength(b[1 : 1+lenOfLen])
	if err != nil {
		return nil, nil, err
	}
	// Canonical: long form must only be used when length > 55.
	if length <= 55 {
		return nil, nil, fmt.Errorf("%w: non-canonical long-form list", ErrInvalidEncoding)
	}
	if uint64(len(b)) < 1+uint64(lenOfLen)+length {
		return nil, nil, ErrTruncated
	}
	end := 1 + lenOfLen + int(length)
	payload := b[1+lenOfLen : end]
	list, err := decodeListItems(payload, depth+1)
	if err != nil {
		return nil, nil, err
	}
	return list, b[end:], nil
}

// decodeListItems decodes all items from a list payload at the given
// nesting depth, returning a non-nil slice even when the payload is
// empty.
func decodeListItems(b []byte, depth int) ([]interface{}, error) {
	items := make([]interface{}, 0)
	for len(b) > 0 {
		val, rest, err := decodeItem(b, depth)
		if err != nil {
			return nil, err
		}
		items = append(items, val)
		b = rest
	}
	return items, nil
}
