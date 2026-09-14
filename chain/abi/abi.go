// Package abi implements Solidity ABI encoding and decoding for the
// core EVM types: uint256, address, bytes32, bool, string, bytes, and
// the dynamic arrays uint256[] and address[].
//
// Static types are encoded inline as 32-byte words; dynamic types place
// a 32-byte offset in the head and the length-prefixed payload in the
// tail, per the [Solidity ABI Specification]. Function selectors are
// the first 4 bytes of the Keccak-256 of the canonical signature.
//
// [Solidity ABI Specification]: https://docs.soliditylang.org/en/latest/abi-spec.html
package abi

import (
	"errors"
	"fmt"

	"github.com/bperin/trust/crypto/hash"
)

// Sentinel errors returned by ParseABIType. Check with errors.Is.
var (
	// ErrUnknownABIType is returned when ParseABIType receives a type
	// string that is not one of the supported canonical types.
	ErrUnknownABIType = errors.New("abi: unknown type")
)

// ABIType identifies a supported Solidity ABI type.
type ABIType int

// Supported ABI types.
const (
	// ABITypeUint256 is the uint256 type — a 256-bit unsigned integer
	// encoded as a 32-byte big-endian word.
	ABITypeUint256 ABIType = iota
	// ABITypeAddress is the address type — a 20-byte value encoded
	// right-aligned in a 32-byte word (12 zero bytes of left padding).
	ABITypeAddress
	// ABITypeBytes32 is the bytes32 type — a fixed 32-byte value encoded
	// as-is in a single word.
	ABITypeBytes32
	// ABITypeBool is the bool type — encoded as 0 or 1 in a 32-byte word.
	ABITypeBool
	// ABITypeString is the dynamic string type — head holds an offset,
	// tail holds a 32-byte length followed by the UTF-8 bytes
	// right-padded to a multiple of 32.
	ABITypeString
	// ABITypeBytes is the dynamic bytes type — head holds an offset,
	// tail holds a 32-byte length followed by the bytes right-padded to
	// a multiple of 32.
	ABITypeBytes
	// ABITypeUint256Array is uint256[] — a dynamic array of uint256.
	// Head holds an offset; tail holds a 32-byte length followed by the
	// length-prefixed elements, each a 32-byte word.
	ABITypeUint256Array
	// ABITypeAddressArray is address[] — a dynamic array of address.
	// Head holds an offset; tail holds a 32-byte length followed by the
	// length-prefixed elements, each right-aligned in a 32-byte word.
	ABITypeAddressArray
)

// wordSize is the ABI word size in bytes. Every static type and every
// head/tail entry is aligned to this size.
const wordSize = 32

// ParseABIType parses a canonical Solidity ABI type string into an
// ABIType. Supported strings are "uint256", "address", "bytes32",
// "bool", "string", "bytes", "uint256[]", and "address[]". Other
// inputs — including nested tuples and fixed-size arrays such as
// "uint256[3]" — return ErrUnknownABIType.
func ParseABIType(s string) (ABIType, error) {
	switch s {
	case "uint256":
		return ABITypeUint256, nil
	case "address":
		return ABITypeAddress, nil
	case "bytes32":
		return ABITypeBytes32, nil
	case "bool":
		return ABITypeBool, nil
	case "string":
		return ABITypeString, nil
	case "bytes":
		return ABITypeBytes, nil
	case "uint256[]":
		return ABITypeUint256Array, nil
	case "address[]":
		return ABITypeAddressArray, nil
	case "":
		return 0, fmt.Errorf("%w: empty type string", ErrUnknownABIType)
	default:
		return 0, fmt.Errorf("%w: %q is not a supported type (no nested tuples or fixed-size arrays)", ErrUnknownABIType, s)
	}
}

// String returns the canonical ABI type string for t. It is the inverse
// of ParseABIType for supported types and is useful for building
// function signatures.
func (t ABIType) String() string {
	switch t {
	case ABITypeUint256:
		return "uint256"
	case ABITypeAddress:
		return "address"
	case ABITypeBytes32:
		return "bytes32"
	case ABITypeBool:
		return "bool"
	case ABITypeString:
		return "string"
	case ABITypeBytes:
		return "bytes"
	case ABITypeUint256Array:
		return "uint256[]"
	case ABITypeAddressArray:
		return "address[]"
	default:
		return fmt.Sprintf("abi: unknown ABIType(%d)", int(t))
	}
}

// isDynamic reports whether t is a dynamic ABI type whose encoding
// places an offset in the head and a payload in the tail. Static types
// (uint256, address, bytes32, bool) are encoded inline.
func (t ABIType) isDynamic() bool {
	switch t {
	case ABITypeString, ABITypeBytes, ABITypeUint256Array, ABITypeAddressArray:
		return true
	default:
		return false
	}
}

// FunctionSelector returns the 4-byte function selector for a canonical
// Solidity function signature: the first 4 bytes of
// Keccak-256(signature), e.g. "transfer(address,uint256)" → 0xa9059cbb.
//
// The signature must be canonical: no whitespace, canonical type names
// (uint256, not uint), and no parameter names. The string is hashed
// verbatim.
func FunctionSelector(signature string) [4]byte {
	// Keccak-256 is deterministic, so a per-call hasher is fine; the
	// underlying trust/crypto/hash Keccak256 is 0-allocation.
	digest := hash.NewKeccak256().Sum([]byte(signature))
	var sel [4]byte
	copy(sel[:], digest[:4])
	return sel
}
