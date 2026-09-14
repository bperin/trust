package rpc

import (
	"math/big"
	"strings"
)

// Quantity error sentinels, checked with errors.Is. Per [EIP-1474] a
// valid quantity is "0x" followed by one or more hex digits with no
// leading zeros; "0x0" is the sole zero representation.
var (
	// ErrEmptyQuantity is returned when the input is the empty string.
	ErrEmptyQuantity = errStr("rpc: empty quantity")
	// ErrMissingPrefix is returned when the "0x" prefix is absent.
	ErrMissingPrefix = errStr("rpc: missing 0x prefix")
	// ErrNoDigits is returned when the input is "0x" with no digits.
	ErrNoDigits = errStr("rpc: no hex digits after 0x")
	// ErrLeadingZeros is returned when the hex digits have leading
	// zeros (e.g. "0x0123").
	ErrLeadingZeros = errStr("rpc: leading zeros in quantity")
	// ErrInvalidHex is returned when the digits contain a non-hex
	// character.
	ErrInvalidHex = errStr("rpc: invalid hex digit")
	// ErrBlockNumberOverflow is returned by ParseBlockNumber when the
	// value exceeds math.MaxUint64.
	ErrBlockNumberOverflow = errStr("rpc: block number exceeds uint64")
)

// errStr is a sentinel error type supporting errors.Is by value.
type errStr string

// Error returns the error string.
func (e errStr) Error() string { return string(e) }

// ParseQuantity parses a JSON-RPC hex quantity string into a *big.Int
// per [EIP-1474]: "0x" followed by one or more hex digits with no
// leading zeros, where "0x0" is the sole zero representation.
// Malformed input returns a typed sentinel error.
func ParseQuantity(hex string) (*big.Int, error) {
	if hex == "" {
		return nil, ErrEmptyQuantity
	}
	if !strings.HasPrefix(hex, "0x") {
		return nil, ErrMissingPrefix
	}
	body := hex[2:]
	if body == "" {
		return nil, ErrNoDigits
	}
	// "0x0" is the sole zero representation; any other leading zero is
	// rejected.
	if len(body) > 1 && body[0] == '0' {
		return nil, ErrLeadingZeros
	}
	n, ok := new(big.Int).SetString(body, 16)
	if !ok {
		return nil, ErrInvalidHex
	}
	return n, nil
}

// FormatQuantity formats a *big.Int as a JSON-RPC hex quantity string
// per [EIP-1474]: "0x" plus lowercase hex digits with no leading
// zeros. A nil or zero n returns "0x0". n must be non-negative;
// quantities are unsigned.
func FormatQuantity(n *big.Int) string {
	if n == nil || n.Sign() == 0 {
		return "0x0"
	}
	return "0x" + n.Text(16)
}

// ParseBlockNumber parses a JSON-RPC hex quantity string into a
// uint64 block number, following the same rules as ParseQuantity.
// Values exceeding math.MaxUint64 return ErrBlockNumberOverflow.
func ParseBlockNumber(hex string) (uint64, error) {
	n, err := ParseQuantity(hex)
	if err != nil {
		return 0, err
	}
	// big.Int.Uint64 returns the low 64 bits regardless of magnitude,
	// so guard the overflow explicitly before conversion.
	if n.BitLen() > 64 {
		return 0, ErrBlockNumberOverflow
	}
	return n.Uint64(), nil
}
