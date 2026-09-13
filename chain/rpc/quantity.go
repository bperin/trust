package rpc

import (
	"math/big"
	"strings"
)

// Quantity error sentinels. Each rejection case has a typed error so
// callers can distinguish malformed input from out-of-range values via
// errors.Is. Per [EIP-1474], a valid quantity is "0x" followed by one
// or more hex digits with no leading zeros, except "0x0" which is the
// sole zero representation.
//
// [EIP-1474]: https://eips.ethereum.org/EIPS/eip-1474
var (
	// ErrEmptyQuantity is returned when the input is the empty string.
	ErrEmptyQuantity = errStr("rpc: empty quantity")
	// ErrMissingPrefix is returned when the "0x" prefix is absent
	// (e.g. "1c8").
	ErrMissingPrefix = errStr("rpc: missing 0x prefix")
	// ErrNoDigits is returned when the input is "0x" with no hex
	// digits following the prefix.
	ErrNoDigits = errStr("rpc: no hex digits after 0x")
	// ErrLeadingZeros is returned when the hex digits have leading
	// zeros (e.g. "0x0123"). Per [EIP-1474], leading zeros are rejected;
	// "0x0" is the sole zero representation.
	//
	// [EIP-1474]: https://eips.ethereum.org/EIPS/eip-1474
	ErrLeadingZeros = errStr("rpc: leading zeros in quantity")
	// ErrInvalidHex is returned when the hex digits contain a
	// character outside [0-9a-fA-F].
	ErrInvalidHex = errStr("rpc: invalid hex digit")
	// ErrBlockNumberOverflow is returned by ParseBlockNumber when the
	// value exceeds math.MaxUint64.
	ErrBlockNumberOverflow = errStr("rpc: block number exceeds uint64")
)

// errStr is a typed sentinel error. It implements the error interface
// and supports errors.Is by value, matching the project's sentinel
// error convention. Each quantity rejection case has its own value so
// callers can branch on the specific failure mode.
type errStr string

// Error implements the error interface.
func (e errStr) Error() string { return string(e) }

// ParseQuantity parses a JSON-RPC hex quantity string into a *big.Int
// per [EIP-1474].
//
// A valid quantity is "0x" followed by one or more hexadecimal digits
// with no leading zeros. "0x0" is the sole zero representation. The
// input is rejected when it:
//   - is the empty string (""),
//   - lacks the "0x" prefix (e.g. "1c8"),
//   - has no digits after the prefix ("0x"),
//   - has leading zeros (e.g. "0x0123"), or
//   - contains a non-hex character.
//
// The returned *big.Int is always non-nil on success.
//
// [EIP-1474]: https://eips.ethereum.org/EIPS/eip-1474
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
// per [EIP-1474].
//
// The result is "0x" followed by the lowercase hexadecimal digits with
// no leading zeros. The sole zero representation is "0x0".
// FormatQuantity(big.NewInt(456)) returns "0x1c8".
//
// The caller must ensure n is non-negative; EIP-1474 quantities are
// unsigned. A nil or zero n returns "0x0". A negative n returns the
// hex form of its magnitude with a leading "-" (e.g. -1 → "0x-1"),
// which is not a valid quantity — callers should validate before
// formatting.
//
// [EIP-1474]: https://eips.ethereum.org/EIPS/eip-1474
func FormatQuantity(n *big.Int) string {
	if n == nil || n.Sign() == 0 {
		return "0x0"
	}
	return "0x" + n.Text(16)
}

// ParseBlockNumber parses a JSON-RPC hex quantity string into a uint64
// block number per [EIP-1474].
//
// The parsing rules match ParseQuantity: a "0x" prefix is required,
// leading zeros are rejected, and "0x0" is the sole zero
// representation. Values exceeding math.MaxUint64 are rejected with
// ErrBlockNumberOverflow.
//
// [EIP-1474]: https://eips.ethereum.org/EIPS/eip-1474
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
