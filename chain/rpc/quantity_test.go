package rpc

import (
	"errors"
	"math"
	"math/big"
	"testing"
)

// TestParseQuantity verifies ParseQuantity against the [EIP-1474]
// quantity encoding vectors. Per EIP-1474, a valid quantity is "0x"
// followed by one or more hex digits with no leading zeros; "0x0" is
// the sole zero representation.
//
// [EIP-1474]: https://eips.ethereum.org/EIPS/eip-1474
func TestParseQuantity(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		input   string
		want    int64
		wantErr error
	}{
		{name: "0x1c8 to 456", input: "0x1c8", want: 456},
		{name: "0x0 to zero", input: "0x0", want: 0},
		{name: "0x1 to one", input: "0x1", want: 1},
		{name: "0xa to ten", input: "0xa", want: 10},
		{name: "0xff to 255", input: "0xff", want: 255},
		{name: "empty string rejected", input: "", wantErr: ErrEmptyQuantity},
		{name: "0x no digits rejected", input: "0x", wantErr: ErrNoDigits},
		{name: "missing 0x prefix rejected", input: "1c8", wantErr: ErrMissingPrefix},
		{name: "leading zeros rejected", input: "0x0123", wantErr: ErrLeadingZeros},
		{name: "leading zero single digit rejected", input: "0x00", wantErr: ErrLeadingZeros},
		{name: "uppercase hex accepted", input: "0x1C8", want: 456},
		{name: "invalid hex char rejected", input: "0x1g", wantErr: ErrInvalidHex},
		{name: "0xg invalid after prefix", input: "0xg", wantErr: ErrInvalidHex},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := ParseQuantity(tc.input)
			if tc.wantErr != nil {
				if err == nil {
					t.Fatalf("ParseQuantity(%q): got nil error, want %v", tc.input, tc.wantErr)
				}
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("ParseQuantity(%q): error got %v, want %v", tc.input, err, tc.wantErr)
				}
				if got != nil {
					t.Fatalf("ParseQuantity(%q): got %v, want nil on error", tc.input, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseQuantity(%q): got error %v, want nil", tc.input, err)
			}
			if got.Cmp(big.NewInt(tc.want)) != 0 {
				t.Fatalf("ParseQuantity(%q): got %v, want %d", tc.input, got, tc.want)
			}
		})
	}
}

// TestParseQuantity_MaxUint64 verifies the boundary where the hex
// quantity equals math.MaxUint64. Per [EIP-1474], "0xffffffffffffffff"
// is a valid quantity and must parse to 18446744073709551615.
//
// [EIP-1474]: https://eips.ethereum.org/EIPS/eip-1474
func TestParseQuantity_MaxUint64(t *testing.T) {
	t.Parallel()
	got, err := ParseQuantity("0xffffffffffffffff")
	if err != nil {
		t.Fatalf("ParseQuantity: got error %v, want nil", err)
	}
	want := new(big.Int).SetUint64(math.MaxUint64)
	if got.Cmp(want) != 0 {
		t.Fatalf("ParseQuantity: got %v, want %v (max uint64)", got, want)
	}
}

// TestFormatQuantity verifies FormatQuantity against the [EIP-1474]
// quantity encoding vectors. Per EIP-1474, the output is "0x" plus
// lowercase hex with no leading zeros; "0x0" is the sole zero
// representation.
//
// [EIP-1474]: https://eips.ethereum.org/EIPS/eip-1474
func TestFormatQuantity(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		n    *big.Int
		want string
	}{
		{name: "456 to 0x1c8", n: big.NewInt(456), want: "0x1c8"},
		{name: "zero to 0x0", n: big.NewInt(0), want: "0x0"},
		{name: "one to 0x1", n: big.NewInt(1), want: "0x1"},
		{name: "255 to 0xff", n: big.NewInt(255), want: "0xff"},
		{name: "max uint64", n: new(big.Int).SetUint64(math.MaxUint64), want: "0xffffffffffffffff"},
		{name: "nil treated as zero", n: nil, want: "0x0"},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := FormatQuantity(tc.n)
			if got != tc.want {
				t.Fatalf("FormatQuantity(%v): got %q, want %q", tc.n, got, tc.want)
			}
		})
	}
}

// TestFormatQuantity_LargeValue verifies FormatQuantity handles values
// exceeding uint64 without truncation, since it returns a *big.Int
// representation.
func TestFormatQuantity_LargeValue(t *testing.T) {
	t.Parallel()
	n, ok := new(big.Int).SetString("100000000000000000000", 10)
	if !ok {
		t.Fatal("SetString: failed to parse large value")
	}
	got := FormatQuantity(n)
	const want = "0x56bc75e2d63100000"
	if got != want {
		t.Fatalf("FormatQuantity: got %q, want %q", got, want)
	}
}

// TestFormatQuantity_Negative pins the behavior of FormatQuantity for
// negative inputs. EIP-1474 quantities are unsigned, so a negative
// input is a caller bug. FormatQuantity does not return an error
// (its signature returns only a string); it produces "0x-1" which is
// not a valid quantity. This test documents that behavior so it is
// not discovered later as a silent bug. Callers must validate
// non-negativity before formatting.
func TestFormatQuantity_Negative(t *testing.T) {
	t.Parallel()
	got := FormatQuantity(big.NewInt(-1))
	const want = "0x-1"
	if got != want {
		t.Fatalf("FormatQuantity(-1): got %q, want %q", got, want)
	}
}

// TestQuantity_RoundTrip verifies that FormatQuantity(ParseQuantity(s))
// == s for the zero and max uint64 representations. Per [EIP-1474],
// these are canonical encodings and must round-trip exactly.
//
// [EIP-1474]: https://eips.ethereum.org/EIPS/eip-1474
func TestQuantity_RoundTrip(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		hex  string
	}{
		{name: "zero", hex: "0x0"},
		{name: "max uint64", hex: "0xffffffffffffffff"},
		{name: "456", hex: "0x1c8"},
		{name: "one", hex: "0x1"},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			n, err := ParseQuantity(tc.hex)
			if err != nil {
				t.Fatalf("ParseQuantity(%q): got error %v, want nil", tc.hex, err)
			}
			got := FormatQuantity(n)
			if got != tc.hex {
				t.Fatalf("round-trip: FormatQuantity(ParseQuantity(%q)) got %q, want %q", tc.hex, got, tc.hex)
			}
		})
	}
}

// TestParseBlockNumber verifies ParseBlockNumber against the [EIP-1474]
// quantity encoding, returning uint64. Per EIP-1474, the parsing rules
// match ParseQuantity; values exceeding math.MaxUint64 are rejected.
//
// [EIP-1474]: https://eips.ethereum.org/EIPS/eip-1474
func TestParseBlockNumber(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		input   string
		want    uint64
		wantErr error
	}{
		{name: "0x1c8 to 456", input: "0x1c8", want: 456},
		{name: "0x0 to zero", input: "0x0", want: 0},
		{name: "max uint64", input: "0xffffffffffffffff", want: math.MaxUint64},
		{name: "empty rejected", input: "", wantErr: ErrEmptyQuantity},
		{name: "missing prefix rejected", input: "1c8", wantErr: ErrMissingPrefix},
		{name: "no digits rejected", input: "0x", wantErr: ErrNoDigits},
		{name: "leading zeros rejected", input: "0x0123", wantErr: ErrLeadingZeros},
		{name: "exceeds uint64 rejected", input: "0x10000000000000000", wantErr: ErrBlockNumberOverflow},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := ParseBlockNumber(tc.input)
			if tc.wantErr != nil {
				if err == nil {
					t.Fatalf("ParseBlockNumber(%q): got nil error, want %v", tc.input, tc.wantErr)
				}
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("ParseBlockNumber(%q): error got %v, want %v", tc.input, err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseBlockNumber(%q): got error %v, want nil", tc.input, err)
			}
			if got != tc.want {
				t.Fatalf("ParseBlockNumber(%q): got %d, want %d", tc.input, got, tc.want)
			}
		})
	}
}

// TestParseBlockNumber_OverflowJustAboveMax verifies the boundary one
// above math.MaxUint64 is rejected while the max itself is accepted.
func TestParseBlockNumber_OverflowJustAboveMax(t *testing.T) {
	t.Parallel()
	// 0x10000000000000000 == 2^64 == MaxUint64 + 1.
	if _, err := ParseBlockNumber("0x10000000000000000"); err == nil {
		t.Fatal("ParseBlockNumber(2^64): got nil error, want overflow")
	} else if !errors.Is(err, ErrBlockNumberOverflow) {
		t.Fatalf("ParseBlockNumber(2^64): error got %v, want ErrBlockNumberOverflow", err)
	}
}

// TestQuantityErrors_Typed verifies each sentinel error is distinct
// and recoverable via errors.Is, matching the project's sentinel
// error convention.
func TestQuantityErrors_Typed(t *testing.T) {
	t.Parallel()
	sentinels := []error{
		ErrEmptyQuantity,
		ErrMissingPrefix,
		ErrNoDigits,
		ErrLeadingZeros,
		ErrInvalidHex,
		ErrBlockNumberOverflow,
	}
	seen := make(map[string]bool, len(sentinels))
	for _, s := range sentinels {
		if seen[s.Error()] {
			t.Fatalf("duplicate sentinel error message: %q", s.Error())
		}
		seen[s.Error()] = true
		var err error = s
		if !errors.Is(err, s) {
			t.Fatalf("errors.Is(%q): got false, want true", s.Error())
		}
	}
}
