package abi

import (
	"bytes"
	"crypto/subtle"
	"errors"
	"math/big"
	"testing"
)

// TestFunctionSelector verifies the 4-byte function selector against
// known vectors from the Solidity ABI Specification v2.
//
// Vector: transfer(address,uint256) → 0xa9059cbb — the canonical
// ERC-20 transfer selector, widely referenced across Ethereum tooling.
//
// Vector: getRoot(bytes32) → 0x84f94221 — cross-referenced with the
// hand-rolled selector in chain/evm/rootlookup.go (computed in its
// init() via hash.NewKeccak256().Sum([]byte("getRoot(bytes32)"))).
// WS-9 (TASK-042) will replace that hand-rolled value with this
// FunctionSelector; this test pins the value so the refactor is
// byte-identical.
func TestFunctionSelector(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name      string
		signature string
		want      [4]byte
	}{
		{
			name:      "transfer(address,uint256)",
			signature: "transfer(address,uint256)",
			want:      [4]byte{0xa9, 0x05, 0x9c, 0xbb},
		},
		{
			name:      "getRoot(bytes32)",
			signature: "getRoot(bytes32)",
			want:      [4]byte{0x84, 0xf9, 0x42, 0x21},
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := FunctionSelector(tc.signature)
			// Selector bytes are security-sensitive (drive contract
			// dispatch); compare in constant time.
			if subtle.ConstantTimeCompare(got[:], tc.want[:]) != 1 {
				t.Fatalf("FunctionSelector(%q) = %x, want %x", tc.signature, got, tc.want)
			}
		})
	}
}

// TestFunctionSelectorDeterminism verifies the same signature always
// produces the same selector (Keccak-256 is deterministic).
func TestFunctionSelectorDeterminism(t *testing.T) {
	t.Parallel()
	sig := "transfer(address,uint256)"
	a := FunctionSelector(sig)
	b := FunctionSelector(sig)
	if subtle.ConstantTimeCompare(a[:], b[:]) != 1 {
		t.Fatalf("non-deterministic selector: %x vs %x", a, b)
	}
}

// TestParseABIType covers all supported canonical type strings and the
// rejection of unsupported ones.
func TestParseABIType(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		input   string
		want    ABIType
		wantErr error
	}{
		{name: "uint256", input: "uint256", want: ABITypeUint256},
		{name: "address", input: "address", want: ABITypeAddress},
		{name: "bytes32", input: "bytes32", want: ABITypeBytes32},
		{name: "bool", input: "bool", want: ABITypeBool},
		{name: "string", input: "string", want: ABITypeString},
		{name: "bytes", input: "bytes", want: ABITypeBytes},
		{name: "uint256[]", input: "uint256[]", want: ABITypeUint256Array},
		{name: "address[]", input: "address[]", want: ABITypeAddressArray},
		{name: "empty string", input: "", wantErr: ErrUnknownABIType},
		{name: "invalid", input: "invalid", wantErr: ErrUnknownABIType},
		{name: "tuple", input: "tuple", wantErr: ErrUnknownABIType},
		{name: "uint alias", input: "uint", wantErr: ErrUnknownABIType},
		{name: "fixed array", input: "uint256[3]", wantErr: ErrUnknownABIType},
		{name: "nested tuple", input: "(uint256,address)", wantErr: ErrUnknownABIType},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := ParseABIType(tc.input)
			if tc.wantErr != nil {
				if err == nil {
					t.Fatalf("ParseABIType(%q) err = nil, want error matching %v", tc.input, tc.wantErr)
				}
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("ParseABIType(%q) err = %v, want errors.Is %v", tc.input, err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseABIType(%q) unexpected err = %v", tc.input, err)
			}
			if got != tc.want {
				t.Fatalf("ParseABIType(%q) = %v, want %v", tc.input, got, tc.want)
			}
		})
	}
}

// TestABITypeString verifies ABIType.String is the inverse of
// ParseABIType for supported types.
func TestABITypeString(t *testing.T) {
	t.Parallel()
	for _, s := range []string{"uint256", "address", "bytes32", "bool", "string", "bytes", "uint256[]", "address[]"} {
		typ, err := ParseABIType(s)
		if err != nil {
			t.Fatalf("ParseABIType(%q) err = %v", s, err)
		}
		if got := typ.String(); got != s {
			t.Errorf("ABIType(%q).String() = %q, want %q", s, got, s)
		}
	}
}

// maxUint256 is 2^256-1, used as a boundary value.
var maxUint256Val = new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 256), big.NewInt(1))

// TestEncodeDecodeRoundTrip round-trips EncodeArgs + DecodeArgs for each
// supported type and verifies the decoded value equals the input.
func TestEncodeDecodeRoundTrip(t *testing.T) {
	t.Parallel()

	addr := [20]byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
		0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13}
	addr2 := [20]byte{0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef, 0xde, 0xad,
		0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef}
	b32 := [32]byte{0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd,
		0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01,
		0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45,
		0x67, 0x89}

	cases := []struct {
		name  string
		types []ABIType
		vals  []interface{}
		check func(t *testing.T, got []interface{})
	}{
		{
			name:  "uint256 zero",
			types: []ABIType{ABITypeUint256},
			vals:  []interface{}{big.NewInt(0)},
			check: func(t *testing.T, got []interface{}) {
				v, ok := got[0].(*big.Int)
				if !ok {
					t.Fatalf("got[0] type %T, want *big.Int", got[0])
				}
				if v.Cmp(big.NewInt(0)) != 0 {
					t.Fatalf("uint256 = %s, want 0", v)
				}
			},
		},
		{
			name:  "uint256 max",
			types: []ABIType{ABITypeUint256},
			vals:  []interface{}{new(big.Int).Set(maxUint256Val)},
			check: func(t *testing.T, got []interface{}) {
				v, ok := got[0].(*big.Int)
				if !ok {
					t.Fatalf("got[0] type %T, want *big.Int", got[0])
				}
				if v.Cmp(maxUint256Val) != 0 {
					t.Fatalf("uint256 = %s, want %s", v, maxUint256Val)
				}
			},
		},
		{
			name:  "uint256 typical",
			types: []ABIType{ABITypeUint256},
			vals:  []interface{}{big.NewInt(123456789)},
			check: func(t *testing.T, got []interface{}) {
				v, ok := got[0].(*big.Int)
				if !ok {
					t.Fatalf("got[0] type %T, want *big.Int", got[0])
				}
				if v.Cmp(big.NewInt(123456789)) != 0 {
					t.Fatalf("uint256 = %s, want 123456789", v)
				}
			},
		},
		{
			name:  "address",
			types: []ABIType{ABITypeAddress},
			vals:  []interface{}{addr},
			check: func(t *testing.T, got []interface{}) {
				v, ok := got[0].([20]byte)
				if !ok {
					t.Fatalf("got[0] type %T, want [20]byte", got[0])
				}
				if v != addr {
					t.Fatalf("address = %x, want %x", v, addr)
				}
			},
		},
		{
			name:  "bytes32",
			types: []ABIType{ABITypeBytes32},
			vals:  []interface{}{b32},
			check: func(t *testing.T, got []interface{}) {
				v, ok := got[0].([32]byte)
				if !ok {
					t.Fatalf("got[0] type %T, want [32]byte", got[0])
				}
				if v != b32 {
					t.Fatalf("bytes32 = %x, want %x", v, b32)
				}
			},
		},
		{
			name:  "bool true",
			types: []ABIType{ABITypeBool},
			vals:  []interface{}{true},
			check: func(t *testing.T, got []interface{}) {
				v, ok := got[0].(bool)
				if !ok {
					t.Fatalf("got[0] type %T, want bool", got[0])
				}
				if !v {
					t.Fatalf("bool = false, want true")
				}
			},
		},
		{
			name:  "bool false",
			types: []ABIType{ABITypeBool},
			vals:  []interface{}{false},
			check: func(t *testing.T, got []interface{}) {
				v, ok := got[0].(bool)
				if !ok {
					t.Fatalf("got[0] type %T, want bool", got[0])
				}
				if v {
					t.Fatalf("bool = true, want false")
				}
			},
		},
		{
			name:  "string",
			types: []ABIType{ABITypeString},
			vals:  []interface{}{"hello, ethereum"},
			check: func(t *testing.T, got []interface{}) {
				v, ok := got[0].(string)
				if !ok {
					t.Fatalf("got[0] type %T, want string", got[0])
				}
				if v != "hello, ethereum" {
					t.Fatalf("string = %q, want %q", v, "hello, ethereum")
				}
			},
		},
		{
			name:  "string empty",
			types: []ABIType{ABITypeString},
			vals:  []interface{}{""},
			check: func(t *testing.T, got []interface{}) {
				v, ok := got[0].(string)
				if !ok {
					t.Fatalf("got[0] type %T, want string", got[0])
				}
				if v != "" {
					t.Fatalf("string = %q, want empty", v)
				}
			},
		},
		{
			name:  "bytes",
			types: []ABIType{ABITypeBytes},
			vals:  []interface{}{[]byte{0xde, 0xad, 0xbe, 0xef}},
			check: func(t *testing.T, got []interface{}) {
				v, ok := got[0].([]byte)
				if !ok {
					t.Fatalf("got[0] type %T, want []byte", got[0])
				}
				want := []byte{0xde, 0xad, 0xbe, 0xef}
				if !bytes.Equal(v, want) {
					t.Fatalf("bytes = %x, want %x", v, want)
				}
			},
		},
		{
			name:  "bytes empty",
			types: []ABIType{ABITypeBytes},
			vals:  []interface{}{[]byte{}},
			check: func(t *testing.T, got []interface{}) {
				v, ok := got[0].([]byte)
				if !ok {
					t.Fatalf("got[0] type %T, want []byte", got[0])
				}
				if len(v) != 0 {
					t.Fatalf("bytes len = %d, want 0", len(v))
				}
			},
		},
		{
			name:  "uint256[]",
			types: []ABIType{ABITypeUint256Array},
			vals:  []interface{}{[]*big.Int{big.NewInt(1), big.NewInt(2), big.NewInt(3)}},
			check: func(t *testing.T, got []interface{}) {
				v, ok := got[0].([]*big.Int)
				if !ok {
					t.Fatalf("got[0] type %T, want []*big.Int", got[0])
				}
				want := []*big.Int{big.NewInt(1), big.NewInt(2), big.NewInt(3)}
				if len(v) != len(want) {
					t.Fatalf("uint256[] len = %d, want %d", len(v), len(want))
				}
				for i := range want {
					if v[i].Cmp(want[i]) != 0 {
						t.Fatalf("uint256[%d] = %s, want %s", i, v[i], want[i])
					}
				}
			},
		},
		{
			name:  "uint256[] empty",
			types: []ABIType{ABITypeUint256Array},
			vals:  []interface{}{[]*big.Int{}},
			check: func(t *testing.T, got []interface{}) {
				v, ok := got[0].([]*big.Int)
				if !ok {
					t.Fatalf("got[0] type %T, want []*big.Int", got[0])
				}
				if len(v) != 0 {
					t.Fatalf("uint256[] len = %d, want 0", len(v))
				}
			},
		},
		{
			name:  "address[]",
			types: []ABIType{ABITypeAddressArray},
			vals:  []interface{}{[][20]byte{addr, addr2}},
			check: func(t *testing.T, got []interface{}) {
				v, ok := got[0].([][20]byte)
				if !ok {
					t.Fatalf("got[0] type %T, want [][20]byte", got[0])
				}
				want := [][20]byte{addr, addr2}
				if len(v) != len(want) {
					t.Fatalf("address[] len = %d, want %d", len(v), len(want))
				}
				for i := range want {
					if v[i] != want[i] {
						t.Fatalf("address[%d] = %x, want %x", i, v[i], want[i])
					}
				}
			},
		},
		{
			name:  "address[] empty",
			types: []ABIType{ABITypeAddressArray},
			vals:  []interface{}{[][20]byte{}},
			check: func(t *testing.T, got []interface{}) {
				v, ok := got[0].([][20]byte)
				if !ok {
					t.Fatalf("got[0] type %T, want [][20]byte", got[0])
				}
				if len(v) != 0 {
					t.Fatalf("address[] len = %d, want 0", len(v))
				}
			},
		},
		{
			name:  "mixed static and dynamic",
			types: []ABIType{ABITypeUint256, ABITypeString, ABITypeAddress, ABITypeUint256Array},
			vals: []interface{}{
				big.NewInt(42),
				"mixed tuple",
				addr,
				[]*big.Int{big.NewInt(7), big.NewInt(8)},
			},
			check: func(t *testing.T, got []interface{}) {
				if got[0].(*big.Int).Cmp(big.NewInt(42)) != 0 {
					t.Fatalf("uint256 = %s, want 42", got[0].(*big.Int))
				}
				if got[1].(string) != "mixed tuple" {
					t.Fatalf("string = %q, want %q", got[1], "mixed tuple")
				}
				if got[2].([20]byte) != addr {
					t.Fatalf("address = %x, want %x", got[2], addr)
				}
				arr := got[3].([]*big.Int)
				if len(arr) != 2 || arr[0].Cmp(big.NewInt(7)) != 0 || arr[1].Cmp(big.NewInt(8)) != 0 {
					t.Fatalf("uint256[] = %s, want [7,8]", arr)
				}
			},
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			encoded, err := EncodeArgs(tc.types, tc.vals)
			if err != nil {
				t.Fatalf("EncodeArgs err = %v", err)
			}
			// Every encoding must be a whole number of 32-byte words.
			if len(encoded)%wordSize != 0 {
				t.Fatalf("encoded length %d not a multiple of %d", len(encoded), wordSize)
			}
			got, err := DecodeArgs(tc.types, encoded)
			if err != nil {
				t.Fatalf("DecodeArgs err = %v", err)
			}
			if len(got) != len(tc.vals) {
				t.Fatalf("decoded count = %d, want %d", len(got), len(tc.vals))
			}
			tc.check(t, got)
		})
	}
}

// TestEncodeUint256StaticWord verifies the static uint256 encoding is
// exactly one 32-byte big-endian word (no offset/tail).
func TestEncodeUint256StaticWord(t *testing.T) {
	t.Parallel()
	encoded, err := EncodeArgs([]ABIType{ABITypeUint256}, []interface{}{big.NewInt(1)})
	if err != nil {
		t.Fatalf("EncodeArgs err = %v", err)
	}
	if len(encoded) != wordSize {
		t.Fatalf("uint256 encoded length = %d, want %d (single word, no tail)", len(encoded), wordSize)
	}
	want := [32]byte{}
	want[wordSize-1] = 1
	if !bytes.Equal(encoded, want[:]) {
		t.Fatalf("uint256 word = %x, want %x", encoded, want)
	}
}

// TestEncodeAddressPadding verifies the address is right-aligned with
// 12 zero bytes of left padding.
func TestEncodeAddressPadding(t *testing.T) {
	t.Parallel()
	addr := [20]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20}
	encoded, err := EncodeArgs([]ABIType{ABITypeAddress}, []interface{}{addr})
	if err != nil {
		t.Fatalf("EncodeArgs err = %v", err)
	}
	for i := 0; i < 12; i++ {
		if encoded[i] != 0 {
			t.Fatalf("address left padding byte %d = %x, want 0", i, encoded[i])
		}
	}
	got := [20]byte{}
	copy(got[:], encoded[12:])
	if got != addr {
		t.Fatalf("address = %x, want %x", got, addr)
	}
}

// TestEncodeDynamicOffset verifies the dynamic-type head word holds the
// correct offset relative to the start of the head section.
func TestEncodeDynamicOffset(t *testing.T) {
	t.Parallel()
	// One static (uint256) + one dynamic (string). Head is 2 words = 64
	// bytes; the string offset must be 64.
	encoded, err := EncodeArgs(
		[]ABIType{ABITypeUint256, ABITypeString},
		[]interface{}{big.NewInt(1), "ab"},
	)
	if err != nil {
		t.Fatalf("EncodeArgs err = %v", err)
	}
	off := new(big.Int).SetBytes(encoded[wordSize : 2*wordSize]).Int64()
	if off != 64 {
		t.Fatalf("string offset = %d, want 64", off)
	}
	// At offset 64: 32-byte length (2) then "ab" padded to 32 bytes.
	length := new(big.Int).SetBytes(encoded[64 : 64+wordSize]).Int64()
	if length != 2 {
		t.Fatalf("string length = %d, want 2", length)
	}
	if string(encoded[64+wordSize:64+wordSize+2]) != "ab" {
		t.Fatalf("string payload = %x, want %x", encoded[64+wordSize:64+wordSize+2], "ab")
	}
}

// TestEncodeErrors covers the negative encode paths.
func TestEncodeErrors(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name   string
		types  []ABIType
		vals   []interface{}
		wantEr error
	}{
		{
			name:   "count mismatch more values",
			types:  []ABIType{ABITypeUint256},
			vals:   []interface{}{big.NewInt(1), big.NewInt(2)},
			wantEr: ErrArgCountMismatch,
		},
		{
			name:   "count mismatch more types",
			types:  []ABIType{ABITypeUint256, ABITypeBool},
			vals:   []interface{}{big.NewInt(1)},
			wantEr: ErrArgCountMismatch,
		},
		{
			name:   "uint256 wrong type",
			types:  []ABIType{ABITypeUint256},
			vals:   []interface{}{int(1)},
			wantEr: ErrWrongValueType,
		},
		{
			name:   "address wrong type",
			types:  []ABIType{ABITypeAddress},
			vals:   []interface{}{[21]byte{}},
			wantEr: ErrWrongValueType,
		},
		{
			name:   "bytes32 wrong type",
			types:  []ABIType{ABITypeBytes32},
			vals:   []interface{}{[31]byte{}},
			wantEr: ErrWrongValueType,
		},
		{
			name:   "bool wrong type",
			types:  []ABIType{ABITypeBool},
			vals:   []interface{}{1},
			wantEr: ErrWrongValueType,
		},
		{
			name:   "string wrong type",
			types:  []ABIType{ABITypeString},
			vals:   []interface{}{42},
			wantEr: ErrWrongValueType,
		},
		{
			name:   "bytes wrong type",
			types:  []ABIType{ABITypeBytes},
			vals:   []interface{}{"not bytes"},
			wantEr: ErrWrongValueType,
		},
		{
			name:   "uint256[] wrong type",
			types:  []ABIType{ABITypeUint256Array},
			vals:   []interface{}{[]int{1, 2}},
			wantEr: ErrWrongValueType,
		},
		{
			name:   "address[] wrong type",
			types:  []ABIType{ABITypeAddressArray},
			vals:   []interface{}{[][21]byte{}},
			wantEr: ErrWrongValueType,
		},
		{
			name:   "uint256 negative overflow",
			types:  []ABIType{ABITypeUint256},
			vals:   []interface{}{big.NewInt(-1)},
			wantEr: ErrUint256Overflow,
		},
		{
			name:   "uint256 exceeds max",
			types:  []ABIType{ABITypeUint256},
			vals:   []interface{}{new(big.Int).Add(new(big.Int).Set(maxUint256Val), big.NewInt(1))},
			wantEr: ErrUint256Overflow,
		},
		{
			name:   "uint256[] element overflow",
			types:  []ABIType{ABITypeUint256Array},
			vals:   []interface{}{[]*big.Int{big.NewInt(-1)}},
			wantEr: ErrUint256Overflow,
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := EncodeArgs(tc.types, tc.vals)
			if err == nil {
				t.Fatalf("EncodeArgs err = nil, want error matching %v", tc.wantEr)
			}
			if !errors.Is(err, tc.wantEr) {
				t.Fatalf("EncodeArgs err = %v, want errors.Is %v", err, tc.wantEr)
			}
		})
	}
}

// TestDecodeErrors covers the negative decode paths.
func TestDecodeErrors(t *testing.T) {
	t.Parallel()

	// A valid encoding of (uint256, string) for constructing tampered
	// inputs.
	valid, err := EncodeArgs(
		[]ABIType{ABITypeUint256, ABITypeString},
		[]interface{}{big.NewInt(1), "hello"},
	)
	if err != nil {
		t.Fatalf("setup EncodeArgs err = %v", err)
	}

	cases := []struct {
		name    string
		types   []ABIType
		data    []byte
		wantEr  error
		wantMsg string
	}{
		{
			name:   "short data no head",
			types:  []ABIType{ABITypeUint256},
			data:   []byte{0x00, 0x01},
			wantEr: ErrShortData,
		},
		{
			name:   "short data two types one word",
			types:  []ABIType{ABITypeUint256, ABITypeBool},
			data:   make([]byte, wordSize),
			wantEr: ErrShortData,
		},
		{
			name:   "empty data zero types ok",
			types:  []ABIType{},
			data:   nil,
			wantEr: nil,
		},
		{
			name:   "string offset out of range",
			types:  []ABIType{ABITypeString},
			data:   append(word(maxUint256Val), make([]byte, wordSize)...),
			wantEr: ErrBadOffset,
		},
		{
			name:  "string offset not representable as int64",
			types: []ABIType{ABITypeString},
			// offset = 2^64 — truncates to 0 without the IsInt64 guard.
			data:   append(word(new(big.Int).Lsh(big.NewInt(1), 64)), make([]byte, wordSize)...),
			wantEr: ErrBadOffset,
		},
		{
			name:  "string offset not word aligned",
			types: []ABIType{ABITypeString},
			// offset = 1 (not word-aligned)
			data:   append(word(big.NewInt(1)), make([]byte, wordSize)...),
			wantEr: ErrBadOffset,
		},
		{
			name:  "string length exceeds remaining",
			types: []ABIType{ABITypeString},
			// offset 32 (valid), then length word claims 100 bytes but
			// only 0 remain after the length word.
			data:   append(append(word(big.NewInt(wordSize)), word(big.NewInt(100))...), make([]byte, 0)...),
			wantEr: ErrShortData,
		},
		{
			name:  "string missing length word",
			types: []ABIType{ABITypeString},
			// offset 32 (valid) but no bytes after the head.
			data:   word(big.NewInt(wordSize)),
			wantEr: ErrShortData,
		},
		{
			name:  "uint256[] length exceeds remaining",
			types: []ABIType{ABITypeUint256Array},
			// offset 32, length 5 (claims 160 bytes), 0 remain.
			data:   append(append(word(big.NewInt(wordSize)), word(big.NewInt(5))...), make([]byte, 0)...),
			wantEr: ErrShortData,
		},
		{
			name:   "address[] length exceeds remaining",
			types:  []ABIType{ABITypeAddressArray},
			data:   append(append(word(big.NewInt(wordSize)), word(big.NewInt(5))...), make([]byte, 0)...),
			wantEr: ErrShortData,
		},
		{
			name:   "bytes length exceeds remaining",
			types:  []ABIType{ABITypeBytes},
			data:   append(append(word(big.NewInt(wordSize)), word(big.NewInt(100))...), make([]byte, 0)...),
			wantEr: ErrShortData,
		},
		{
			name:   "tampered valid encoding truncated head",
			types:  []ABIType{ABITypeUint256, ABITypeString},
			data:   valid[:wordSize], // only one word of a two-word head
			wantEr: ErrShortData,
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := DecodeArgs(tc.types, tc.data)
			if tc.wantEr == nil {
				if err != nil {
					t.Fatalf("DecodeArgs err = %v, want nil", err)
				}
				if len(got) != 0 {
					t.Fatalf("DecodeArgs returned %d values, want 0", len(got))
				}
				return
			}
			if err == nil {
				t.Fatalf("DecodeArgs err = nil, want error matching %v", tc.wantEr)
			}
			if !errors.Is(err, tc.wantEr) {
				t.Fatalf("DecodeArgs err = %v, want errors.Is %v", err, tc.wantEr)
			}
		})
	}
}

// TestEncodeNilUint256 verifies a nil *big.Int encodes as zero.
func TestEncodeNilUint256(t *testing.T) {
	t.Parallel()
	encoded, err := EncodeArgs([]ABIType{ABITypeUint256}, []interface{}{(*big.Int)(nil)})
	if err != nil {
		t.Fatalf("EncodeArgs err = %v", err)
	}
	for i, b := range encoded {
		if b != 0 {
			t.Fatalf("nil uint256 byte %d = %x, want 0", i, b)
		}
	}
}

// TestRoundTripReencode verifies that decoding then re-encoding
// produces byte-identical output (the encoding is canonical).
func TestRoundTripReencode(t *testing.T) {
	t.Parallel()
	types := []ABIType{ABITypeUint256, ABITypeString, ABITypeAddressArray}
	addr := [20]byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33,
		0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd}
	vals := []interface{}{big.NewInt(99), "reencode", [][20]byte{addr}}
	enc1, err := EncodeArgs(types, vals)
	if err != nil {
		t.Fatalf("EncodeArgs err = %v", err)
	}
	decoded, err := DecodeArgs(types, enc1)
	if err != nil {
		t.Fatalf("DecodeArgs err = %v", err)
	}
	enc2, err := EncodeArgs(types, decoded)
	if err != nil {
		t.Fatalf("re-encode err = %v", err)
	}
	if !bytes.Equal(enc1, enc2) {
		t.Fatalf("re-encode not canonical:\nenc1 = %x\nenc2 = %x", enc1, enc2)
	}
}

// word builds a 32-byte big-endian word from a *big.Int.
func word(v *big.Int) []byte {
	b := make([]byte, wordSize)
	src := v.Bytes()
	copy(b[wordSize-len(src):], src)
	return b
}
