package rlp

import (
	"bytes"
	"encoding/hex"
	"errors"
	"reflect"
	"testing"
)

// hexDecode is a test helper that panics on invalid hex so test vectors
// fail loudly rather than silently passing with a nil slice.
func hexDecode(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("hexDecode(%q): %v", s, err)
	}
	return b
}

// TestEncodeBytes covers Yellow Paper Appendix B byte-string vectors.
//
// Reference: Ethereum Yellow Paper, Appendix B.
func TestEncodeBytes(t *testing.T) {
	tests := []struct {
		name  string
		input []byte
		want  []byte
	}{
		// Vector: [Yellow Paper Appendix B] "" → 0x80.
		{"empty string", []byte(""), hexDecode(t, "80")},
		// Vector: [Yellow Paper Appendix B] 0x0f → 0x0f (single byte < 0x80).
		{"single byte below 0x80", []byte{0x0f}, hexDecode(t, "0f")},
		// Vector: [Yellow Paper Appendix B] "dog" → 0x83646f67.
		{"dog", []byte("dog"), hexDecode(t, "83646f67")},
		// Boundary: single byte exactly 0x80 must use 0x81 prefix.
		{"single byte 0x80", []byte{0x80}, hexDecode(t, "8180")},
		// Boundary: single byte 0xff.
		{"single byte 0xff", []byte{0xff}, hexDecode(t, "81ff")},
		// Boundary: exactly 55 bytes uses short form (0x80+55 = 0xb7).
		{"55 bytes", bytes.Repeat([]byte{0xaa}, 55), append([]byte{0xb7}, bytes.Repeat([]byte{0xaa}, 55)...)},
		// Boundary: 56 bytes uses long form (0xb8 0x38 ...).
		{"56 bytes", bytes.Repeat([]byte{0xaa}, 56), append([]byte{0xb8, 0x38}, bytes.Repeat([]byte{0xaa}, 56)...)},
		// Vector: [Yellow Paper Appendix B] encode nil → 0x80.
		{"nil slice", nil, hexDecode(t, "80")},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := EncodeBytes(tt.input)
			if !bytes.Equal(got, tt.want) {
				t.Errorf("EncodeBytes(% x): got % x, want % x", tt.input, got, tt.want)
			}
		})
	}
}

// TestEncodeList covers Yellow Paper Appendix B list vectors.
//
// Reference: Ethereum Yellow Paper, Appendix B.
func TestEncodeList(t *testing.T) {
	tests := []struct {
		name  string
		items []byte // pre-encoded items concatenated for comparison
		args  [][]byte
		want  []byte
	}{
		// Vector: [Yellow Paper Appendix B] empty list → 0xc0.
		{"empty list", nil, nil, hexDecode(t, "c0")},
		// Vector: [Yellow Paper Appendix B] ["cat","dog"] → 0xc8 8363617483646f67.
		{
			name: "cat dog",
			args: [][]byte{
				EncodeBytes([]byte("cat")),
				EncodeBytes([]byte("dog")),
			},
			want: hexDecode(t, "c88363617483646f67"),
		},
		// Boundary: list payload exactly 55 bytes → short form (0xc0+55 = 0xf7).
		{
			name: "payload 55 bytes",
			args: [][]byte{bytes.Repeat([]byte{0xaa}, 55)},
			want: append([]byte{0xf7}, bytes.Repeat([]byte{0xaa}, 55)...),
		},
		// Boundary: list payload 56 bytes → long form (0xf8 0x38 ...).
		{
			name: "payload 56 bytes",
			args: [][]byte{bytes.Repeat([]byte{0xaa}, 56)},
			want: append([]byte{0xf8, 0x38}, bytes.Repeat([]byte{0xaa}, 56)...),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := EncodeList(tt.args...)
			if !bytes.Equal(got, tt.want) {
				t.Errorf("EncodeList(% x): got % x, want % x", tt.items, got, tt.want)
			}
		})
	}
}

// TestEncodeUint64 covers Yellow Paper Appendix B integer vectors.
//
// Reference: Ethereum Yellow Paper, Appendix B.
func TestEncodeUint64(t *testing.T) {
	tests := []struct {
		name string
		n    uint64
		want []byte
	}{
		// Vector: [Yellow Paper Appendix B] integer 0 → 0x80.
		{"zero", 0, hexDecode(t, "80")},
		// Vector: [Yellow Paper Appendix B] integer 15 → 0x0f.
		{"fifteen", 15, hexDecode(t, "0f")},
		// Vector: [Yellow Paper Appendix B] integer 1024 → 0x820400.
		{"1024", 1024, hexDecode(t, "820400")},
		// Boundary: single-byte max (127) → 0x7f.
		{"127", 127, hexDecode(t, "7f")},
		// Boundary: 128 → 0x8180 (needs 1-byte string since 0x80 >= 0x80).
		{"128", 128, hexDecode(t, "8180")},
		// Boundary: 255 → 0x81ff.
		{"255", 255, hexDecode(t, "81ff")},
		// Boundary: 256 → 0x820100.
		{"256", 256, hexDecode(t, "820100")},
		// Max uint64 → 8-byte big-endian.
		{"max uint64", ^uint64(0), append([]byte{0x88}, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := EncodeUint64(tt.n)
			if !bytes.Equal(got, tt.want) {
				t.Errorf("EncodeUint64(%d): got % x, want % x", tt.n, got, tt.want)
			}
		})
	}
}

// TestDecode covers Yellow Paper Appendix B decode vectors.
//
// Reference: Ethereum Yellow Paper, Appendix B.
func TestDecode(t *testing.T) {
	tests := []struct {
		name  string
		input []byte
		want  interface{}
	}{
		// Vector: [Yellow Paper Appendix B] "" → 0x80.
		{"empty string", hexDecode(t, "80"), []byte{}},
		// Vector: [Yellow Paper Appendix B] 0x0f → 0x0f.
		{"single byte 0x0f", hexDecode(t, "0f"), []byte{0x0f}},
		// Vector: [Yellow Paper Appendix B] "dog" → 0x83646f67.
		{"dog", hexDecode(t, "83646f67"), []byte("dog")},
		// Vector: [Yellow Paper Appendix B] empty list → 0xc0.
		{"empty list", hexDecode(t, "c0"), []interface{}{}},
		// Vector: [Yellow Paper Appendix B] ["cat","dog"] → 0xc88363617483646f67.
		{
			name:  "cat dog list",
			input: hexDecode(t, "c88363617483646f67"),
			want:  []interface{}{[]byte("cat"), []byte("dog")},
		},
		// Nested list: [ [], [[]], [] ] → 0xc4 c0 c1c0 c0.
		{
			name:  "nested list",
			input: hexDecode(t, "c4c0c1c0c0"),
			want: []interface{}{
				[]interface{}{},
				[]interface{}{[]interface{}{}},
				[]interface{}{},
			},
		},
		// Integer 1024 → 0x820400 decodes to [0x04, 0x00].
		{"integer 1024", hexDecode(t, "820400"), []byte{0x04, 0x00}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Decode(tt.input)
			if err != nil {
				t.Fatalf("Decode(% x): unexpected error: %v", tt.input, err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Decode(% x): got %#v, want %#v", tt.input, got, tt.want)
			}
		})
	}
}

// TestDecodeErrors covers negative decode cases: truncated input,
// non-canonical encodings, and trailing bytes.
func TestDecodeErrors(t *testing.T) {
	tests := []struct {
		name     string
		input    []byte
		wantErr  error
		errMatch string
	}{
		// Negative: empty input → truncated.
		{"empty input", []byte{}, ErrTruncated, ""},
		// Negative: byte string claims 3 bytes but none follow → truncated.
		{"truncated byte string", hexDecode(t, "83"), ErrTruncated, ""},
		// Negative: byte string claims 5 bytes, only 2 follow → truncated.
		{"truncated byte string partial", hexDecode(t, "850102"), ErrTruncated, ""},
		// Negative: long-form byte string length present but payload short.
		{"truncated long byte string", hexDecode(t, "b83801"), ErrTruncated, ""},
		// Negative: list claims 3 bytes but none follow → truncated.
		{"truncated list", hexDecode(t, "c3"), ErrTruncated, ""},
		// Negative: non-canonical single byte (0x81 0x00 should be 0x00).
		{"non-canonical single byte", hexDecode(t, "8100"), ErrInvalidEncoding, "non-canonical single byte"},
		// Negative: non-canonical long-form byte string (1-byte payload in long form).
		{"non-canonical long byte string", hexDecode(t, "b80141"), ErrInvalidEncoding, "non-canonical long-form byte string"},
		// Negative: non-canonical long-form list (empty list in long form).
		{"non-canonical long list", hexDecode(t, "f800"), ErrInvalidEncoding, "non-canonical long-form list"},
		// Negative: leading zero in long-form length.
		{"leading zero length", hexDecode(t, "b9000100"), ErrInvalidEncoding, "leading zero in length"},
		// Negative: trailing bytes after a complete item.
		{"trailing bytes", hexDecode(t, "8080"), ErrTrailingBytes, ""},
		// Negative: trailing bytes after a list.
		{"trailing bytes after list", hexDecode(t, "c080"), ErrTrailingBytes, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Decode(tt.input)
			if err == nil {
				t.Fatalf("Decode(% x): expected error, got nil", tt.input)
			}
			if !errors.Is(err, tt.wantErr) {
				t.Errorf("Decode(% x): error = %v, want %v", tt.input, err, tt.wantErr)
			}
		})
	}
}

// TestRoundTripByteStrings verifies decode(encode(x)) == x for byte strings.
func TestRoundTripByteStrings(t *testing.T) {
	tests := []struct {
		name string
		val  []byte
	}{
		{"empty", []byte{}},
		{"single low byte", []byte{0x00}},
		{"single 0x7f", []byte{0x7f}},
		{"single 0x80", []byte{0x80}},
		{"single 0xff", []byte{0xff}},
		{"short string", []byte("hello")},
		{"55 bytes", bytes.Repeat([]byte{0xaa}, 55)},
		{"56 bytes", bytes.Repeat([]byte{0xaa}, 56)},
		{"1000 bytes", bytes.Repeat([]byte{0xbb}, 1000)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			encoded := EncodeBytes(tt.val)
			decoded, err := Decode(encoded)
			if err != nil {
				t.Fatalf("Decode(% x): unexpected error: %v", encoded, err)
			}
			got, ok := decoded.([]byte)
			if !ok {
				t.Fatalf("Decode(% x): got %T, want []byte", encoded, decoded)
			}
			if !bytes.Equal(got, tt.val) {
				t.Errorf("round-trip: got % x, want % x", got, tt.val)
			}
		})
	}
}

// TestRoundTripUint64 verifies decode(encode(n)) recovers the integer.
func TestRoundTripUint64(t *testing.T) {
	tests := []struct {
		name string
		n    uint64
	}{
		{"zero", 0},
		{"one", 1},
		{"fifteen", 15},
		{"127", 127},
		{"128", 128},
		{"255", 255},
		{"256", 256},
		{"1024", 1024},
		{"max uint64", ^uint64(0)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			encoded := EncodeUint64(tt.n)
			decoded, err := Decode(encoded)
			if err != nil {
				t.Fatalf("Decode(% x): unexpected error: %v", encoded, err)
			}
			got, ok := decoded.([]byte)
			if !ok {
				t.Fatalf("Decode(% x): got %T, want []byte", encoded, decoded)
			}
			// Reconstruct the uint64 from the stripped big-endian bytes.
			var recovered uint64
			for _, b := range got {
				recovered = (recovered << 8) | uint64(b)
			}
			if recovered != tt.n {
				t.Errorf("round-trip uint64: got %d, want %d (bytes % x)", recovered, tt.n, got)
			}
		})
	}
}

// TestRoundTripNestedLists verifies decode(encode(list)) == list for
// arbitrarily nested lists.
func TestRoundTripNestedLists(t *testing.T) {
	tests := []struct {
		name    string
		encoded []byte
		want    interface{}
	}{
		{
			name:    "empty list",
			encoded: EncodeList(),
			want:    []interface{}{},
		},
		{
			name:    "flat list of strings",
			encoded: EncodeList(EncodeBytes([]byte("cat")), EncodeBytes([]byte("dog"))),
			want:    []interface{}{[]byte("cat"), []byte("dog")},
		},
		{
			name: "list with integer and string",
			encoded: EncodeList(
				EncodeUint64(1024),
				EncodeBytes([]byte("hello")),
			),
			want: []interface{}{[]byte{0x04, 0x00}, []byte("hello")},
		},
		{
			name: "nested empty lists",
			encoded: EncodeList(
				EncodeList(),
				EncodeList(EncodeList()),
			),
			want: []interface{}{
				[]interface{}{},
				[]interface{}{[]interface{}{}},
			},
		},
		{
			name: "deeply nested",
			encoded: EncodeList(
				EncodeBytes([]byte("a")),
				EncodeList(
					EncodeBytes([]byte("b")),
					EncodeList(EncodeBytes([]byte("c"))),
				),
				EncodeUint64(42),
			),
			want: []interface{}{
				[]byte("a"),
				[]interface{}{
					[]byte("b"),
					[]interface{}{[]byte("c")},
				},
				[]byte{42},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			decoded, err := Decode(tt.encoded)
			if err != nil {
				t.Fatalf("Decode(% x): unexpected error: %v", tt.encoded, err)
			}
			if !reflect.DeepEqual(decoded, tt.want) {
				t.Errorf("round-trip list: got %#v, want %#v", decoded, tt.want)
			}
		})
	}
}

// TestDecodeNestingDepth verifies that Decode rejects input nested
// deeper than MaxNestingDepth. nested(k) wraps an empty list in k
// enclosing lists via EncodeList, placing the innermost 0xc0 at
// depth k. Deeply nested lists are the classic stack-exhaustion
// vector against recursive RLP decoders.
//
// Vector: nesting DoS — cf. go-ethereum rlp recursion hardening.
func TestDecodeNestingDepth(t *testing.T) {
	nested := func(k int) []byte {
		b := []byte{0xc0}
		for i := 0; i < k; i++ {
			b = EncodeList(b)
		}
		return b
	}

	tests := []struct {
		name    string
		input   []byte
		wantErr error
	}{
		{
			// Boundary: MaxNestingDepth-1 enclosing lists places the
			// innermost list at depth MaxNestingDepth-1 — allowed.
			name:    "at limit",
			input:   nested(MaxNestingDepth - 1),
			wantErr: nil,
		},
		{
			// Boundary: MaxNestingDepth enclosing lists places the
			// innermost list at depth MaxNestingDepth — rejected.
			name:    "over limit",
			input:   nested(MaxNestingDepth),
			wantErr: ErrNestingLimit,
		},
		{
			// Far over the limit — the attack shape that previously
			// recursed until the goroutine stack was exhausted.
			name:    "far over limit",
			input:   nested(10 * MaxNestingDepth),
			wantErr: ErrNestingLimit,
		},
		{
			// Negative: a list nested at the limit inside a byte string
			// sibling is still rejected wherever it sits.
			name:    "nested deep in mixed list",
			input:   EncodeList(EncodeBytes([]byte("x")), nested(MaxNestingDepth-1)),
			wantErr: ErrNestingLimit,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Decode(tt.input)
			if tt.wantErr == nil {
				if err != nil {
					t.Fatalf("Decode(%d bytes): got error %v, want nil", len(tt.input), err)
				}
				return
			}
			if err == nil {
				t.Fatalf("Decode(%d bytes): got nil error, want %v", len(tt.input), tt.wantErr)
			}
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("Decode(%d bytes): error = %v, want errors.Is %v", len(tt.input), err, tt.wantErr)
			}
		})
	}
}

// TestDecodeInputTooLarge verifies that Decode rejects input larger
// than MaxInputLen before attempting to parse it, and that an input at
// exactly the limit is parsed normally.
func TestDecodeInputTooLarge(t *testing.T) {
	tests := []struct {
		name    string
		input   []byte
		wantErr error
		notErr  error // must NOT match this error
	}{
		{
			// Boundary: one byte over the limit is rejected outright.
			name:    "one byte over limit",
			input:   make([]byte, MaxInputLen+1),
			wantErr: ErrInputTooLarge,
		},
		{
			// Negative: a large encoding that claims a huge payload is
			// also rejected by the input bound.
			name:    "oversized input with list prefix",
			input:   append([]byte{0xff, 0xff, 0xff, 0xff}, make([]byte, MaxInputLen)...),
			wantErr: ErrInputTooLarge,
		},
		{
			// Boundary: exactly MaxInputLen bytes is parsed — the size
			// check must not fire. A leading 0x00 single-byte item then
			// leaves trailing bytes, so the outcome is ErrTrailingBytes,
			// not ErrInputTooLarge.
			name:    "at limit",
			input:   make([]byte, MaxInputLen),
			wantErr: ErrTrailingBytes,
			notErr:  ErrInputTooLarge,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Decode(tt.input)
			if err == nil {
				t.Fatalf("Decode(%d bytes): got nil error, want %v", len(tt.input), tt.wantErr)
			}
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("Decode(%d bytes): error = %v, want errors.Is %v", len(tt.input), err, tt.wantErr)
			}
			if tt.notErr != nil && errors.Is(err, tt.notErr) {
				t.Fatalf("Decode(%d bytes): error = %v, must not match %v", len(tt.input), err, tt.notErr)
			}
		})
	}
}

// TestDeterminism verifies that the same input always produces the same
// encoding (RLP is a deterministic format).
func TestDeterminism(t *testing.T) {
	input := []byte("deterministic encoding test")
	first := EncodeBytes(input)
	for i := 0; i < 10; i++ {
		got := EncodeBytes(input)
		if !bytes.Equal(got, first) {
			t.Fatalf("non-deterministic: run %d got % x, want % x", i, got, first)
		}
	}
}
