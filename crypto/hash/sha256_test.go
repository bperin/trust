package hash

import (
	"crypto/subtle"
	"encoding/hex"
	"strings"
	"testing"
)

// Test vectors from NIST FIPS 180-4 Appendix B.1.
// Source: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf

func TestSHA256_NISTVectors(t *testing.T) {
	// Vector: [FIPS 180-4] Appendix B.1
	tests := []struct {
		name  string
		input string
		want  string // hex-encoded expected digest
	}{
		{
			name:  "empty string",
			input: "",
			want:  "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		},
		{
			name:  "abc",
			input: "abc",
			want:  "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
		},
		{
			name:  "two-block message (448 bits)",
			input: "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
			want:  "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
		},
		{
			name:  "one million 'a' characters",
			input: strings.Repeat("a", 1000000),
			want:  "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0",
		},
	}

	h := NewSHA256()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := h.Sum([]byte(tt.input))
			wantBytes, err := hex.DecodeString(tt.want)
			if err != nil {
				t.Fatalf("invalid test vector hex: %v", err)
			}
			var want [32]byte
			copy(want[:], wantBytes)

			// Constant-time comparison per AGENTS.md security rules.
			if subtle.ConstantTimeCompare(got[:], want[:]) != 1 {
				t.Errorf("SHA-256(%q) = %x, want %s", tt.name, got, tt.want)
			}
		})
	}
}

func TestSHA256_NilAndEmpty(t *testing.T) {
	// Nil input should produce the same digest as empty input, not panic.
	h := NewSHA256()

	tests := []struct {
		name  string
		input []byte
	}{
		{name: "nil", input: nil},
		{name: "empty slice", input: []byte{}},
	}

	var digests [][32]byte
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := h.Sum(tt.input)
			digests = append(digests, got)
			// Should not be all zeros.
			if subtle.ConstantTimeCompare(got[:], make([]byte, 32)) == 1 {
				t.Error("digest is all zeros")
			}
		})
	}

	if len(digests) == 2 {
		if subtle.ConstantTimeCompare(digests[0][:], digests[1][:]) != 1 {
			t.Error("SHA-256(nil) != SHA-256(empty), expected equal")
		}
	}
}

func TestSHA256_NegativeMatch(t *testing.T) {
	// A correct digest must not match a wrong digest.
	h := NewSHA256()
	correct := h.Sum([]byte("abc"))
	wrong := h.Sum([]byte("abd"))

	tests := []struct {
		name string
		a    [32]byte
		b    [32]byte
		want int // 1 = match, 0 = no match
	}{
		{name: "same input matches", a: correct, b: correct, want: 1},
		{name: "different input does not match", a: correct, b: wrong, want: 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := subtle.ConstantTimeCompare(tt.a[:], tt.b[:])
			if got != tt.want {
				t.Errorf("ConstantTimeCompare = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestSHA256_SumBytesMatchesSum(t *testing.T) {
	h := NewSHA256()

	tests := []struct {
		name  string
		input []byte
	}{
		{name: "short", input: []byte("test data")},
		{name: "empty", input: []byte{}},
		{name: "nil", input: nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fixed := h.Sum(tt.input)
			slice := h.SumBytes(tt.input)

			if subtle.ConstantTimeCompare(fixed[:], slice) != 1 {
				t.Errorf("Sum and SumBytes produced different digests for %s", tt.name)
			}
		})
	}
}

func TestSHA256_Deterministic(t *testing.T) {
	h := NewSHA256()

	tests := []struct {
		name  string
		input []byte
	}{
		{name: "short", input: []byte("deterministic test")},
		{name: "empty", input: []byte{}},
		{name: "long", input: []byte(strings.Repeat("x", 10000))},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			first := h.Sum(tt.input)
			second := h.Sum(tt.input)

			if subtle.ConstantTimeCompare(first[:], second[:]) != 1 {
				t.Error("SHA-256 is not deterministic for same input")
			}
		})
	}
}
