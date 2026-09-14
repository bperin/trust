package hash

import (
	"crypto/subtle"
	"encoding/hex"
	"strings"
	"testing"
)

// Test vectors: known Keccak-256 digests (original Keccak padding, 0x01).
// These differ from SHA-3-256 (FIPS 202 padding, 0x06).
// Reference: https://eips.ethereum.org/EIPS/eip-191

func TestKeccak256_KnownVectors(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "empty string",
			input: "",
			want:  "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470",
		},
		{
			name:  "abc",
			input: "abc",
			want:  "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45",
		},
		{
			name:  "testing",
			input: "testing",
			want:  "5f16f4c7f149ac4f9510d9cf8cf384038ad348b3bcdc01915f95de12df9d1b02",
		},
	}

	h := NewKeccak256()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := h.Sum([]byte(tt.input))
			wantBytes, err := hex.DecodeString(tt.want)
			if err != nil {
				t.Fatalf("invalid test vector hex: %v", err)
			}
			if len(wantBytes) != 32 {
				t.Fatalf("invalid test vector length %d, want 32", len(wantBytes))
			}
			var want [32]byte
			copy(want[:], wantBytes)

			if subtle.ConstantTimeCompare(got[:], want[:]) != 1 {
				t.Errorf("Keccak256(%q) = %x, want %s", tt.name, got, tt.want)
			}
		})
	}
}

func TestKeccak256_NilAndEmpty(t *testing.T) {
	h := NewKeccak256()

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
			if subtle.ConstantTimeCompare(got[:], make([]byte, 32)) == 1 {
				t.Error("digest is all zeros")
			}
		})
	}

	if len(digests) == 2 {
		if subtle.ConstantTimeCompare(digests[0][:], digests[1][:]) != 1 {
			t.Error("Keccak256(nil) != Keccak256(empty), expected equal")
		}
	}
}

func TestKeccak256_NotSHA3(t *testing.T) {
	// Keccak-256 and SHA-3-256 must produce different digests for the same
	// input because they use different padding (0x01 vs 0x06).
	kec := NewKeccak256()
	sha3 := NewSHA3_256()

	input := []byte("abc")
	k := kec.Sum(input)
	s := sha3.Sum(input)

	if subtle.ConstantTimeCompare(k[:], s[:]) == 1 {
		t.Fatal("Keccak256(abc) == SHA3_256(abc) — padding difference not reflected")
	}
}

func TestKeccak256_NegativeMatch(t *testing.T) {
	h := NewKeccak256()
	correct := h.Sum([]byte("abc"))
	wrong := h.Sum([]byte("abd"))

	if subtle.ConstantTimeCompare(correct[:], wrong[:]) == 1 {
		t.Error("Keccak256(abc) == Keccak256(abd) — different inputs produced same digest")
	}
}

func TestKeccak256_SumBytesMatchesSum(t *testing.T) {
	h := NewKeccak256()

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
				t.Errorf("Sum and SumBytes differ for %s", tt.name)
			}
		})
	}
}

func TestKeccak256_Deterministic(t *testing.T) {
	h := NewKeccak256()

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
				t.Error("Keccak256 is not deterministic for same input")
			}
		})
	}
}

func TestKeccak256_LargeInput(t *testing.T) {
	// Boundary test: 1MB input must succeed and produce a non-zero digest.
	// Exercises multi-block absorption across the rate boundary.
	h := NewKeccak256()
	data := []byte(strings.Repeat("a", 1<<20)) // 1 MiB

	digest := h.Sum(data)

	if subtle.ConstantTimeCompare(digest[:], make([]byte, 32)) == 1 {
		t.Fatal("Keccak256(1MB) produced an all-zero digest")
	}

	// Determinism check on the large input.
	again := h.Sum(data)
	if subtle.ConstantTimeCompare(digest[:], again[:]) != 1 {
		t.Error("Keccak256(1MB) is not deterministic")
	}
}
