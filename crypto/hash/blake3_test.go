package hash

import (
	"crypto/subtle"
	"encoding/hex"
	"strings"
	"testing"
)

// Test vectors from the BLAKE3 specification.
// Reference: https://github.com/BLAKE3-team/BLAKE3-specs/blob/master/blake3.pdf

func TestBLAKE3_KnownVectors(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "empty string",
			input: "",
			want:  "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262",
		},
		{
			name:  "abc",
			input: "abc",
			want:  "6437b3ac38465133ffb63b75273a8db548c558465d79db03fd359c6cd5bd9d85",
		},
	}

	h := NewBLAKE3()

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
				t.Errorf("BLAKE3(%q) = %x, want %s", tt.name, got, tt.want)
			}
		})
	}
}

func TestBLAKE3_NilAndEmpty(t *testing.T) {
	h := NewBLAKE3()

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
			t.Error("BLAKE3(nil) != BLAKE3(empty), expected equal")
		}
	}
}

func TestBLAKE3_NegativeMatch(t *testing.T) {
	h := NewBLAKE3()

	tests := []struct {
		name string
		a    []byte
		b    []byte
	}{
		{"abc vs abd", []byte("abc"), []byte("abd")},
		{"empty vs single byte", []byte{}, []byte("x")},
		{"long vs long-1byte", []byte(strings.Repeat("x", 1000)), []byte(strings.Repeat("x", 999) + "y")},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := h.Sum(tt.a)
			b := h.Sum(tt.b)
			if subtle.ConstantTimeCompare(a[:], b[:]) == 1 {
				t.Errorf("BLAKE3(%q) == BLAKE3(%q) — different inputs produced same digest", tt.a, tt.b)
			}
		})
	}
}

func TestBLAKE3_SumBytesMatchesSum(t *testing.T) {
	h := NewBLAKE3()

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

func TestBLAKE3_Deterministic(t *testing.T) {
	h := NewBLAKE3()

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
				t.Error("BLAKE3 is not deterministic for same input")
			}
		})
	}
}

// TestBLAKE3_LargeInput exercises boundary sizes. BLAKE3's built-in
// Merkle tree mode chunks input into 1024-byte chunks, so inputs that
// cross chunk boundaries exercise the multi-node tree path.
func TestBLAKE3_LargeInput(t *testing.T) {
	h := NewBLAKE3()

	tests := []struct {
		name string
		size int
	}{
		{"single byte", 1},
		{"chunk boundary (1024 bytes)", 1024},
		{"1 MB", 1 << 20},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data := make([]byte, tt.size)
			for i := range data {
				data[i] = byte(i)
			}

			fixed := h.Sum(data)
			slice := h.SumBytes(data)

			if subtle.ConstantTimeCompare(fixed[:], slice) != 1 {
				t.Fatalf("Sum and SumBytes disagree on %d-byte input", tt.size)
			}

			// A single-byte change must produce a different digest (avalanche).
			data[len(data)-1] ^= 0x01
			tampered := h.Sum(data)
			if subtle.ConstantTimeCompare(fixed[:], tampered[:]) == 1 {
				t.Fatalf("%d-byte input: tampering last byte did not change digest", tt.size)
			}
		})
	}
}
