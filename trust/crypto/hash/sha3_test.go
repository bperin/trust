package hash

import (
	"crypto/subtle"
	"encoding/hex"
	"strings"
	"testing"
)

// Test vectors from NIST FIPS 202 Appendix A.1.
// Source: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf

func TestSHA3_256_NISTVectors(t *testing.T) {
	// Vector: [FIPS 202] Appendix A.1
	tests := []struct {
		name  string
		input string
		want  string // hex-encoded expected digest
	}{
		{
			name:  "empty string",
			input: "",
			want:  "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a",
		},
		{
			name:  "abc",
			input: "abc",
			want:  "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532",
		},
		{
			name:  "two-block message",
			input: "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
			want:  "41c0dba2a9d6240849100376a8235e2c82e1b9998a999e21db32dd97496d3376",
		},
		{
			name:  "one million 'a' characters",
			input: strings.Repeat("a", 1000000),
			want:  "5c8875ae474a3634ba4fd55ec85bffd661f32aca75c6d699d0cdcb6c115891c1",
		},
	}

	h := NewSHA3_256()

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

			// Constant-time comparison per AGENTS.md security rules.
			if subtle.ConstantTimeCompare(got[:], want[:]) != 1 {
				t.Errorf("SHA3-256(%q) = %x, want %s", tt.name, got, tt.want)
			}
		})
	}
}

func TestSHA3_256_NilAndEmpty(t *testing.T) {
	// Nil input should produce the same digest as empty input, not panic.
	h := NewSHA3_256()

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
			t.Error("SHA3-256(nil) != SHA3-256(empty), expected equal")
		}
	}
}

func TestSHA3_256_NegativeMatch(t *testing.T) {
	// A correct digest must not match a wrong digest.
	h := NewSHA3_256()
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

func TestSHA3_256_SumBytesMatchesSum(t *testing.T) {
	h := NewSHA3_256()

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

func TestSHA3_256_Deterministic(t *testing.T) {
	h := NewSHA3_256()

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
				t.Error("SHA3-256 is not deterministic for same input")
			}
		})
	}
}
