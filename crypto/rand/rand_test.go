package rand

import (
	"crypto/subtle"
	"errors"
	"io"
	"testing"
)

// TestBytes covers the deterministic input/output contract of Bytes:
// length, error semantics, and non-nil returns. Table-driven per the
// AGENTS testing rules.
func TestBytes(t *testing.T) {
	cases := []struct {
		name    string
		n       int
		wantErr error
		wantLen int
	}{
		{"zero returns empty slice", 0, nil, 0},
		{"one byte", 1, nil, 1},
		{"32 bytes", 32, nil, 32},
		{"64KB large request", 65536, nil, 65536},
		{"negative returns ErrNegativeLength", -1, ErrNegativeLength, 0},
		{"negative one hundred", -100, ErrNegativeLength, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out, err := Bytes(tc.n)
			if tc.wantErr != nil {
				if err == nil {
					t.Fatalf("Bytes(%d) returned nil error, want %v", tc.n, tc.wantErr)
				}
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("Bytes(%d) error = %v, want %v", tc.n, err, tc.wantErr)
				}
				if out != nil {
					t.Errorf("Bytes(%d) returned %v on error, want nil", tc.n, out)
				}
				return
			}
			if err != nil {
				t.Fatalf("Bytes(%d) error: %v", tc.n, err)
			}
			if len(out) != tc.wantLen {
				t.Errorf("Bytes(%d) length = %d, want %d", tc.n, len(out), tc.wantLen)
			}
			if out == nil {
				t.Errorf("Bytes(%d) returned nil, want non-nil slice", tc.n)
			}
		})
	}
}

// TestBytesProperties covers stochastic properties of the CSPRNG that
// cannot be expressed as deterministic table cases.
func TestBytesProperties(t *testing.T) {
	t.Run("non-zero output", func(t *testing.T) {
		out, err := Bytes(32)
		if err != nil {
			t.Fatalf("Bytes(32) error: %v", err)
		}
		if subtle.ConstantTimeCompare(out, make([]byte, 32)) == 1 {
			t.Fatal("Bytes(32) returned all zeros — entropy source may be broken")
		}
	})

	t.Run("two calls differ", func(t *testing.T) {
		a, err := Bytes(32)
		if err != nil {
			t.Fatalf("first Bytes(32) error: %v", err)
		}
		b, err := Bytes(32)
		if err != nil {
			t.Fatalf("second Bytes(32) error: %v", err)
		}
		if subtle.ConstantTimeCompare(a, b) == 1 {
			t.Fatal("two Bytes(32) calls produced identical output")
		}
	})

	t.Run("no duplicates in 1000 calls", func(t *testing.T) {
		seen := make(map[[32]byte]bool, 1000)
		for i := 0; i < 1000; i++ {
			out, err := Bytes(32)
			if err != nil {
				t.Fatalf("Bytes(32) iteration %d error: %v", i, err)
			}
			var key [32]byte
			copy(key[:], out)
			if seen[key] {
				t.Fatalf("duplicate output at iteration %d — CSPRNG may be repeating", i)
			}
			seen[key] = true
		}
	})
}

// TestReader covers the exported Reader re-export.
func TestReader(t *testing.T) {
	t.Run("produces non-zero output", func(t *testing.T) {
		a := make([]byte, 32)
		if _, err := io.ReadFull(Reader, a); err != nil {
			t.Fatalf("io.ReadFull(Reader) error: %v", err)
		}
		if subtle.ConstantTimeCompare(a, make([]byte, 32)) == 1 {
			t.Fatal("Reader produced all zeros — entropy source may be broken")
		}
	})

	t.Run("two reads differ", func(t *testing.T) {
		a := make([]byte, 32)
		if _, err := io.ReadFull(Reader, a); err != nil {
			t.Fatalf("first io.ReadFull(Reader) error: %v", err)
		}
		b := make([]byte, 32)
		if _, err := io.ReadFull(Reader, b); err != nil {
			t.Fatalf("second io.ReadFull(Reader) error: %v", err)
		}
		if subtle.ConstantTimeCompare(a, b) == 1 {
			t.Fatal("two Reader reads produced identical output")
		}
	})

	t.Run("Bytes and Reader draw from same live pool", func(t *testing.T) {
		fromFunc, err := Bytes(32)
		if err != nil {
			t.Fatalf("Bytes(32) error: %v", err)
		}
		fromReader := make([]byte, 32)
		if _, err := io.ReadFull(Reader, fromReader); err != nil {
			t.Fatalf("io.ReadFull(Reader) error: %v", err)
		}
		if subtle.ConstantTimeCompare(fromFunc, fromReader) == 1 {
			t.Fatal("Bytes and Reader returned identical output — possible shared buffer")
		}
	})
}
