package hkdf

import (
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"testing"
)

// Test vectors from [RFC 5869] Appendix A.
// Source: https://www.rfc-editor.org/rfc/rfc5869

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("invalid hex vector %q: %v", s, err)
	}
	return b
}

func TestDeriveKey_RFC5869(t *testing.T) {
	// Vector: [RFC 5869] Test Case 1, 2, 3
	tests := []struct {
		name    string
		ikm     []byte
		salt    []byte
		info    []byte
		length  int
		wantHex string
	}{
		{
			name:    "Case 1 — basic with SHA-256",
			ikm:     bytesFill(22, 0x0b),
			salt:    []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c},
			info:    []byte{0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9},
			length:  42,
			wantHex: "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865",
		},
		{
			name:    "Case 2 — longer inputs and outputs",
			ikm:     bytesFillCount(80),
			salt:    bytesFillOffset(80, 0x60),
			info:    bytesFillOffset(80, 0xb0),
			length:  82,
			wantHex: "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71cc30c58179ec3e87c14c01d5c1f3434f1d87",
		},
		{
			name:    "Case 3 — zero-length salt and info",
			ikm:     bytesFill(22, 0x0b),
			salt:    nil,
			info:    nil,
			length:  42,
			wantHex: "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			okm, err := DeriveKey(tt.ikm, tt.salt, tt.info, tt.length)
			if err != nil {
				t.Fatalf("DeriveKey error: %v", err)
			}
			want := mustHex(t, tt.wantHex)
			if subtle.ConstantTimeCompare(okm, want) != 1 {
				t.Errorf("OKM = %x, want %s", okm, tt.wantHex)
			}
		})
	}
}

func TestExtract_RFC5869(t *testing.T) {
	// Vector: [RFC 5869] Test Case 1 PRK
	ikm := bytesFill(22, 0x0b)
	salt := []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c}
	wantHex := "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5"

	prk, err := Extract(ikm, salt)
	if err != nil {
		t.Fatalf("Extract error: %v", err)
	}
	want := mustHex(t, wantHex)
	if subtle.ConstantTimeCompare(prk, want) != 1 {
		t.Errorf("PRK = %x, want %s", prk, wantHex)
	}
}

func TestDeriveKey_EqualsExtractThenExpand(t *testing.T) {
	ikm := []byte("input keying material")
	salt := []byte("salt")
	info := []byte("info")

	derived, err := DeriveKey(ikm, salt, info, 64)
	if err != nil {
		t.Fatalf("DeriveKey error: %v", err)
	}

	prk, err := Extract(ikm, salt)
	if err != nil {
		t.Fatalf("Extract error: %v", err)
	}
	expanded, err := Expand(prk, info, 64)
	if err != nil {
		t.Fatalf("Expand error: %v", err)
	}

	if subtle.ConstantTimeCompare(derived, expanded) != 1 {
		t.Error("DeriveKey != Extract+Expand for same inputs")
	}
}

func TestDeriveKey_Deterministic(t *testing.T) {
	ikm := []byte("secret")
	salt := []byte("salt")
	info := []byte("context")

	a, err := DeriveKey(ikm, salt, info, 32)
	if err != nil {
		t.Fatalf("first DeriveKey error: %v", err)
	}
	b, err := DeriveKey(ikm, salt, info, 32)
	if err != nil {
		t.Fatalf("second DeriveKey error: %v", err)
	}

	if subtle.ConstantTimeCompare(a, b) != 1 {
		t.Error("DeriveKey not deterministic for same inputs")
	}
}

func TestDeriveKey_DifferentInfoProducesDifferentKeys(t *testing.T) {
	ikm := []byte("secret")
	salt := []byte("salt")

	a, err := DeriveKey(ikm, salt, []byte("context-a"), 32)
	if err != nil {
		t.Fatalf("first DeriveKey error: %v", err)
	}
	b, err := DeriveKey(ikm, salt, []byte("context-b"), 32)
	if err != nil {
		t.Fatalf("second DeriveKey error: %v", err)
	}

	if subtle.ConstantTimeCompare(a, b) == 1 {
		t.Error("different info produced same key")
	}
}

func TestDeriveKey_NegativeTests(t *testing.T) {
	tests := []struct {
		name   string
		secret []byte
		length int
		want   error
	}{
		{name: "zero length", secret: []byte("secret"), length: 0, want: ErrInvalidLength},
		{name: "negative length", secret: []byte("secret"), length: -1, want: ErrInvalidLength},
		{name: "exceeds max", secret: []byte("secret"), length: MaxExpandLength + 1, want: ErrInvalidLength},
		{name: "nil secret", secret: nil, length: 32, want: ErrEmptySecret},
		{name: "empty secret", secret: []byte{}, length: 32, want: ErrEmptySecret},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := DeriveKey(tt.secret, nil, nil, tt.length)
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if !errors.Is(err, tt.want) {
				t.Errorf("error = %v, want %v", err, tt.want)
			}
		})
	}
}

func TestExtract_NegativeTests(t *testing.T) {
	tests := []struct {
		name   string
		secret []byte
		want   error
	}{
		{name: "nil secret", secret: nil, want: ErrEmptySecret},
		{name: "empty secret", secret: []byte{}, want: ErrEmptySecret},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Extract(tt.secret, nil)
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if !errors.Is(err, tt.want) {
				t.Errorf("error = %v, want %v", err, tt.want)
			}
		})
	}
}

func TestExpand(t *testing.T) {
	// Verify Expand succeeds with a valid PRK of exactly HashLen.
	prk := make([]byte, 32)
	for i := range prk {
		prk[i] = byte(i)
	}

	out, err := Expand(prk, []byte("info"), 32)
	if err != nil {
		t.Fatalf("Expand error: %v", err)
	}
	if len(out) != 32 {
		t.Errorf("output length = %d, want 32", len(out))
	}
}

func TestExpand_NegativeTests(t *testing.T) {
	tests := []struct {
		name   string
		prk    []byte
		length int
		want   error
	}{
		{name: "zero length", prk: make([]byte, 32), length: 0, want: ErrInvalidLength},
		{name: "negative length", prk: make([]byte, 32), length: -1, want: ErrInvalidLength},
		{name: "exceeds max", prk: make([]byte, 32), length: MaxExpandLength + 1, want: ErrInvalidLength},
		{name: "nil prk", prk: nil, length: 32, want: ErrInvalidPRK},
		{name: "empty prk", prk: []byte{}, length: 32, want: ErrInvalidPRK},
		{name: "short prk", prk: make([]byte, 16), length: 32, want: ErrInvalidPRK},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Expand(tt.prk, nil, tt.length)
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if !errors.Is(err, tt.want) {
				t.Errorf("error = %v, want %v", err, tt.want)
			}
		})
	}
}

// bytesFill returns n bytes all set to v.
func bytesFill(n int, v byte) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = v
	}
	return b
}

// bytesFillCount returns n bytes where b[i] = i.
func bytesFillCount(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i)
	}
	return b
}

// bytesFillOffset returns n bytes where b[i] = offset + i.
func bytesFillOffset(n int, offset byte) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = offset + byte(i)
	}
	return b
}
