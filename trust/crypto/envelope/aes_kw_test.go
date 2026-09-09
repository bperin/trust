package envelope

import (
	"crypto/subtle"
	"encoding/hex"
	"testing"
)

// RFC 3394 §4.1.1 test vector: wrap 128-bit key with 128-bit KEK.
// KEK  = 000102030405060708090A0B0C0D0E0F
// Key  = 00112233445566778899AABBCCDDEEFF
// Wrap = 1FA68B0A8112B447AEF34BD8FB5A7B829D3E862371D2CFE5
func TestRFC3394_4_1_1(t *testing.T) {
	kek, _ := hex.DecodeString("000102030405060708090A0B0C0D0E0F")
	key, _ := hex.DecodeString("00112233445566778899AABBCCDDEEFF")
	want, _ := hex.DecodeString("1FA68B0A8112B447AEF34BD8FB5A7B829D3E862371D2CFE5")

	got, err := Wrap(kek, key)
	if err != nil {
		t.Fatalf("Wrap: %v", err)
	}
	if subtle.ConstantTimeCompare(got, want) != 1 {
		t.Fatalf("got %x, want %x", got, want)
	}

	// Round-trip: unwrap should recover the original key.
	unwrap, err := Unwrap(kek, got)
	if err != nil {
		t.Fatalf("Unwrap: %v", err)
	}
	if subtle.ConstantTimeCompare(unwrap, key) != 1 {
		t.Fatalf("unwrap %x, want %x", unwrap, key)
	}
}

// TestWrapUnwrapRoundTrip verifies Wrap/Unwrap round-trips with a generated KEK.
func TestWrapUnwrapRoundTrip(t *testing.T) {
	kek, err := GenerateKEK()
	if err != nil {
		t.Fatalf("GenerateKEK: %v", err)
	}
	key, err := GenerateKEK()
	if err != nil {
		t.Fatalf("GenerateKEK: %v", err)
	}

	wrapped, err := Wrap(kek, key)
	if err != nil {
		t.Fatalf("Wrap: %v", err)
	}
	unwrap, err := Unwrap(kek, wrapped)
	if err != nil {
		t.Fatalf("Unwrap: %v", err)
	}
	if subtle.ConstantTimeCompare(unwrap, key) != 1 {
		t.Fatal("unwrap != original key")
	}
}

// TestUnwrapWrongKEK verifies a wrong KEK causes ICV mismatch.
func TestUnwrapWrongKEK(t *testing.T) {
	kek, _ := hex.DecodeString("000102030405060708090A0B0C0D0E0F")
	key, _ := hex.DecodeString("00112233445566778899AABBCCDDEEFF")
	wrapped, err := Wrap(kek, key)
	if err != nil {
		t.Fatalf("Wrap: %v", err)
	}

	wrongKEK, _ := hex.DecodeString("FF0102030405060708090A0B0C0D0E0F")
	_, err = Unwrap(wrongKEK, wrapped)
	if err != ErrICVMismatch {
		t.Fatalf("got %v, want ErrICVMismatch", err)
	}
}
