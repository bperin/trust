package x25519

import (
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
)

// Test vectors from RFC 7748 §6.1.
// Source: https://www.rfc-editor.org/rfc/rfc7748

func TestRFC7748_Vector1(t *testing.T) {
	// RFC 7748 §6.1 — X25519 test vector
	alicePrivHex := "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"
	bobPrivHex := "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb"
	wantAlicePub := "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"
	wantBobPub := "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"
	wantShared := "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"

	alicePrivBytes, _ := hex.DecodeString(alicePrivHex)
	bobPrivBytes, _ := hex.DecodeString(bobPrivHex)

	alicePriv, err := NewPrivateKey(alicePrivBytes)
	if err != nil {
		t.Fatalf("NewPrivateKey(alice) error: %v", err)
	}
	bobPriv, err := NewPrivateKey(bobPrivBytes)
	if err != nil {
		t.Fatalf("NewPrivateKey(bob) error: %v", err)
	}

	// Public key derivation
	alicePub := alicePriv.Public()
	wantAlicePubBytes, _ := hex.DecodeString(wantAlicePub)
	alicePubBytes := alicePub.Bytes()
	if subtle.ConstantTimeCompare(alicePubBytes[:], wantAlicePubBytes) != 1 {
		t.Errorf("Alice public = %x, want %s", alicePub.Bytes(), wantAlicePub)
	}

	bobPub := bobPriv.Public()
	wantBobPubBytes, _ := hex.DecodeString(wantBobPub)
	bobPubBytes := bobPub.Bytes()
	if subtle.ConstantTimeCompare(bobPubBytes[:], wantBobPubBytes) != 1 {
		t.Errorf("Bob public = %x, want %s", bobPub.Bytes(), wantBobPub)
	}

	// Shared secret — Alice computes with Bob's public
	shared1, err := alicePriv.SharedSecret(bobPub)
	if err != nil {
		t.Fatalf("Alice SharedSecret error: %v", err)
	}
	wantSharedBytes, _ := hex.DecodeString(wantShared)
	if subtle.ConstantTimeCompare(shared1, wantSharedBytes) != 1 {
		t.Errorf("Alice shared = %x, want %s", shared1, wantShared)
	}

	// Shared secret — Bob computes with Alice's public
	shared2, err := bobPriv.SharedSecret(alicePub)
	if err != nil {
		t.Fatalf("Bob SharedSecret error: %v", err)
	}
	if subtle.ConstantTimeCompare(shared2, wantSharedBytes) != 1 {
		t.Errorf("Bob shared = %x, want %s", shared2, wantShared)
	}

	// Both parties must derive the same shared secret
	if subtle.ConstantTimeCompare(shared1, shared2) != 1 {
		t.Error("Alice and Bob derived different shared secrets")
	}
}

func TestGenerateKey_RoundTrip(t *testing.T) {
	// Generated keypair must produce a valid shared secret
	alicePriv, alicePub, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey error: %v", err)
	}

	bobPriv, bobPub, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey error: %v", err)
	}

	shared1, err := alicePriv.SharedSecret(bobPub)
	if err != nil {
		t.Fatalf("Alice SharedSecret error: %v", err)
	}
	shared2, err := bobPriv.SharedSecret(alicePub)
	if err != nil {
		t.Fatalf("Bob SharedSecret error: %v", err)
	}

	if subtle.ConstantTimeCompare(shared1, shared2) != 1 {
		t.Error("generated keypair shared secrets don't match")
	}
}

func TestNewPrivateKey_InvalidLength(t *testing.T) {
	tests := []struct {
		name string
		key  []byte
	}{
		{"nil", nil},
		{"empty", []byte{}},
		{"too short", make([]byte, 31)},
		{"too long", make([]byte, 33)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewPrivateKey(tt.key)
			if err == nil {
				t.Error("expected error, got nil")
			}
			if !errors.Is(err, ErrInvalidKey) {
				t.Errorf("error = %v, want ErrInvalidKey", err)
			}
		})
	}
}

func TestNewPublicKey_InvalidLength(t *testing.T) {
	tests := []struct {
		name string
		key  []byte
	}{
		{"nil", nil},
		{"empty", []byte{}},
		{"too short", make([]byte, 31)},
		{"too long", make([]byte, 33)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewPublicKey(tt.key)
			if err == nil {
				t.Error("expected error, got nil")
			}
			if !errors.Is(err, ErrInvalidKey) {
				t.Errorf("error = %v, want ErrInvalidKey", err)
			}
		})
	}
}

func TestPrivateKey_Redact(t *testing.T) {
	priv, _, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey error: %v", err)
	}

	redacted := priv.Redact()

	// Must not contain the full key
	fullHex := hex.EncodeToString(priv.key[:])
	if strings.Contains(redacted, fullHex) {
		t.Fatal("Redact() exposes full key material")
	}

	// Must not contain any raw key byte as a hex pair — no raw key
	// material may appear in the redacted output.
	for i := 0; i < 32; i++ {
		byteHex := hex.EncodeToString(priv.key[i : i+1])
		if strings.Contains(redacted, byteHex) {
			// A single-byte match could be coincidental in a hash
			// prefix, so only flag 2+ consecutive raw key bytes.
			if i+1 < 32 {
				pairHex := hex.EncodeToString(priv.key[i : i+2])
				if strings.Contains(redacted, pairHex) {
					t.Fatalf("Redact() exposes raw key bytes at offset %d: %q in %q", i, pairHex, redacted)
				}
			}
		}
	}

	// Must end with "..."
	if !strings.HasSuffix(redacted, "...") {
		t.Errorf("Redact() = %q, want suffix '...'", redacted)
	}

	// Must be short (8 hex chars + 3 dots = 11 chars)
	if len(redacted) > 11 {
		t.Errorf("Redact() = %q, length %d, want <= 11", redacted, len(redacted))
	}

	// Must be deterministic — same key yields same fingerprint
	if priv.Redact() != redacted {
		t.Error("Redact() is not deterministic")
	}
}

func TestPublicKey_Equal(t *testing.T) {
	_, pub1, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey error: %v", err)
	}
	_, pub2, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey error: %v", err)
	}

	if !pub1.Equal(pub1) {
		t.Error("public key not equal to itself")
	}
	if pub1.Equal(pub2) {
		t.Error("different public keys reported equal")
	}
}

func TestPublicKey_Redact(t *testing.T) {
	_, pub, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey error: %v", err)
	}

	redacted := pub.Redact()
	if !strings.HasSuffix(redacted, "...") {
		t.Errorf("Redact() = %q, want suffix '...'", redacted)
	}
}

func TestSharedSecret_WrongPeer(t *testing.T) {
	// A wrong peer public key must produce a different shared secret
	// (not an error — just a different value).
	alicePriv, _, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey(alice) error: %v", err)
	}

	_, bobPub, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey(bob) error: %v", err)
	}

	_, evePub, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey(eve) error: %v", err)
	}

	sharedWithBob, err := alicePriv.SharedSecret(bobPub)
	if err != nil {
		t.Fatalf("SharedSecret(bob) error: %v", err)
	}
	sharedWithEve, err := alicePriv.SharedSecret(evePub)
	if err != nil {
		t.Fatalf("SharedSecret(eve) error: %v", err)
	}

	if subtle.ConstantTimeCompare(sharedWithBob, sharedWithEve) == 1 {
		t.Fatal("shared secret with wrong peer matches — keys are not independent")
	}
}

func TestSharedSecret_NilPeer(t *testing.T) {
	priv, _, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey error: %v", err)
	}

	_, err = priv.SharedSecret(nil)
	if err == nil {
		t.Fatal("SharedSecret(nil) expected error, got nil")
	}
	if !errors.Is(err, ErrInvalidKey) {
		t.Errorf("SharedSecret(nil) error = %v, want ErrInvalidKey", err)
	}
}

func TestSharedSecret_LowOrderPoint(t *testing.T) {
	// RFC 7748 §6: implementations MUST reject an all-zero shared
	// secret, which results from a low-order peer point. The all-zero
	// public key is the canonical low-order point. Wycheproof tests
	// this as an invalid-curve / small-subgroup edge case.
	priv, _, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey error: %v", err)
	}

	zeroPub, err := NewPublicKey(make([]byte, 32))
	if err != nil {
		t.Fatalf("NewPublicKey(zero) error: %v", err)
	}

	shared, err := priv.SharedSecret(zeroPub)
	if err == nil {
		t.Fatalf("SharedSecret(low-order point) expected error, got secret %x", shared)
	}
}

func TestPublicKey_Equal_Nil(t *testing.T) {
	_, pub, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey error: %v", err)
	}

	if pub.Equal(nil) {
		t.Fatal("Equal(nil) returned true, want false")
	}
}
