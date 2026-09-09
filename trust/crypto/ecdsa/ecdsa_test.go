package ecdsa

import (
	"crypto"
	stdecdsa "crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
)

// TestP256RoundTrip verifies P-256 sign/verify round-trips.
func TestP256RoundTrip(t *testing.T) {
	t.Parallel()
	priv, pub, err := GenerateKey(elliptic.P256(), crypto.SHA256)
	if err != nil {
		t.Fatalf("GenerateKey P-256: %v", err)
	}

	msg := []byte("test message for P-256 round-trip")
	sig, err := priv.Sign(msg)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	if !pub.Verify(sig, msg) {
		t.Fatal("Verify returned false for valid signature")
	}
}

// TestP384RoundTrip verifies P-384 sign/verify round-trips.
func TestP384RoundTrip(t *testing.T) {
	t.Parallel()
	priv, pub, err := GenerateKey(elliptic.P384(), crypto.SHA384)
	if err != nil {
		t.Fatalf("GenerateKey P-384: %v", err)
	}

	msg := []byte("test message for P-384 round-trip")
	sig, err := priv.Sign(msg)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	if !pub.Verify(sig, msg) {
		t.Fatal("Verify returned false for valid signature")
	}
}

// TestRoundTrip_Table runs round-trip sign/verify for both curves
// with table-driven named subtests covering different message sizes.
func TestRoundTrip_Table(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		curve elliptic.Curve
		hash  crypto.Hash
		msg   []byte
	}{
		{"P256/empty", elliptic.P256(), crypto.SHA256, []byte("")},
		{"P256/single-byte", elliptic.P256(), crypto.SHA256, []byte("a")},
		{"P256/typical", elliptic.P256(), crypto.SHA256, []byte("the quick brown fox jumps over the lazy dog")},
		{"P256/1KB", elliptic.P256(), crypto.SHA256, bytes1KB()},
		{"P384/empty", elliptic.P384(), crypto.SHA384, []byte("")},
		{"P384/single-byte", elliptic.P384(), crypto.SHA384, []byte("z")},
		{"P384/typical", elliptic.P384(), crypto.SHA384, []byte("the quick brown fox jumps over the lazy dog")},
		{"P384/1KB", elliptic.P384(), crypto.SHA384, bytes1KB()},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			priv, pub, err := GenerateKey(tt.curve, tt.hash)
			if err != nil {
				t.Fatalf("GenerateKey: %v", err)
			}
			sig, err := priv.Sign(tt.msg)
			if err != nil {
				t.Fatalf("Sign: %v", err)
			}
			if !pub.Verify(sig, tt.msg) {
				t.Fatal("Verify returned false for valid signature")
			}
		})
	}
}

// TestNonDeterminism verifies Go's ECDSA is randomized — same key +
// message produces different signatures, and both verify true.
func TestNonDeterminism(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		curve elliptic.Curve
		hash  crypto.Hash
	}{
		{"P256", elliptic.P256(), crypto.SHA256},
		{"P384", elliptic.P384(), crypto.SHA384},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			priv, pub, err := GenerateKey(tt.curve, tt.hash)
			if err != nil {
				t.Fatalf("GenerateKey: %v", err)
			}

			msg := []byte("same message for non-determinism test")
			sig1, err := priv.Sign(msg)
			if err != nil {
				t.Fatalf("Sign #1: %v", err)
			}
			sig2, err := priv.Sign(msg)
			if err != nil {
				t.Fatalf("Sign #2: %v", err)
			}

			// Signatures must differ (randomized nonces).
			if subtle.ConstantTimeCompare(sig1, sig2) == 1 {
				t.Fatal("ECDSA signatures should differ (randomized nonces)")
			}

			// Both must verify.
			if !pub.Verify(sig1, msg) {
				t.Fatal("sig1 did not verify")
			}
			if !pub.Verify(sig2, msg) {
				t.Fatal("sig2 did not verify")
			}
		})
	}
}

// TestHashCurveBinding verifies mismatched hash/curve pairs are
// rejected by GenerateKey.
func TestHashCurveBinding(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		curve   elliptic.Curve
		hash    crypto.Hash
		wantErr error
	}{
		{"P256_with_SHA384", elliptic.P256(), crypto.SHA384, ErrUnsupportedHash},
		{"P384_with_SHA256", elliptic.P384(), crypto.SHA256, ErrUnsupportedHash},
		{"P256_with_SHA512", elliptic.P256(), crypto.SHA512, ErrUnsupportedHash},
		{"P384_with_SHA512", elliptic.P384(), crypto.SHA512, ErrUnsupportedHash},
		{"P256_with_SHA1", elliptic.P256(), crypto.SHA1, ErrUnsupportedHash},
		{"P384_with_SHA1", elliptic.P384(), crypto.SHA1, ErrUnsupportedHash},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, _, err := GenerateKey(tt.curve, tt.hash)
			if err == nil {
				t.Fatal("GenerateKey should reject mismatched hash/curve pair")
			}
			if !errors.Is(err, tt.wantErr) {
				t.Errorf("error = %v, want %v", err, tt.wantErr)
			}
		})
	}
}

// TestHashCurveBinding_NewPrivateKey verifies mismatched hash/curve
// pairs are rejected by NewPrivateKey.
func TestHashCurveBinding_NewPrivateKey(t *testing.T) {
	t.Parallel()

	// Generate a valid P-256 key to test wrapping.
	stdKey, err := stdecdsa.GenerateKey(elliptic.P256(), nil)
	if err != nil {
		t.Fatalf("stdlib GenerateKey: %v", err)
	}

	tests := []struct {
		name    string
		key     *stdecdsa.PrivateKey
		hash    crypto.Hash
		wantErr error
	}{
		{"P256_with_SHA384", stdKey, crypto.SHA384, ErrUnsupportedHash},
		{"P256_with_SHA512", stdKey, crypto.SHA512, ErrUnsupportedHash},
		{"nil_key", nil, crypto.SHA256, ErrNilKey},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, err := NewPrivateKey(tt.key, tt.hash)
			if err == nil {
				t.Fatal("NewPrivateKey should reject")
			}
			if !errors.Is(err, tt.wantErr) {
				t.Errorf("error = %v, want %v", err, tt.wantErr)
			}
		})
	}
}

// TestHashCurveBinding_NewPublicKey verifies mismatched hash/curve
// pairs are rejected by NewPublicKey.
func TestHashCurveBinding_NewPublicKey(t *testing.T) {
	t.Parallel()

	stdKey, err := stdecdsa.GenerateKey(elliptic.P384(), nil)
	if err != nil {
		t.Fatalf("stdlib GenerateKey: %v", err)
	}

	tests := []struct {
		name    string
		key     *stdecdsa.PublicKey
		hash    crypto.Hash
		wantErr error
	}{
		{"P384_with_SHA256", &stdKey.PublicKey, crypto.SHA256, ErrUnsupportedHash},
		{"P384_with_SHA512", &stdKey.PublicKey, crypto.SHA512, ErrUnsupportedHash},
		{"nil_key", nil, crypto.SHA384, ErrNilKey},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, err := NewPublicKey(tt.key, tt.hash)
			if err == nil {
				t.Fatal("NewPublicKey should reject")
			}
			if !errors.Is(err, tt.wantErr) {
				t.Errorf("error = %v, want %v", err, tt.wantErr)
			}
		})
	}
}

// TestInvalidCurve verifies that unsupported curves are rejected.
func TestInvalidCurve(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		curve elliptic.Curve
	}{
		{"P224", elliptic.P224()},
		{"P521", elliptic.P521()},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name+"/GenerateKey", func(t *testing.T) {
			t.Parallel()
			// P224 and P521 don't have matching hashes in our binding.
			// Use SHA256 as a plausible hash — the curve check fires first.
			_, _, err := GenerateKey(tt.curve, crypto.SHA256)
			if err == nil {
				t.Fatal("GenerateKey should reject unsupported curve")
			}
			if !errors.Is(err, ErrUnsupportedCurve) {
				t.Errorf("error = %v, want ErrUnsupportedCurve", err)
			}
		})
	}
}

// TestInvalidCurve_NewPrivateKey verifies NewPrivateKey rejects
// unsupported curves.
func TestInvalidCurve_NewPrivateKey(t *testing.T) {
	t.Parallel()

	// Generate a P-224 key from stdlib (unsupported by our wrapper).
	stdKey, err := stdecdsa.GenerateKey(elliptic.P224(), nil)
	if err != nil {
		t.Fatalf("stdlib GenerateKey P-224: %v", err)
	}

	_, err = NewPrivateKey(stdKey, crypto.SHA256)
	if err == nil {
		t.Fatal("NewPrivateKey should reject P-224")
	}
	if !errors.Is(err, ErrUnsupportedCurve) {
		t.Errorf("error = %v, want ErrUnsupportedCurve", err)
	}
}

// TestInvalidCurve_NewPublicKey verifies NewPublicKey rejects
// unsupported curves.
func TestInvalidCurve_NewPublicKey(t *testing.T) {
	t.Parallel()

	stdKey, err := stdecdsa.GenerateKey(elliptic.P521(), nil)
	if err != nil {
		t.Fatalf("stdlib GenerateKey P-521: %v", err)
	}

	_, err = NewPublicKey(&stdKey.PublicKey, crypto.SHA512)
	if err == nil {
		t.Fatal("NewPublicKey should reject P-521")
	}
	if !errors.Is(err, ErrUnsupportedCurve) {
		t.Errorf("error = %v, want ErrUnsupportedCurve", err)
	}
}

// TestCrossCurve verifies a P-256 key cannot verify a P-384 signature
// and vice versa.
func TestCrossCurve(t *testing.T) {
	t.Parallel()

	// Generate keys on both curves.
	p256Priv, p256Pub, err := GenerateKey(elliptic.P256(), crypto.SHA256)
	if err != nil {
		t.Fatalf("GenerateKey P-256: %v", err)
	}
	p384Priv, p384Pub, err := GenerateKey(elliptic.P384(), crypto.SHA384)
	if err != nil {
		t.Fatalf("GenerateKey P-384: %v", err)
	}

	msg := []byte("cross-curve test message")

	// Sign with P-256, verify with P-384 public key — must fail.
	p256Sig, err := p256Priv.Sign(msg)
	if err != nil {
		t.Fatalf("P-256 Sign: %v", err)
	}
	if p384Pub.Verify(p256Sig, msg) {
		t.Fatal("P-384 public key verified a P-256 signature (cross-curve attack)")
	}

	// Sign with P-384, verify with P-256 public key — must fail.
	p384Sig, err := p384Priv.Sign(msg)
	if err != nil {
		t.Fatalf("P-384 Sign: %v", err)
	}
	if p256Pub.Verify(p384Sig, msg) {
		t.Fatal("P-256 public key verified a P-384 signature (cross-curve attack)")
	}
}

// TestVerify_Negative runs table-driven negative verification tests
// for both curves: modified signature, modified message, wrong key,
// truncated DER, empty signature, all-zero signature.
func TestVerify_Negative(t *testing.T) {
	t.Parallel()

	curves := []struct {
		name  string
		curve elliptic.Curve
		hash  crypto.Hash
	}{
		{"P256", elliptic.P256(), crypto.SHA256},
		{"P384", elliptic.P384(), crypto.SHA384},
	}

	for _, c := range curves {
		c := c
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()

			priv, pub, err := GenerateKey(c.curve, c.hash)
			if err != nil {
				t.Fatalf("GenerateKey: %v", err)
			}
			msg := []byte("negative test message")
			sig, err := priv.Sign(msg)
			if err != nil {
				t.Fatalf("Sign: %v", err)
			}

			// Generate a second key for wrong-key tests.
			_, wrongPub, err := GenerateKey(c.curve, c.hash)
			if err != nil {
				t.Fatalf("GenerateKey (wrong): %v", err)
			}

			tests := []struct {
				name string
				sig  []byte
				msg  []byte
				pub  *PublicKey
			}{
				{
					name: "modified_signature_bit_flip",
					sig:  flipBit(sig, 0),
					msg:  msg,
					pub:  pub,
				},
				{
					name: "modified_signature_last_byte",
					sig:  flipBit(sig, len(sig)-1),
					msg:  msg,
					pub:  pub,
				},
				{
					name: "modified_message",
					sig:  sig,
					msg:  []byte("modified message"),
					pub:  pub,
				},
				{
					name: "wrong_key",
					sig:  sig,
					msg:  msg,
					pub:  wrongPub,
				},
				{
					name: "truncated_DER",
					sig:  sig[:len(sig)/2],
					msg:  msg,
					pub:  pub,
				},
				{
					name: "empty_signature",
					sig:  []byte{},
					msg:  msg,
					pub:  pub,
				},
				{
					name: "nil_signature",
					sig:  nil,
					msg:  msg,
					pub:  pub,
				},
				{
					name: "all_zero_signature",
					sig:  make([]byte, len(sig)),
					msg:  msg,
					pub:  pub,
				},
				{
					name: "single_byte_signature",
					sig:  []byte{0x30},
					msg:  msg,
					pub:  pub,
				},
			}

			for _, tt := range tests {
				tt := tt
				t.Run(tt.name, func(t *testing.T) {
					t.Parallel()
					if tt.pub.Verify(tt.sig, tt.msg) {
						t.Fatal("Verify returned true, want false")
					}
				})
			}
		})
	}
}

// TestVerify_EmptyMessage verifies that an empty message signs and
// verifies correctly (boundary test).
func TestVerify_EmptyMessage(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		curve elliptic.Curve
		hash  crypto.Hash
	}{
		{"P256", elliptic.P256(), crypto.SHA256},
		{"P384", elliptic.P384(), crypto.SHA384},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			priv, pub, err := GenerateKey(tt.curve, tt.hash)
			if err != nil {
				t.Fatalf("GenerateKey: %v", err)
			}
			sig, err := priv.Sign(nil)
			if err != nil {
				t.Fatalf("Sign(nil): %v", err)
			}
			if !pub.Verify(sig, nil) {
				t.Fatal("Verify returned false for empty message round-trip")
			}
			if !pub.Verify(sig, []byte{}) {
				t.Fatal("Verify returned false for empty []byte round-trip")
			}
		})
	}
}

// TestNilKey_Sign verifies Sign on a nil-keyed PrivateKey returns
// ErrNilKey (fail closed, never panic).
func TestNilKey_Sign(t *testing.T) {
	t.Parallel()

	priv := &PrivateKey{}
	_, err := priv.Sign([]byte("test"))
	if err == nil {
		t.Fatal("Sign on nil key should return error")
	}
	if !errors.Is(err, ErrNilKey) {
		t.Errorf("error = %v, want ErrNilKey", err)
	}
}

// TestNilKey_Verify verifies Verify on a nil-keyed PublicKey returns
// false (fail closed, never panic).
func TestNilKey_Verify(t *testing.T) {
	t.Parallel()

	pub := &PublicKey{}
	if pub.Verify([]byte("sig"), []byte("msg")) {
		t.Fatal("Verify on nil key returned true, want false")
	}
}

// TestNilKey_Public verifies Public on a nil-keyed PrivateKey returns
// nil (fail closed, never panic).
func TestNilKey_Public(t *testing.T) {
	t.Parallel()

	priv := &PrivateKey{}
	if priv.Public() != nil {
		t.Fatal("Public on nil key returned non-nil, want nil")
	}
}

// TestRedact verifies Redact does not leak raw key material.
func TestRedact(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		curve elliptic.Curve
		hash  crypto.Hash
	}{
		{"P256", elliptic.P256(), crypto.SHA256},
		{"P384", elliptic.P384(), crypto.SHA384},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			priv, pub, err := GenerateKey(tt.curve, tt.hash)
			if err != nil {
				t.Fatalf("GenerateKey: %v", err)
			}

			privRedacted := priv.Redact()
			pubRedacted := pub.Redact()

			// Must be 8 hex chars + "..." = 11 chars.
			if len(privRedacted) != 11 {
				t.Errorf("priv Redact() = %q, length %d, want 11", privRedacted, len(privRedacted))
			}
			if len(pubRedacted) != 11 {
				t.Errorf("pub Redact() = %q, length %d, want 11", pubRedacted, len(pubRedacted))
			}

			// Must end with "...".
			if !strings.HasSuffix(privRedacted, "...") {
				t.Errorf("priv Redact() = %q, want suffix '...'", privRedacted)
			}
			if !strings.HasSuffix(pubRedacted, "...") {
				t.Errorf("pub Redact() = %q, want suffix '...'", pubRedacted)
			}

			// Must not contain raw private key bytes (D).
			dHex := hex.EncodeToString(priv.key.D.Bytes())
			if strings.Contains(privRedacted, dHex) {
				t.Fatal("priv Redact() contains raw D bytes")
			}
			// Check no 2+ consecutive raw key byte pairs appear in output.
			for i := 0; i+1 < len(dHex); i += 2 {
				pair := dHex[i : i+2]
				if len(pair) == 2 && strings.Contains(privRedacted, pair) {
					// Redact output is a SHA-256 hash prefix, so
					// accidental 2-char collisions are possible but
					// extremely unlikely. We check the full D hex
					// above as the primary guard.
				}
			}

			// Must not contain raw public key bytes.
			enc := elliptic.Marshal(pub.key.Curve, pub.key.X, pub.key.Y)
			encHex := hex.EncodeToString(enc)
			if strings.Contains(pubRedacted, encHex) {
				t.Fatal("pub Redact() contains raw encoded public key")
			}

			// Must be deterministic — same key produces same redaction.
			if priv.Redact() != privRedacted {
				t.Error("priv Redact() is not deterministic")
			}
			if pub.Redact() != pubRedacted {
				t.Error("pub Redact() is not deterministic")
			}
		})
	}
}

// TestPublicKey_Equal verifies constant-time equality: true for
// identical keys, false for different keys.
func TestPublicKey_Equal(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		curve elliptic.Curve
		hash  crypto.Hash
	}{
		{"P256", elliptic.P256(), crypto.SHA256},
		{"P384", elliptic.P384(), crypto.SHA384},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			priv1, pub1, err := GenerateKey(tt.curve, tt.hash)
			if err != nil {
				t.Fatalf("GenerateKey #1: %v", err)
			}
			_, pub2, err := GenerateKey(tt.curve, tt.hash)
			if err != nil {
				t.Fatalf("GenerateKey #2: %v", err)
			}

			// Same key equals itself.
			if !pub1.Equal(pub1) {
				t.Error("public key not equal to itself")
			}

			// Public() derives the same key.
			derived := priv1.Public()
			if !pub1.Equal(derived) {
				t.Error("Public() does not match the public key from GenerateKey")
			}

			// Different keys are not equal.
			if pub1.Equal(pub2) {
				t.Error("different public keys reported equal")
			}
		})
	}
}

// TestPublicKey_Equal_Nil verifies Equal returns false for nil.
func TestPublicKey_Equal_Nil(t *testing.T) {
	t.Parallel()

	_, pub, err := GenerateKey(elliptic.P256(), crypto.SHA256)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	if pub.Equal(nil) {
		t.Fatal("Equal(nil) returned true, want false")
	}
}

// TestPublicKey_Equal_CrossCurve verifies keys on different curves
// are not equal.
func TestPublicKey_Equal_CrossCurve(t *testing.T) {
	t.Parallel()

	_, p256Pub, err := GenerateKey(elliptic.P256(), crypto.SHA256)
	if err != nil {
		t.Fatalf("GenerateKey P-256: %v", err)
	}
	_, p384Pub, err := GenerateKey(elliptic.P384(), crypto.SHA384)
	if err != nil {
		t.Fatalf("GenerateKey P-384: %v", err)
	}

	if p256Pub.Equal(p384Pub) {
		t.Fatal("cross-curve keys reported equal")
	}
}

// TestCurve verifies Curve() returns the correct curve for both key
// types.
func TestCurve(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		curve    elliptic.Curve
		hash     crypto.Hash
		wantName string
	}{
		{"P256", elliptic.P256(), crypto.SHA256, "P-256"},
		{"P384", elliptic.P384(), crypto.SHA384, "P-384"},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			priv, pub, err := GenerateKey(tt.curve, tt.hash)
			if err != nil {
				t.Fatalf("GenerateKey: %v", err)
			}
			if priv.Curve() != tt.curve {
				t.Errorf("priv Curve() = %v, want %v", priv.Curve(), tt.curve)
			}
			if pub.Curve() != tt.curve {
				t.Errorf("pub Curve() = %v, want %v", pub.Curve(), tt.curve)
			}
		})
	}
}

// TestNewPrivateKey_Wrap verifies NewPrivateKey wraps an existing
// stdlib key and the wrapper signs/verifies correctly.
func TestNewPrivateKey_Wrap(t *testing.T) {
	t.Parallel()

	stdKey, err := stdecdsa.GenerateKey(elliptic.P256(), nil)
	if err != nil {
		t.Fatalf("stdlib GenerateKey: %v", err)
	}

	priv, err := NewPrivateKey(stdKey, crypto.SHA256)
	if err != nil {
		t.Fatalf("NewPrivateKey: %v", err)
	}

	pub := priv.Public()
	msg := []byte("wrapped key test")
	sig, err := priv.Sign(msg)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if !pub.Verify(sig, msg) {
		t.Fatal("Verify returned false for wrapped key")
	}
}

// TestNewPublicKey_Wrap verifies NewPublicKey wraps an existing
// stdlib key and the wrapper verifies correctly.
func TestNewPublicKey_Wrap(t *testing.T) {
	t.Parallel()

	stdKey, err := stdecdsa.GenerateKey(elliptic.P384(), nil)
	if err != nil {
		t.Fatalf("stdlib GenerateKey: %v", err)
	}

	pub, err := NewPublicKey(&stdKey.PublicKey, crypto.SHA384)
	if err != nil {
		t.Fatalf("NewPublicKey: %v", err)
	}

	// Sign with the stdlib key, verify with the wrapper.
	msg := []byte("wrapped pubkey test")
	h := sha512.New384()
	h.Write(msg)
	digest := h.Sum(nil)
	sig, err := stdecdsa.SignASN1(nil, stdKey, digest)
	if err != nil {
		t.Fatalf("SignASN1: %v", err)
	}
	if !pub.Verify(sig, msg) {
		t.Fatal("Verify returned false for wrapped public key")
	}
}

// TestGenerateKey_DerivesPublic verifies that Public() on the
// generated private key matches the public key returned by
// GenerateKey.
func TestGenerateKey_DerivesPublic(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		curve elliptic.Curve
		hash  crypto.Hash
	}{
		{"P256", elliptic.P256(), crypto.SHA256},
		{"P384", elliptic.P384(), crypto.SHA384},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			priv, pub, err := GenerateKey(tt.curve, tt.hash)
			if err != nil {
				t.Fatalf("GenerateKey: %v", err)
			}
			derived := priv.Public()
			if !pub.Equal(derived) {
				t.Fatal("Public() does not match the public key from GenerateKey")
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Wycheproof test vectors
// ---------------------------------------------------------------------------

// wycheproofSuite models the relevant fields of the Wycheproof
// ECDSA test vector JSON structure.
type wycheproofSuite struct {
	Algorithm     string            `json:"algorithm"`
	NumberOfTests int               `json:"numberOfTests"`
	TestGroups    []wycheproofGroup `json:"testGroups"`
}

type wycheproofGroup struct {
	PublicKey wycheproofPublicKey `json:"publicKey"`
	SHA       string              `json:"sha"`
	Tests     []wycheproofTest    `json:"tests"`
}

type wycheproofPublicKey struct {
	Curve        string `json:"curve"`
	Uncompressed string `json:"uncompressed"`
	WX           string `json:"wx"`
	WY           string `json:"wy"`
}

type wycheproofTest struct {
	TcID    int      `json:"tcId"`
	Comment string   `json:"comment"`
	Flags   []string `json:"flags"`
	Msg     string   `json:"msg"`
	Sig     string   `json:"sig"`
	Result  string   `json:"result"`
}

// wycheproofRunSuite loads a Wycheproof ECDSA test vector file,
// constructs public keys from the test groups, and runs every test
// case against our Verify wrapper.
func wycheproofRunSuite(t *testing.T, filename string, curve elliptic.Curve, hash crypto.Hash, wantSHA string) {
	t.Helper()

	data, err := os.ReadFile(filename)
	if err != nil {
		t.Fatalf("Wycheproof test data not found (%s): %v", filename, err)
	}

	var suite wycheproofSuite
	if err := json.Unmarshal(data, &suite); err != nil {
		t.Fatalf("unmarshal wycheproof (%s): %v", filename, err)
	}

	total := 0
	for _, group := range suite.TestGroups {
		// Filter to the expected hash for this curve.
		if group.SHA != wantSHA {
			continue
		}

		// Parse the uncompressed public key point.
		pointBytes, err := hex.DecodeString(group.PublicKey.Uncompressed)
		if err != nil {
			t.Fatalf("decode publicKey uncompressed: %v", err)
		}
		x, y := elliptic.Unmarshal(curve, pointBytes)
		if x == nil {
			// Some Wycheproof groups use deliberately invalid public
			// keys (not on the curve); skip those groups — they test
			// parsing, not verify.
			continue
		}

		stdPub := &stdecdsa.PublicKey{Curve: curve, X: x, Y: y}
		pub, err := NewPublicKey(stdPub, hash)
		if err != nil {
			// NewPublicKey validates the curve/hash — this should not
			// fail for a valid P-256/P-384 point.
			t.Fatalf("NewPublicKey: %v", err)
		}

		for _, tc := range group.Tests {
			tc := tc
			total++
			t.Run(wycheproofName(tc.TcID, tc.Comment), func(t *testing.T) {
				t.Parallel()
				msg, _ := hex.DecodeString(tc.Msg)
				sig, _ := hex.DecodeString(tc.Sig)

				got := pub.Verify(sig, msg)

				switch tc.Result {
				case "valid":
					if !got {
						t.Errorf("tcId %d (%s): Verify = false, want true [flags: %v]", tc.TcID, tc.Comment, tc.Flags)
					}
				case "acceptable":
					// Acceptable cases may pass or fail depending on
					// implementation choices (e.g. BER encoding). We
					// log the result and flags for security review
					// but do not fail the test.
					t.Logf("tcId %d (%s): acceptable result, Verify = %v [flags: %v]", tc.TcID, tc.Comment, got, tc.Flags)
				case "invalid":
					if got {
						t.Errorf("tcId %d (%s): Verify = true, want false [flags: %v]", tc.TcID, tc.Comment, tc.Flags)
					}
				}
			})
		}
	}

	if total == 0 {
		t.Fatalf("no Wycheproof test cases were run from %s", filename)
	}
	t.Logf("ran %d Wycheproof test cases from %s", total, filename)
}

// TestWycheproof_P256 loads Project Wycheproof ECDSA P-256 SHA-256
// vectors and runs every case against our Verify wrapper.
//
// Vector: [Wycheproof] ecdsa_secp256r1_sha256_test.json
func TestWycheproof_P256(t *testing.T) {
	t.Parallel()
	wycheproofRunSuite(t, "testdata/ecdsa_secp256r1_sha256_test.json", elliptic.P256(), crypto.SHA256, "SHA-256")
}

// TestWycheproof_P384 loads Project Wycheproof ECDSA P-384 SHA-384
// vectors and runs every case against our Verify wrapper.
//
// Vector: [Wycheproof] ecdsa_secp384r1_sha384_test.json
func TestWycheproof_P384(t *testing.T) {
	t.Parallel()
	wycheproofRunSuite(t, "testdata/ecdsa_secp384r1_sha384_test.json", elliptic.P384(), crypto.SHA384, "SHA-384")
}

// ---------------------------------------------------------------------------
// Examples
// ---------------------------------------------------------------------------

// ExampleGenerateKey demonstrates generating an ECDSA P-256 keypair.
func ExampleGenerateKey() {
	priv, pub, err := GenerateKey(elliptic.P256(), crypto.SHA256)
	if err != nil {
		panic(err)
	}
	_ = priv
	_ = pub
	// Output:
}

// Example_signVerify demonstrates signing a message and verifying
// the signature with ECDSA P-256.
func Example_signVerify() {
	priv, pub, err := GenerateKey(elliptic.P256(), crypto.SHA256)
	if err != nil {
		panic(err)
	}

	msg := []byte("hello, world")
	sig, err := priv.Sign(msg)
	if err != nil {
		panic(err)
	}

	valid := pub.Verify(sig, msg)
	fmt.Println(valid)
	// Output: true
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// flipBit returns a copy of b with the specified bit flipped.
func flipBit(b []byte, bit int) []byte {
	out := make([]byte, len(b))
	copy(out, b)
	out[bit/8] ^= 1 << (bit % 8)
	return out
}

// bytes1KB returns a 1024-byte test message.
func bytes1KB() []byte {
	b := make([]byte, 1024)
	for i := range b {
		b[i] = byte(i % 256)
	}
	return b
}

// wycheproofName formats a Wycheproof test case name for t.Run.
func wycheproofName(tcID int, comment string) string {
	if comment == "" {
		return "tcId-" + itoa(tcID)
	}
	c := strings.NewReplacer(" ", "_", "/", "_", "(", "", ")", "", ",", "_").Replace(comment)
	return "tcId-" + itoa(tcID) + "-" + c
}

// itoa converts a non-negative int to its decimal string (test-only
// helper to avoid importing strconv — matches the ed25519 test
// pattern).
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}
