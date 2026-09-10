package rsa

import (
	"crypto"
	cryptorand "crypto/rand"
	stdrsa "crypto/rsa"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Full test suite for the RSA package.
// Covers round-trip, determinism, hash binding, scheme separation,
// negative/boundary tests, redaction, equality, Wycheproof vectors,
// and example functions. See TASK-014 for acceptance criteria.

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// mustGeneratePSS generates a 2048-bit PSS key or fails the test.
func mustGeneratePSS(t *testing.T, hash crypto.Hash) (*PSSPrivateKey, *PSSPublicKey) {
	t.Helper()
	priv, pub, err := GeneratePSSKey(2048, hash)
	if err != nil {
		t.Fatalf("GeneratePSSKey(2048, %v): %v", hash, err)
	}
	return priv, pub
}

// mustGeneratePKCS1 generates a 2048-bit PKCS1v1.5 key or fails the test.
func mustGeneratePKCS1(t *testing.T, hash crypto.Hash) (*PKCS1PrivateKey, *PKCS1PublicKey) {
	t.Helper()
	priv, pub, err := GeneratePKCS1Key(2048, hash)
	if err != nil {
		t.Fatalf("GeneratePKCS1Key(2048, %v): %v", hash, err)
	}
	return priv, pub
}

// supportedHashes returns the hashes this package supports, used by
// table-driven tests that iterate over all three.
var supportedHashes = []struct {
	name string
	hash crypto.Hash
}{
	{"SHA-256", crypto.SHA256},
	{"SHA-384", crypto.SHA384},
	{"SHA-512", crypto.SHA512},
}

// hashOutputLen returns the digest length in bytes for a supported hash.
func hashOutputLen(h crypto.Hash) int {
	switch h {
	case crypto.SHA256:
		return 32
	case crypto.SHA384:
		return 48
	case crypto.SHA512:
		return 64
	default:
		return 0
	}
}

// ---------------------------------------------------------------------------
// Round-trip tests
// ---------------------------------------------------------------------------

// TestPSSRoundTrip verifies PSS sign/verify round-trips with a generated key
// across all supported hashes.
func TestPSSRoundTrip(t *testing.T) {
	t.Parallel()
	for _, tt := range supportedHashes {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			priv, pub := mustGeneratePSS(t, tt.hash)

			msg := []byte("test message for PSS round-trip")
			sig, err := priv.Sign(msg)
			if err != nil {
				t.Fatalf("Sign: %v", err)
			}
			if !pub.Verify(sig, msg) {
				t.Fatal("Verify returned false for valid signature")
			}
		})
	}
}

// TestPKCS1RoundTrip verifies PKCS1v1.5 sign/verify round-trips with a
// generated key across all supported hashes.
func TestPKCS1RoundTrip(t *testing.T) {
	t.Parallel()
	for _, tt := range supportedHashes {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			priv, pub := mustGeneratePKCS1(t, tt.hash)

			msg := []byte("test message for PKCS1 round-trip")
			sig, err := priv.Sign(msg)
			if err != nil {
				t.Fatalf("Sign: %v", err)
			}
			if !pub.Verify(sig, msg) {
				t.Fatal("Verify returned false for valid signature")
			}
		})
	}
}

// TestRoundTrip_EmptyMessage verifies both schemes handle the empty-message
// boundary correctly.
func TestRoundTrip_EmptyMessage(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		scheme string
	}{
		{"PSS/empty", "pss"},
		{"PKCS1/empty", "pkcs1"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			switch tt.scheme {
			case "pss":
				priv, pub := mustGeneratePSS(t, crypto.SHA256)
				sig, err := priv.Sign(nil)
				if err != nil {
					t.Fatalf("Sign(nil): %v", err)
				}
				if !pub.Verify(sig, nil) {
					t.Fatal("Verify returned false for empty message round-trip")
				}
			case "pkcs1":
				priv, pub := mustGeneratePKCS1(t, crypto.SHA256)
				sig, err := priv.Sign(nil)
				if err != nil {
					t.Fatalf("Sign(nil): %v", err)
				}
				if !pub.Verify(sig, nil) {
					t.Fatal("Verify returned false for empty message round-trip")
				}
			}
		})
	}
}

// TestPublicDerivation verifies Public() returns a key that verifies
// signatures from the private key, for both schemes.
func TestPublicDerivation(t *testing.T) {
	t.Parallel()
	t.Run("PSS", func(t *testing.T) {
		t.Parallel()
		priv, _ := mustGeneratePSS(t, crypto.SHA256)
		derived := priv.Public()
		msg := []byte("public derivation test")
		sig, err := priv.Sign(msg)
		if err != nil {
			t.Fatalf("Sign: %v", err)
		}
		if !derived.Verify(sig, msg) {
			t.Fatal("derived public key failed to verify signature")
		}
	})
	t.Run("PKCS1", func(t *testing.T) {
		t.Parallel()
		priv, _ := mustGeneratePKCS1(t, crypto.SHA256)
		derived := priv.Public()
		msg := []byte("public derivation test")
		sig, err := priv.Sign(msg)
		if err != nil {
			t.Fatalf("Sign: %v", err)
		}
		if !derived.Verify(sig, msg) {
			t.Fatal("derived public key failed to verify signature")
		}
	})
}

// ---------------------------------------------------------------------------
// Determinism tests
// ---------------------------------------------------------------------------

// TestPSSNonDeterminism verifies PSS is probabilistic — same key + message
// produces different signatures.
func TestPSSNonDeterminism(t *testing.T) {
	t.Parallel()
	priv, _ := mustGeneratePSS(t, crypto.SHA256)

	msg := []byte("same message")
	sig1, err := priv.Sign(msg)
	if err != nil {
		t.Fatalf("Sign #1: %v", err)
	}
	sig2, err := priv.Sign(msg)
	if err != nil {
		t.Fatalf("Sign #2: %v", err)
	}
	if subtle.ConstantTimeCompare(sig1, sig2) == 1 {
		t.Fatal("PSS signatures should differ (probabilistic)")
	}
}

// TestPKCS1Determinism verifies PKCS1v1.5 is deterministic — same key +
// message produces byte-identical signatures.
func TestPKCS1Determinism(t *testing.T) {
	t.Parallel()
	priv, _ := mustGeneratePKCS1(t, crypto.SHA256)

	msg := []byte("same message")
	sig1, err := priv.Sign(msg)
	if err != nil {
		t.Fatalf("Sign #1: %v", err)
	}
	sig2, err := priv.Sign(msg)
	if err != nil {
		t.Fatalf("Sign #2: %v", err)
	}
	if subtle.ConstantTimeCompare(sig1, sig2) != 1 {
		t.Fatal("PKCS1v1.5 signatures should be identical (deterministic)")
	}
}

// ---------------------------------------------------------------------------
// Hash binding tests
// ---------------------------------------------------------------------------

// TestHashBinding verifies that a key bound to one hash cannot verify a
// signature produced with a different hash.
func TestHashBinding(t *testing.T) {
	t.Parallel()
	t.Run("PSS/SHA256_key_rejects_SHA384_sig", func(t *testing.T) {
		t.Parallel()
		// Sign with SHA-384 key.
		priv384, _ := mustGeneratePSS(t, crypto.SHA384)
		msg := []byte("hash binding test")
		sig384, err := priv384.Sign(msg)
		if err != nil {
			t.Fatalf("Sign with SHA-384: %v", err)
		}
		// Build a SHA-256 public key from the same modulus.
		pub256, err := NewPSSPublicKey(&priv384.key.PublicKey, crypto.SHA256)
		if err != nil {
			t.Fatalf("NewPSSPublicKey with SHA-256: %v", err)
		}
		if pub256.Verify(sig384, msg) {
			t.Fatal("SHA-256 key verified SHA-384 signature, want false")
		}
	})
	t.Run("PKCS1/SHA256_key_rejects_SHA384_sig", func(t *testing.T) {
		t.Parallel()
		priv384, _ := mustGeneratePKCS1(t, crypto.SHA384)
		msg := []byte("hash binding test")
		sig384, err := priv384.Sign(msg)
		if err != nil {
			t.Fatalf("Sign with SHA-384: %v", err)
		}
		pub256, err := NewPKCS1PublicKey(&priv384.key.PublicKey, crypto.SHA256)
		if err != nil {
			t.Fatalf("NewPKCS1PublicKey with SHA-256: %v", err)
		}
		if pub256.Verify(sig384, msg) {
			t.Fatal("SHA-256 key verified SHA-384 signature, want false")
		}
	})
}

// TestHashBinding_SameHashVerifies verifies the positive case: a key
// bound to the same hash that produced the signature verifies it.
func TestHashBinding_SameHashVerifies(t *testing.T) {
	t.Parallel()
	t.Run("PSS", func(t *testing.T) {
		t.Parallel()
		priv, pub := mustGeneratePSS(t, crypto.SHA384)
		msg := []byte("same hash verifies")
		sig, err := priv.Sign(msg)
		if err != nil {
			t.Fatalf("Sign: %v", err)
		}
		if !pub.Verify(sig, msg) {
			t.Fatal("SHA-384 key failed to verify SHA-384 signature")
		}
	})
	t.Run("PKCS1", func(t *testing.T) {
		t.Parallel()
		priv, pub := mustGeneratePKCS1(t, crypto.SHA512)
		msg := []byte("same hash verifies")
		sig, err := priv.Sign(msg)
		if err != nil {
			t.Fatalf("Sign: %v", err)
		}
		if !pub.Verify(sig, msg) {
			t.Fatal("SHA-512 key failed to verify SHA-512 signature")
		}
	})
}

// ---------------------------------------------------------------------------
// Scheme separation tests
// ---------------------------------------------------------------------------

// TestSchemeSeparation verifies that PSS rejects PKCS1v1.5 signatures and
// vice versa — the compiler enforces type separation, and the verify
// functions enforce padding separation.
func TestSchemeSeparation(t *testing.T) {
	t.Parallel()
	t.Run("PSS_rejects_PKCS1_sig", func(t *testing.T) {
		t.Parallel()
		pssPriv, pssPub := mustGeneratePSS(t, crypto.SHA256)
		// Use the PSS private key's modulus for the PKCS1 private key
		// so the signature is valid PKCS1v1.5 for the same modulus.
		pkcs1PrivSame, err := NewPKCS1PrivateKey(pssPriv.key, crypto.SHA256)
		if err != nil {
			t.Fatalf("NewPKCS1PrivateKey: %v", err)
		}
		msg := []byte("scheme separation test")
		pkcs1Sig, err := pkcs1PrivSame.Sign(msg)
		if err != nil {
			t.Fatalf("PKCS1 Sign: %v", err)
		}
		if pssPub.Verify(pkcs1Sig, msg) {
			t.Fatal("PSS public key accepted PKCS1v1.5 signature, want false")
		}
		// Sanity: the PKCS1 sig is valid under the PKCS1 public key
		// derived from the same private key.
		pkcs1PubSame := pkcs1PrivSame.Public()
		if !pkcs1PubSame.Verify(pkcs1Sig, msg) {
			t.Fatal("PKCS1 sig failed verification under PKCS1 public key (sanity)")
		}
	})
	t.Run("PKCS1_rejects_PSS_sig", func(t *testing.T) {
		t.Parallel()
		pkcs1Priv, pkcs1Pub := mustGeneratePKCS1(t, crypto.SHA256)
		// Sign with PSS using the same private key.
		pssPrivSame, err := NewPSSPrivateKey(pkcs1Priv.key, crypto.SHA256)
		if err != nil {
			t.Fatalf("NewPSSPrivateKey: %v", err)
		}
		msg := []byte("scheme separation test")
		pssSig, err := pssPrivSame.Sign(msg)
		if err != nil {
			t.Fatalf("PSS Sign: %v", err)
		}
		if pkcs1Pub.Verify(pssSig, msg) {
			t.Fatal("PKCS1 public key accepted PSS signature, want false")
		}
		// Sanity: the PSS sig is valid under the PSS public key.
		pssPub := pssPrivSame.Public()
		if !pssPub.Verify(pssSig, msg) {
			t.Fatal("PSS sig failed verification under PSS public key (sanity)")
		}
	})
}

// ---------------------------------------------------------------------------
// Negative tests: modified signature, modified message, wrong key
// ---------------------------------------------------------------------------

// TestVerify_RejectsModifiedSignature flips a bit in the signature and
// verifies both schemes reject it.
func TestVerify_RejectsModifiedSignature(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		scheme string
	}{
		{"PSS", "pss"},
		{"PKCS1", "pkcs1"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var sig []byte
			var pub interface {
				Verify(signature, message []byte) bool
			}
			msg := []byte("modified signature test")
			switch tt.scheme {
			case "pss":
				priv, p := mustGeneratePSS(t, crypto.SHA256)
				pub = p
				sig, _ = priv.Sign(msg)
			case "pkcs1":
				priv, p := mustGeneratePKCS1(t, crypto.SHA256)
				pub = p
				sig, _ = priv.Sign(msg)
			}
			tampered := make([]byte, len(sig))
			copy(tampered, sig)
			tampered[0] ^= 0x01
			if pub.Verify(tampered, msg) {
				t.Fatal("Verify returned true for modified signature, want false")
			}
		})
	}
}

// TestVerify_RejectsModifiedMessage verifies both schemes reject a
// signature when the message is changed.
func TestVerify_RejectsModifiedMessage(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		scheme string
	}{
		{"PSS", "pss"},
		{"PKCS1", "pkcs1"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var sig []byte
			var pub interface {
				Verify(signature, message []byte) bool
			}
			msg := []byte("original message")
			switch tt.scheme {
			case "pss":
				priv, p := mustGeneratePSS(t, crypto.SHA256)
				pub = p
				sig, _ = priv.Sign(msg)
			case "pkcs1":
				priv, p := mustGeneratePKCS1(t, crypto.SHA256)
				pub = p
				sig, _ = priv.Sign(msg)
			}
			if pub.Verify(sig, []byte("modified message")) {
				t.Fatal("Verify returned true for modified message, want false")
			}
		})
	}
}

// TestVerify_RejectsWrongKey verifies both schemes reject a signature
// when verified with a different keypair.
func TestVerify_RejectsWrongKey(t *testing.T) {
	t.Parallel()
	t.Run("PSS", func(t *testing.T) {
		t.Parallel()
		priv, _ := mustGeneratePSS(t, crypto.SHA256)
		_, otherPub := mustGeneratePSS(t, crypto.SHA256)
		msg := []byte("wrong key test")
		sig, err := priv.Sign(msg)
		if err != nil {
			t.Fatalf("Sign: %v", err)
		}
		if otherPub.Verify(sig, msg) {
			t.Fatal("Verify returned true with wrong public key, want false")
		}
	})
	t.Run("PKCS1", func(t *testing.T) {
		t.Parallel()
		priv, _ := mustGeneratePKCS1(t, crypto.SHA256)
		_, otherPub := mustGeneratePKCS1(t, crypto.SHA256)
		msg := []byte("wrong key test")
		sig, err := priv.Sign(msg)
		if err != nil {
			t.Fatalf("Sign: %v", err)
		}
		if otherPub.Verify(sig, msg) {
			t.Fatal("Verify returned true with wrong public key, want false")
		}
	})
}

// TestVerify_RejectsEmptySignature verifies both schemes reject a
// zero-length signature.
func TestVerify_RejectsEmptySignature(t *testing.T) {
	t.Parallel()
	t.Run("PSS", func(t *testing.T) {
		t.Parallel()
		_, pub := mustGeneratePSS(t, crypto.SHA256)
		if pub.Verify([]byte{}, []byte("empty sig test")) {
			t.Fatal("Verify returned true for empty signature, want false")
		}
	})
	t.Run("PKCS1", func(t *testing.T) {
		t.Parallel()
		_, pub := mustGeneratePKCS1(t, crypto.SHA256)
		if pub.Verify([]byte{}, []byte("empty sig test")) {
			t.Fatal("Verify returned true for empty signature, want false")
		}
	})
}

// ---------------------------------------------------------------------------
// Key validation tests
// ---------------------------------------------------------------------------

// TestGenerateKey_TooSmall verifies GeneratePSSKey and GeneratePKCS1Key
// reject keys below 2048 bits.
func TestGenerateKey_TooSmall(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		bits   int
		scheme string
	}{
		{"PSS/1024", 1024, "pss"},
		{"PSS/512", 512, "pss"},
		{"PSS/1536", 1536, "pss"},
		{"PKCS1/1024", 1024, "pkcs1"},
		{"PKCS1/512", 512, "pkcs1"},
		{"PKCS1/1536", 1536, "pkcs1"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var err error
			switch tt.scheme {
			case "pss":
				_, _, err = GeneratePSSKey(tt.bits, crypto.SHA256)
			case "pkcs1":
				_, _, err = GeneratePKCS1Key(tt.bits, crypto.SHA256)
			}
			if err == nil {
				t.Fatal("expected error for small key, got nil")
			}
			if !errors.Is(err, ErrKeyTooSmall) {
				t.Errorf("error = %v, want ErrKeyTooSmall", err)
			}
			if !strings.Contains(err.Error(), fmt.Sprintf("%d", tt.bits)) {
				t.Errorf("error %q should contain actual bit length %d", err, tt.bits)
			}
		})
	}
}

// TestGenerateKey_UnsupportedHash verifies GeneratePSSKey and
// GeneratePKCS1Key reject unsupported hashes.
func TestGenerateKey_UnsupportedHash(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		hash   crypto.Hash
		scheme string
	}{
		{"PSS/SHA1", crypto.SHA1, "pss"},
		{"PSS/SHA224", crypto.SHA224, "pss"},
		{"PSS/MD5", crypto.MD5, "pss"},
		{"PKCS1/SHA1", crypto.SHA1, "pkcs1"},
		{"PKCS1/SHA224", crypto.SHA224, "pkcs1"},
		{"PKCS1/MD5", crypto.MD5, "pkcs1"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var err error
			switch tt.scheme {
			case "pss":
				_, _, err = GeneratePSSKey(2048, tt.hash)
			case "pkcs1":
				_, _, err = GeneratePKCS1Key(2048, tt.hash)
			}
			if err == nil {
				t.Fatal("expected error for unsupported hash, got nil")
			}
			if !errors.Is(err, ErrUnsupportedHash) {
				t.Errorf("error = %v, want ErrUnsupportedHash", err)
			}
		})
	}
}

// TestNewPrivateKey_TooSmall verifies NewPSSPrivateKey and
// NewPKCS1PrivateKey reject keys below 2048 bits.
func TestNewPrivateKey_TooSmall(t *testing.T) {
	t.Parallel()
	// Generate a 1024-bit key with the stdlib directly (our wrappers
	// would reject it).
	stdKey, err := stdrsa.GenerateKey(readOnlyRand{}, 1024)
	if err != nil {
		t.Fatalf("stdlib GenerateKey: %v", err)
	}
	tests := []struct {
		name   string
		scheme string
	}{
		{"PSS", "pss"},
		{"PKCS1", "pkcs1"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var err error
			switch tt.scheme {
			case "pss":
				_, err = NewPSSPrivateKey(stdKey, crypto.SHA256)
			case "pkcs1":
				_, err = NewPKCS1PrivateKey(stdKey, crypto.SHA256)
			}
			if err == nil {
				t.Fatal("expected error for small key, got nil")
			}
			if !errors.Is(err, ErrKeyTooSmall) {
				t.Errorf("error = %v, want ErrKeyTooSmall", err)
			}
			if !strings.Contains(err.Error(), "1024") {
				t.Errorf("error %q should contain actual bit length 1024", err)
			}
		})
	}
}

// TestNewPublicKey_TooSmall verifies NewPSSPublicKey and NewPKCS1PublicKey
// reject keys below 2048 bits.
func TestNewPublicKey_TooSmall(t *testing.T) {
	t.Parallel()
	stdKey, err := stdrsa.GenerateKey(readOnlyRand{}, 1024)
	if err != nil {
		t.Fatalf("stdlib GenerateKey: %v", err)
	}
	tests := []struct {
		name   string
		scheme string
	}{
		{"PSS", "pss"},
		{"PKCS1", "pkcs1"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var err error
			switch tt.scheme {
			case "pss":
				_, err = NewPSSPublicKey(&stdKey.PublicKey, crypto.SHA256)
			case "pkcs1":
				_, err = NewPKCS1PublicKey(&stdKey.PublicKey, crypto.SHA256)
			}
			if err == nil {
				t.Fatal("expected error for small key, got nil")
			}
			if !errors.Is(err, ErrKeyTooSmall) {
				t.Errorf("error = %v, want ErrKeyTooSmall", err)
			}
		})
	}
}

// TestNewPrivateKey_NilKey verifies nil keys are rejected.
func TestNewPrivateKey_NilKey(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		key    *stdrsa.PrivateKey
		scheme string
	}{
		{"PSS/nil", nil, "pss"},
		{"PKCS1/nil", nil, "pkcs1"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var err error
			switch tt.scheme {
			case "pss":
				_, err = NewPSSPrivateKey(tt.key, crypto.SHA256)
			case "pkcs1":
				_, err = NewPKCS1PrivateKey(tt.key, crypto.SHA256)
			}
			if err == nil {
				t.Fatal("expected error for nil key, got nil")
			}
			if !errors.Is(err, ErrNilKey) {
				t.Errorf("error = %v, want ErrNilKey", err)
			}
		})
	}
}

// TestNewPublicKey_NilKey verifies nil public keys are rejected.
func TestNewPublicKey_NilKey(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		key    *stdrsa.PublicKey
		scheme string
	}{
		{"PSS/nil", nil, "pss"},
		{"PKCS1/nil", nil, "pkcs1"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var err error
			switch tt.scheme {
			case "pss":
				_, err = NewPSSPublicKey(tt.key, crypto.SHA256)
			case "pkcs1":
				_, err = NewPKCS1PublicKey(tt.key, crypto.SHA256)
			}
			if err == nil {
				t.Fatal("expected error for nil key, got nil")
			}
			if !errors.Is(err, ErrNilKey) {
				t.Errorf("error = %v, want ErrNilKey", err)
			}
		})
	}
}

// TestNewPrivateKey_NilModulus verifies a key with a nil modulus is rejected.
func TestNewPrivateKey_NilModulus(t *testing.T) {
	t.Parallel()
	key := &stdrsa.PrivateKey{
		D: big.NewInt(1),
	}
	tests := []struct {
		name   string
		scheme string
	}{
		{"PSS", "pss"},
		{"PKCS1", "pkcs1"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var err error
			switch tt.scheme {
			case "pss":
				_, err = NewPSSPrivateKey(key, crypto.SHA256)
			case "pkcs1":
				_, err = NewPKCS1PrivateKey(key, crypto.SHA256)
			}
			if err == nil {
				t.Fatal("expected error for nil modulus, got nil")
			}
			if !errors.Is(err, ErrNilKey) {
				t.Errorf("error = %v, want ErrNilKey", err)
			}
		})
	}
}

// TestNewPrivateKey_NilExponent verifies a key with a nil private exponent
// is rejected.
func TestNewPrivateKey_NilExponent(t *testing.T) {
	t.Parallel()
	key := &stdrsa.PrivateKey{
		PublicKey: stdrsa.PublicKey{
			N: big.NewInt(1),
			E: 65537,
		},
	}
	tests := []struct {
		name   string
		scheme string
	}{
		{"PSS", "pss"},
		{"PKCS1", "pkcs1"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var err error
			switch tt.scheme {
			case "pss":
				_, err = NewPSSPrivateKey(key, crypto.SHA256)
			case "pkcs1":
				_, err = NewPKCS1PrivateKey(key, crypto.SHA256)
			}
			if err == nil {
				t.Fatal("expected error for nil exponent, got nil")
			}
			if !errors.Is(err, ErrNilKey) {
				t.Errorf("error = %v, want ErrNilKey", err)
			}
		})
	}
}

// readOnlyRand is a minimal io.Reader that delegates to crypto/rand.Reader
// for generating small test keys that our wrappers would reject.
type readOnlyRand struct{}

func (readOnlyRand) Read(p []byte) (int, error) {
	return cryptorand.Read(p)
}

// ---------------------------------------------------------------------------
// Redact tests
// ---------------------------------------------------------------------------

// TestRedact verifies Redact does not leak raw key material. The output
// must be short, end with "...", and not contain any consecutive raw key
// bytes.
func TestRedact(t *testing.T) {
	t.Parallel()
	t.Run("PSS/private", func(t *testing.T) {
		t.Parallel()
		priv, _ := mustGeneratePSS(t, crypto.SHA256)
		assertRedactSafe(t, priv.Redact(), priv.key.D.Bytes())
	})
	t.Run("PSS/public", func(t *testing.T) {
		t.Parallel()
		_, pub := mustGeneratePSS(t, crypto.SHA256)
		assertRedactSafe(t, pub.Redact(), pub.key.N.Bytes())
	})
	t.Run("PKCS1/private", func(t *testing.T) {
		t.Parallel()
		priv, _ := mustGeneratePKCS1(t, crypto.SHA256)
		assertRedactSafe(t, priv.Redact(), priv.key.D.Bytes())
	})
	t.Run("PKCS1/public", func(t *testing.T) {
		t.Parallel()
		_, pub := mustGeneratePKCS1(t, crypto.SHA256)
		assertRedactSafe(t, pub.Redact(), pub.key.N.Bytes())
	})
}

// assertRedactSafe checks that a redacted string does not contain raw key
// material, ends with "...", and is short.
func assertRedactSafe(t *testing.T, redacted string, rawKey []byte) {
	t.Helper()
	// Must end with "...".
	if !strings.HasSuffix(redacted, "...") {
		t.Fatalf("Redact() = %q, want suffix '...'", redacted)
	}
	// Must be short (8 hex chars + 3 dots = 11 chars).
	if len(redacted) != 11 {
		t.Fatalf("Redact() = %q, length %d, want 11", redacted, len(redacted))
	}
	// Must not contain any 2+ consecutive raw key bytes.
	for i := 0; i+1 < len(rawKey); i++ {
		pairHex := hex.EncodeToString(rawKey[i : i+2])
		if strings.Contains(redacted, pairHex) {
			t.Fatalf("Redact() exposes raw key bytes at offset %d: %q in %q", i, pairHex, redacted)
		}
	}
}

// TestRedact_Deterministic verifies Redact is deterministic — same key
// always produces the same fingerprint.
func TestRedact_Deterministic(t *testing.T) {
	t.Parallel()
	t.Run("PSS", func(t *testing.T) {
		t.Parallel()
		priv, pub := mustGeneratePSS(t, crypto.SHA256)
		if priv.Redact() != priv.Redact() {
			t.Fatal("private Redact() is not deterministic")
		}
		if pub.Redact() != pub.Redact() {
			t.Fatal("public Redact() is not deterministic")
		}
	})
	t.Run("PKCS1", func(t *testing.T) {
		t.Parallel()
		priv, pub := mustGeneratePKCS1(t, crypto.SHA256)
		if priv.Redact() != priv.Redact() {
			t.Fatal("private Redact() is not deterministic")
		}
		if pub.Redact() != pub.Redact() {
			t.Fatal("public Redact() is not deterministic")
		}
	})
}

// TestRedact_DifferentKeys verifies different keys produce different
// fingerprints.
func TestRedact_DifferentKeys(t *testing.T) {
	t.Parallel()
	t.Run("PSS/private", func(t *testing.T) {
		t.Parallel()
		priv1, _ := mustGeneratePSS(t, crypto.SHA256)
		priv2, _ := mustGeneratePSS(t, crypto.SHA256)
		if priv1.Redact() == priv2.Redact() {
			t.Fatal("different private keys produced same Redact() fingerprint")
		}
	})
	t.Run("PSS/public", func(t *testing.T) {
		t.Parallel()
		_, pub1 := mustGeneratePSS(t, crypto.SHA256)
		_, pub2 := mustGeneratePSS(t, crypto.SHA256)
		if pub1.Redact() == pub2.Redact() {
			t.Fatal("different public keys produced same Redact() fingerprint")
		}
	})
}

// ---------------------------------------------------------------------------
// Equal tests
// ---------------------------------------------------------------------------

// TestPSSPublicKey_Equal verifies constant-time equality for PSS public keys.
func TestPSSPublicKey_Equal(t *testing.T) {
	t.Parallel()
	priv1, pub1 := mustGeneratePSS(t, crypto.SHA256)
	_, pub2 := mustGeneratePSS(t, crypto.SHA256)
	derived := priv1.Public()

	tests := []struct {
		name string
		a, b *PSSPublicKey
		want bool
	}{
		{"same_ref", pub1, pub1, true},
		{"derived_from_private", pub1, derived, true},
		{"different_keys", pub1, pub2, false},
		{"nil_other", pub1, nil, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := tt.a.Equal(tt.b)
			if got != tt.want {
				t.Fatalf("Equal = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestPKCS1PublicKey_Equal verifies constant-time equality for PKCS1 public keys.
func TestPKCS1PublicKey_Equal(t *testing.T) {
	t.Parallel()
	priv1, pub1 := mustGeneratePKCS1(t, crypto.SHA256)
	_, pub2 := mustGeneratePKCS1(t, crypto.SHA256)
	derived := priv1.Public()

	tests := []struct {
		name string
		a, b *PKCS1PublicKey
		want bool
	}{
		{"same_ref", pub1, pub1, true},
		{"derived_from_private", pub1, derived, true},
		{"different_keys", pub1, pub2, false},
		{"nil_other", pub1, nil, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := tt.a.Equal(tt.b)
			if got != tt.want {
				t.Fatalf("Equal = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestEqual_Symmetric verifies a.Equal(b) == b.Equal(a).
func TestEqual_Symmetric(t *testing.T) {
	t.Parallel()
	_, pub1 := mustGeneratePSS(t, crypto.SHA256)
	_, pub2 := mustGeneratePSS(t, crypto.SHA256)
	if pub1.Equal(pub2) != pub2.Equal(pub1) {
		t.Fatal("Equal is not symmetric")
	}
	if !pub1.Equal(pub1) {
		t.Fatal("Equal(self) returned false")
	}
}

// ---------------------------------------------------------------------------
// Wycheproof tests
// ---------------------------------------------------------------------------

// wycheproofRSASuite models the relevant fields of the Wycheproof
// RSA PSS and PKCS1v1.5 test vector JSON files.
type wycheproofRSASuite struct {
	Algorithm     string                   `json:"algorithm"`
	NumberOfTests int                      `json:"numberOfTests"`
	TestGroups    []wycheproofRSATestGroup `json:"testGroups"`
}

type wycheproofRSATestGroup struct {
	KeySize   int                    `json:"keySize"`
	SHA       string                 `json:"sha"`
	Mgf       string                 `json:"mgf"`
	MgfSHA    string                 `json:"mgfSha"`
	SLen      int                    `json:"sLen"`
	PublicKey wycheproofRSAPublicKey `json:"publicKey"`
	Tests     []wycheproofRSATest    `json:"tests"`
}

type wycheproofRSAPublicKey struct {
	Modulus        string `json:"modulus"`
	PublicExponent string `json:"publicExponent"`
}

type wycheproofRSATest struct {
	TcID    int      `json:"tcId"`
	Comment string   `json:"comment"`
	Flags   []string `json:"flags"`
	Msg     string   `json:"msg"`
	Sig     string   `json:"sig"`
	Result  string   `json:"result"`
}

// hashFromWycheproofName maps a Wycheproof hash name string to a crypto.Hash.
// Returns ok=false for unsupported hashes.
func hashFromWycheproofName(name string) (crypto.Hash, bool) {
	switch name {
	case "SHA-256":
		return crypto.SHA256, true
	case "SHA-384":
		return crypto.SHA384, true
	case "SHA-512":
		return crypto.SHA512, true
	default:
		return 0, false
	}
}

// rsaPublicKeyFromWycheproof constructs a *stdrsa.PublicKey from the
// hex-encoded modulus and public exponent in a Wycheproof test group.
func rsaPublicKeyFromWycheproof(wk wycheproofRSAPublicKey) (*stdrsa.PublicKey, error) {
	modulus, err := hex.DecodeString(wk.Modulus)
	if err != nil {
		return nil, fmt.Errorf("decode modulus: %w", err)
	}
	exp, err := hex.DecodeString(wk.PublicExponent)
	if err != nil {
		return nil, fmt.Errorf("decode publicExponent: %w", err)
	}
	n := new(big.Int).SetBytes(modulus)
	e := new(big.Int).SetBytes(exp)
	if !e.IsInt64() {
		return nil, fmt.Errorf("public exponent too large")
	}
	return &stdrsa.PublicKey{N: n, E: int(e.Int64())}, nil
}

// loadWycheproofRSA reads and parses a Wycheproof RSA test vector file.
func loadWycheproofRSA(t *testing.T, path string) wycheproofRSASuite {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	var suite wycheproofRSASuite
	if err := json.Unmarshal(data, &suite); err != nil {
		t.Fatalf("unmarshal %s: %v", path, err)
	}
	return suite
}

// wycheproofTestName sanitizes a Wycheproof test comment into a valid
// Go subtest name.
func wycheproofTestName(tcID int, comment string) string {
	if comment == "" {
		return fmt.Sprintf("tcId-%d", tcID)
	}
	c := strings.NewReplacer(" ", "_", "/", "_", "(", "", ")", "", "'", "", "\"", "")
	return fmt.Sprintf("tcId-%d-%s", tcID, c.Replace(comment))
}

// TestWycheproofPSS loads all Wycheproof RSASSA-PSS test vector files from
// testdata/, filters to keySize >= 2048, supported hashes (SHA-256,
// SHA-384, SHA-512), and salt length == hash output length, then runs
// every test case: valid/acceptable → Verify returns true, invalid →
// Verify returns false.
//
// Vector: [Wycheproof] rsa_pss_*_test.json
func TestWycheproofPSS(t *testing.T) {
	t.Parallel()
	files, err := filepath.Glob("testdata/rsa_pss_*.json")
	if err != nil {
		t.Fatalf("glob wycheproof PSS files: %v", err)
	}
	if len(files) == 0 {
		t.Fatal("no Wycheproof PSS test vector files found in testdata/")
	}

	total := 0
	for _, file := range files {
		suite := loadWycheproofRSA(t, file)
		for _, group := range suite.TestGroups {
			// Filter: keySize >= 2048.
			if group.KeySize < 2048 {
				continue
			}
			// Filter: supported hash.
			hash, ok := hashFromWycheproofName(group.SHA)
			if !ok {
				continue
			}
			// Filter: salt length == hash output length.
			if group.SLen != hashOutputLen(hash) {
				continue
			}
			// Filter: MGF1 with same hash as signature hash (Go's
			// PSSOptions does not support a separate MGF hash).
			if group.MgfSHA != "" && group.MgfSHA != group.SHA {
				continue
			}

			// Construct the public key.
			stdPub, err := rsaPublicKeyFromWycheproof(group.PublicKey)
			if err != nil {
				// Some groups use deliberately invalid keys; skip.
				continue
			}
			pub, err := NewPSSPublicKey(stdPub, hash)
			if err != nil {
				// Key too small or invalid — skip this group.
				continue
			}

			for _, tc := range group.Tests {
				tc := tc
				total++
				t.Run(wycheproofTestName(tc.TcID, tc.Comment), func(t *testing.T) {
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
						// "acceptable" means the implementation may
						// accept or reject. Log flags for investigation
						// but do not fail either way.
						if !got {
							t.Logf("tcId %d (%s): acceptable case rejected [flags: %v]", tc.TcID, tc.Comment, tc.Flags)
						}
					case "invalid":
						if got {
							t.Errorf("tcId %d (%s): Verify = true, want false [flags: %v]", tc.TcID, tc.Comment, tc.Flags)
						}
					default:
						t.Errorf("tcId %d (%s): unknown result %q", tc.TcID, tc.Comment, tc.Result)
					}
				})
			}
		}
	}
	if total == 0 {
		t.Fatal("no Wycheproof PSS test cases were run")
	}
	t.Logf("ran %d Wycheproof PSS test cases from %d files", total, len(files))
}

// TestWycheproofPKCS1 loads all Wycheproof RSASSA-PKCS1-v1_5 test vector
// files from testdata/, filters to keySize >= 2048 and supported hashes
// (SHA-256, SHA-384, SHA-512), then runs every test case:
// valid/acceptable → Verify returns true, invalid → Verify returns false.
//
// Vector: [Wycheproof] rsa_signature_*_test.json
func TestWycheproofPKCS1(t *testing.T) {
	t.Parallel()
	files, err := filepath.Glob("testdata/rsa_signature_*.json")
	if err != nil {
		t.Fatalf("glob wycheproof PKCS1 files: %v", err)
	}
	if len(files) == 0 {
		t.Fatal("no Wycheproof PKCS1 test vector files found in testdata/")
	}

	total := 0
	for _, file := range files {
		suite := loadWycheproofRSA(t, file)
		for _, group := range suite.TestGroups {
			// Filter: keySize >= 2048.
			if group.KeySize < 2048 {
				continue
			}
			// Filter: supported hash.
			hash, ok := hashFromWycheproofName(group.SHA)
			if !ok {
				continue
			}

			// Construct the public key.
			stdPub, err := rsaPublicKeyFromWycheproof(group.PublicKey)
			if err != nil {
				continue
			}
			pub, err := NewPKCS1PublicKey(stdPub, hash)
			if err != nil {
				continue
			}

			for _, tc := range group.Tests {
				tc := tc
				total++
				t.Run(wycheproofTestName(tc.TcID, tc.Comment), func(t *testing.T) {
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
						// "acceptable" means the implementation may
						// accept or reject. Log flags for investigation
						// but do not fail either way.
						if !got {
							t.Logf("tcId %d (%s): acceptable case rejected [flags: %v]", tc.TcID, tc.Comment, tc.Flags)
						}
					case "invalid":
						if got {
							t.Errorf("tcId %d (%s): Verify = true, want false [flags: %v]", tc.TcID, tc.Comment, tc.Flags)
						}
					default:
						t.Errorf("tcId %d (%s): unknown result %q", tc.TcID, tc.Comment, tc.Result)
					}
				})
			}
		}
	}
	if total == 0 {
		t.Fatal("no Wycheproof PKCS1 test cases were run")
	}
	t.Logf("ran %d Wycheproof PKCS1 test cases from %d files", total, len(files))
}

// ---------------------------------------------------------------------------
// Cross-module isolation test
// ---------------------------------------------------------------------------

// TestNoAuthChainImports verifies the RSA package does not import auth or
// chain modules (dependency rule from AGENTS.md).
func TestNoAuthChainImports(t *testing.T) {
	t.Parallel()
	// Check non-test source files only. The test file itself contains
	// the import-path strings as part of its assertions, which would
	// produce false positives if included.
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatalf("glob: %v", err)
	}
	for _, file := range files {
		if strings.HasSuffix(file, "_test.go") {
			continue
		}
		data, err := os.ReadFile(file)
		if err != nil {
			t.Fatalf("read %s: %v", file, err)
		}
		if strings.Contains(string(data), "github.com/bperin/auth") {
			t.Errorf("file %s imports github.com/bperin/auth (dependency rule violation)", file)
		}
		if strings.Contains(string(data), "github.com/bperin/chain") {
			t.Errorf("file %s imports github.com/bperin/chain (dependency rule violation)", file)
		}
	}
}

// ---------------------------------------------------------------------------
// Example functions
// ---------------------------------------------------------------------------

// ExampleGeneratePSSKey demonstrates generating a PSS keypair, signing a
// message, and verifying the signature.
func ExampleGeneratePSSKey() {
	priv, pub, err := GeneratePSSKey(2048, crypto.SHA256)
	if err != nil {
		fmt.Println("key generation failed:", err)
		return
	}

	msg := []byte("hello from PSS")
	sig, err := priv.Sign(msg)
	if err != nil {
		fmt.Println("sign failed:", err)
		return
	}

	if pub.Verify(sig, msg) {
		fmt.Println("PSS signature verified")
	} else {
		fmt.Println("PSS verification failed")
	}

	// Output:
	// PSS signature verified
}

// ExampleGeneratePKCS1Key demonstrates generating a PKCS1v1.5 keypair,
// signing a message, and verifying the signature.
func ExampleGeneratePKCS1Key() {
	priv, pub, err := GeneratePKCS1Key(2048, crypto.SHA256)
	if err != nil {
		fmt.Println("key generation failed:", err)
		return
	}

	msg := []byte("hello from PKCS1v1.5")
	sig, err := priv.Sign(msg)
	if err != nil {
		fmt.Println("sign failed:", err)
		return
	}

	if pub.Verify(sig, msg) {
		fmt.Println("PKCS1v1.5 signature verified")
	} else {
		fmt.Println("PKCS1v1.5 verification failed")
	}

	// PKCS1v1.5 is deterministic: signing the same message twice
	// produces byte-identical signatures.
	sig2, _ := priv.Sign(msg)
	if subtle.ConstantTimeCompare(sig, sig2) == 1 {
		fmt.Println("deterministic signatures match")
	}

	// Output:
	// PKCS1v1.5 signature verified
	// deterministic signatures match
}
