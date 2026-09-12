package claims

import (
	"crypto"
	"crypto/elliptic"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	stded25519 "crypto/ed25519"

	"github.com/bperin/trust/crypto/ecdsa"
	"github.com/bperin/trust/crypto/ed25519"
	"github.com/bperin/trust/crypto/rsa"
	"github.com/bperin/trust/crypto/secp256k1"
	"github.com/bperin/trust/crypto/x25519"
	jwkutil "github.com/bperin/trust/identity/jwk"
	"github.com/bperin/trust/signature"
)

func TestSignAndVerify(t *testing.T) {
	pubBytes, privBytes, err := stded25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	pub, err := ed25519.NewPublicKey(pubBytes)
	if err != nil {
		t.Fatalf("NewPublicKey: %v", err)
	}
	priv, err := ed25519.NewPrivateKey(privBytes)
	if err != nil {
		t.Fatalf("NewPrivateKey: %v", err)
	}

	now := time.Now().Unix()
	c := Claims{
		Issuer:    "https://auth.example.com",
		Subject:   "user-123",
		Audience:  []string{"api.example.com"},
		ExpiresAt: now + 3600,
		NotBefore: now - 60,
		IssuedAt:  now,
		ID:        "jti-999",
		Extra:     map[string]any{"role": "admin"},
	}

	token, err := Sign(c, priv, Options{Algorithm: "EdDSA"})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	verified, err := Verify(token, pub, Options{
		Algorithm:        "EdDSA",
		ExpectedIssuer:   "https://auth.example.com",
		ExpectedAudience: []string{"api.example.com"},
		Now:              func() time.Time { return time.Unix(now+10, 0) },
	})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}

	if verified.Subject != "user-123" {
		t.Errorf("Subject: got %q, want %q", verified.Subject, "user-123")
	}
	if verified.Extra["role"] != "admin" {
		t.Errorf("Extra role: got %v, want %q", verified.Extra["role"], "admin")
	}
}

func TestVerifyWithJWK(t *testing.T) {
	pubBytes, privBytes, err := stded25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	pub, err := ed25519.NewPublicKey(pubBytes)
	if err != nil {
		t.Fatalf("NewPublicKey: %v", err)
	}
	priv, err := ed25519.NewPrivateKey(privBytes)
	if err != nil {
		t.Fatalf("NewPrivateKey: %v", err)
	}

	jwkBytes, err := jwkutil.ToJWK(pub)
	if err != nil {
		t.Fatalf("ToJWK: %v", err)
	}

	now := time.Now().Unix()
	c := Claims{
		Issuer:    "iss",
		ExpiresAt: now + 60,
	}

	token, err := Sign(c, priv, Options{Algorithm: "EdDSA"})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	verified, err := VerifyWithJWK(token, jwkBytes, Options{
		Algorithm:      "EdDSA",
		ExpectedIssuer: "iss",
		Now:            func() time.Time { return time.Unix(now, 0) },
	})
	if err != nil {
		t.Fatalf("VerifyWithJWK: %v", err)
	}
	if verified.Issuer != "iss" {
		t.Errorf("Issuer: got %q, want %q", verified.Issuer, "iss")
	}
}

func TestExpiration(t *testing.T) {
	pubBytes, privBytes, _ := stded25519.GenerateKey(nil)
	pub, _ := ed25519.NewPublicKey(pubBytes)
	priv, _ := ed25519.NewPrivateKey(privBytes)

	now := time.Now().Unix()
	c := Claims{
		ExpiresAt: now + 10,
	}

	token, _ := Sign(c, priv, Options{Algorithm: "EdDSA"})

	// Verify before expiration
	_, err := Verify(token, pub, Options{
		Algorithm: "EdDSA",
		Now:       func() time.Time { return time.Unix(now+5, 0) },
	})
	if err != nil {
		t.Errorf("Expected success before expiry, got: %v", err)
	}

	// Verify after expiration
	_, err = Verify(token, pub, Options{
		Algorithm: "EdDSA",
		Now:       func() time.Time { return time.Unix(now+15, 0) },
	})
	if err == nil {
		t.Errorf("Expected expiration error, got nil")
	}
}

func TestConcurrencyAndRace(t *testing.T) {
	pubBytes, privBytes, _ := stded25519.GenerateKey(nil)
	pub, _ := ed25519.NewPublicKey(pubBytes)
	priv, _ := ed25519.NewPrivateKey(privBytes)

	now := time.Now().Unix()
	c := Claims{
		Issuer:    "iss",
		ExpiresAt: now + 1000,
	}
	token, _ := Sign(c, priv, Options{Algorithm: "EdDSA"})

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := Verify(token, pub, Options{
				Algorithm:      "EdDSA",
				ExpectedIssuer: "iss",
				Now:            func() time.Time { return time.Unix(now+10, 0) },
			})
			if err != nil {
				t.Errorf("Concurrent verify failed: %v", err)
			}
		}()
	}
	wg.Wait()
}

// keyPair holds a generated private/public key pair for testing.
type keyPair struct {
	priv crypto.PrivateKey
	pub  crypto.PublicKey
	alg  string // expected JOSE algorithm name
}

// generateKeyPair generates a key pair for the given algorithm family.
func generateKeyPair(t *testing.T, alg string) keyPair {
	t.Helper()
	switch alg {
	case "EdDSA":
		priv, pub, err := ed25519.GenerateKey()
		if err != nil {
			t.Fatalf("ed25519.GenerateKey: %v", err)
		}
		return keyPair{priv, pub, "EdDSA"}
	case "ES256K":
		priv, pub, err := secp256k1.GenerateKey()
		if err != nil {
			t.Fatalf("secp256k1.GenerateKey: %v", err)
		}
		return keyPair{priv, pub, "ES256K"}
	case "ES256":
		priv, pub, err := ecdsa.GenerateKey(elliptic.P256(), crypto.SHA256)
		if err != nil {
			t.Fatalf("ecdsa.GenerateKey P-256: %v", err)
		}
		return keyPair{priv, pub, "ES256"}
	case "ES384":
		priv, pub, err := ecdsa.GenerateKey(elliptic.P384(), crypto.SHA384)
		if err != nil {
			t.Fatalf("ecdsa.GenerateKey P-384: %v", err)
		}
		return keyPair{priv, pub, "ES384"}
	case "PS256":
		priv, pub, err := rsa.GeneratePSSKey(2048, crypto.SHA256)
		if err != nil {
			t.Fatalf("rsa.GeneratePSSKey: %v", err)
		}
		return keyPair{priv, pub, "PS256"}
	case "RS256":
		priv, pub, err := rsa.GeneratePKCS1Key(2048, crypto.SHA256)
		if err != nil {
			t.Fatalf("rsa.GeneratePKCS1Key: %v", err)
		}
		return keyPair{priv, pub, "RS256"}
	default:
		t.Fatalf("unsupported algorithm: %s", alg)
		return keyPair{}
	}
}

// TestSignAutoDerive verifies that claims.Sign with an empty
// opts.Algorithm derives the correct JOSE name from the key type for
// every supported algorithm family.
func TestSignAutoDerive(t *testing.T) {
	algorithms := []string{"EdDSA", "ES256K", "ES256", "ES384", "PS256", "RS256"}

	for _, alg := range algorithms {
		t.Run(alg, func(t *testing.T) {
			kp := generateKeyPair(t, alg)

			now := time.Now().Unix()
			c := Claims{
				Issuer:    "iss",
				Subject:   "sub",
				ExpiresAt: now + 3600,
				IssuedAt:  now,
			}

			// Sign with empty Algorithm — should auto-derive.
			token, err := Sign(c, kp.priv, Options{})
			if err != nil {
				t.Fatalf("Sign with auto-derive: %v", err)
			}

			// Verify the token has the correct alg header.
			verified, err := Verify(token, kp.pub, Options{
				ExpectedIssuer: "iss",
				Now:            func() time.Time { return time.Unix(now+10, 0) },
			})
			if err != nil {
				t.Fatalf("Verify: %v", err)
			}
			if verified.Subject != "sub" {
				t.Errorf("Subject: got %q, want %q", verified.Subject, "sub")
			}

			// Extract the alg header from the token to confirm it matches.
			headerJSON, err := base64.RawURLEncoding.DecodeString(token[:strings.IndexByte(token, '.')])
			if err != nil {
				t.Fatalf("decode header: %v", err)
			}
			var header map[string]any
			if err := json.Unmarshal(headerJSON, &header); err != nil {
				t.Fatalf("unmarshal header: %v", err)
			}
			gotAlg, _ := header["alg"].(string)
			if gotAlg != alg {
				t.Errorf("alg header: got %q, want %q", gotAlg, alg)
			}
		})
	}
}

// TestSignExplicitAlgorithm verifies that claims.Sign with an explicit
// opts.Algorithm still works (the override path is preserved).
func TestSignExplicitAlgorithm(t *testing.T) {
	algorithms := []string{"EdDSA", "ES256K", "ES256", "PS256", "RS256"}

	for _, alg := range algorithms {
		t.Run(alg, func(t *testing.T) {
			kp := generateKeyPair(t, alg)

			now := time.Now().Unix()
			c := Claims{
				Issuer:    "iss",
				ExpiresAt: now + 3600,
			}

			token, err := Sign(c, kp.priv, Options{Algorithm: alg})
			if err != nil {
				t.Fatalf("Sign with explicit alg: %v", err)
			}

			_, err = Verify(token, kp.pub, Options{
				Algorithm:      alg,
				ExpectedIssuer: "iss",
				Now:            func() time.Time { return time.Unix(now+10, 0) },
			})
			if err != nil {
				t.Fatalf("Verify: %v", err)
			}
		})
	}
}

// TestSignUnsupportedKey verifies that an unrecognized key type
// (x25519 — a key exchange key, not a signing key) returns a typed
// error wrapping signature.ErrUnsupportedAlgorithm.
func TestSignUnsupportedKey(t *testing.T) {
	priv, _, err := x25519.GenerateKey()
	if err != nil {
		t.Fatalf("x25519.GenerateKey: %v", err)
	}

	c := Claims{Issuer: "iss", ExpiresAt: time.Now().Unix() + 60}
	_, err = Sign(c, priv, Options{})
	if err == nil {
		t.Fatal("Sign with x25519 key: expected error, got nil")
	}
	if !errors.Is(err, signature.ErrUnsupportedAlgorithm) {
		t.Errorf("Sign with x25519: err = %v, want errors.Is(_, signature.ErrUnsupportedAlgorithm)", err)
	}
}
