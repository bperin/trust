package claims

import (
	stded25519 "crypto/ed25519"
	"sync"
	"testing"
	"time"

	"github.com/bperin/trust/crypto/ed25519"
	jwkutil "github.com/bperin/trust/identity/jwk"
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
