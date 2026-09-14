package claims

import (
	"crypto"
	"crypto/elliptic"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
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

// TestA14ReservedClaimRejectedInExtra verifies finding A14: a registered
// claim name (iss, sub, aud, exp, nbf, iat, jti) in Claims.Extra is rejected
// at marshal time so it cannot overwrite the registered claim field. Each
// registered name is a separate table case per [RFC 7519] §4.1.
func TestA14ReservedClaimRejectedInExtra(t *testing.T) {
	t.Parallel()

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
	tests := []struct {
		name    string
		extra   map[string]any
		wantErr error
	}{
		{name: "iss in extra", extra: map[string]any{"iss": "evil-issuer"}, wantErr: ErrReservedClaim},
		{name: "sub in extra", extra: map[string]any{"sub": "evil-subject"}, wantErr: ErrReservedClaim},
		{name: "aud in extra", extra: map[string]any{"aud": "evil-audience"}, wantErr: ErrReservedClaim},
		{name: "exp in extra", extra: map[string]any{"exp": float64(now + 9999)}, wantErr: ErrReservedClaim},
		{name: "nbf in extra", extra: map[string]any{"nbf": float64(now)}, wantErr: ErrReservedClaim},
		{name: "iat in extra", extra: map[string]any{"iat": float64(now)}, wantErr: ErrReservedClaim},
		{name: "jti in extra", extra: map[string]any{"jti": "evil-jti"}, wantErr: ErrReservedClaim},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			c := Claims{
				Issuer:    "real-issuer",
				Subject:   "real-subject",
				ExpiresAt: now + 3600,
				Extra:     tt.extra,
			}

			// Validate rejects the reserved name.
			if !errors.Is(c.Validate(), tt.wantErr) {
				t.Errorf("Validate: got error %v, want errors.Is(_, %v)", c.Validate(), tt.wantErr)
			}

			// MarshalJSON rejects the reserved name.
			if _, err := json.Marshal(c); !errors.Is(err, tt.wantErr) {
				t.Errorf("MarshalJSON: got error %v, want errors.Is(_, %v)", err, tt.wantErr)
			}

			// Sign rejects the reserved name before any key work.
			_, err := Sign(c, priv, Options{Algorithm: "EdDSA"})
			if !errors.Is(err, tt.wantErr) {
				t.Errorf("Sign: got error %v, want errors.Is(_, %v)", err, tt.wantErr)
			}
		})
	}

	// A non-reserved custom claim is accepted and round-trips.
	t.Run("custom claim accepted", func(t *testing.T) {
		t.Parallel()
		c := Claims{
			Issuer:    "real-issuer",
			ExpiresAt: now + 3600,
			Extra:     map[string]any{"role": "admin"},
		}
		if err := c.Validate(); err != nil {
			t.Fatalf("Validate with custom claim: got error %v, want nil", err)
		}
		token, err := Sign(c, priv, Options{Algorithm: "EdDSA"})
		if err != nil {
			t.Fatalf("Sign with custom claim: got error %v, want nil", err)
		}
		verified, err := Verify(token, pub, Options{
			Algorithm:      "EdDSA",
			ExpectedIssuer: "real-issuer",
			Now:            func() time.Time { return time.Unix(now+10, 0) },
		})
		if err != nil {
			t.Fatalf("Verify with custom claim: got error %v, want nil", err)
		}
		if verified.Extra["role"] != "admin" {
			t.Errorf("Extra role: got %v, want %q", verified.Extra["role"], "admin")
		}
	})
}

// TestA14ReservedClaimNotOverwritten verifies that a token carrying a
// registered claim is parsed into the dedicated field, never into Extra, so
// unmarshaling cannot smuggle a reserved name past the A14 guard.
func TestA14ReservedClaimNotOverwritten(t *testing.T) {
	t.Parallel()

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
		Issuer:    "real-issuer",
		Subject:   "real-subject",
		Audience:  []string{"real-audience"},
		ExpiresAt: now + 3600,
		NotBefore: now - 60,
		IssuedAt:  now,
		ID:        "real-jti",
		Extra:     map[string]any{"role": "admin"},
	}
	token, err := Sign(c, priv, Options{Algorithm: "EdDSA"})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	verified, err := Verify(token, pub, Options{
		Algorithm:        "EdDSA",
		ExpectedIssuer:   "real-issuer",
		ExpectedAudience: []string{"real-audience"},
		Now:              func() time.Time { return time.Unix(now+10, 0) },
	})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	// Registered claims are in their fields, not in Extra.
	if verified.Issuer != "real-issuer" {
		t.Errorf("Issuer: got %q, want %q", verified.Issuer, "real-issuer")
	}
	if verified.Subject != "real-subject" {
		t.Errorf("Subject: got %q, want %q", verified.Subject, "real-subject")
	}
	if verified.ID != "real-jti" {
		t.Errorf("ID: got %q, want %q", verified.ID, "real-jti")
	}
	for _, reserved := range []string{"iss", "sub", "aud", "exp", "nbf", "iat", "jti"} {
		if _, present := verified.Extra[reserved]; present {
			t.Errorf("Extra contains reserved claim %q (A14)", reserved)
		}
	}
}

// TestVerifyAlgNoneRejected verifies that a token with "alg":"none" is
// rejected before any signature work, with a typed error. The alg header is
// never trusted.
func TestVerifyAlgNoneRejected(t *testing.T) {
	t.Parallel()

	pubBytes, _, err := stded25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	pub, err := ed25519.NewPublicKey(pubBytes)
	if err != nil {
		t.Fatalf("NewPublicKey: %v", err)
	}

	now := time.Now().Unix()
	payload, _ := json.Marshal(map[string]any{"iss": "iss", "exp": now + 3600})
	noneHeader := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none"}`))
	noneToken := noneHeader + "." + base64.RawURLEncoding.EncodeToString(payload) + "."

	_, err = Verify(noneToken, pub, Options{Algorithm: "EdDSA"})
	if !errors.Is(err, ErrAlgNone) {
		t.Errorf("Verify alg none: got error %v, want errors.Is(_, %v)", err, ErrAlgNone)
	}

	// Without a pinned Algorithm the alg:none token is still rejected.
	_, err = Verify(noneToken, pub, Options{})
	if !errors.Is(err, ErrAlgNone) {
		t.Errorf("Verify alg none unpinned: got error %v, want errors.Is(_, %v)", err, ErrAlgNone)
	}
}

// TestSignAlgNoneRejected verifies that Sign refuses to sign with "alg":"none".
func TestSignAlgNoneRejected(t *testing.T) {
	t.Parallel()

	_, privBytes, err := stded25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	priv, err := ed25519.NewPrivateKey(privBytes)
	if err != nil {
		t.Fatalf("NewPrivateKey: %v", err)
	}

	c := Claims{Issuer: "iss", ExpiresAt: time.Now().Unix() + 60}
	_, err = Sign(c, priv, Options{Algorithm: "none"})
	if !errors.Is(err, ErrAlgNone) {
		t.Errorf("Sign alg none: got error %v, want errors.Is(_, %v)", err, ErrAlgNone)
	}
}

// TestVerifyAlgorithmWhitelist verifies the per-key algorithm whitelist: a
// token whose "alg" header is not in opts.AllowedAlgorithms is rejected with
// ErrAlgNotAllowed, even when the signature is valid for the key.
func TestVerifyAlgorithmWhitelist(t *testing.T) {
	t.Parallel()

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
	c := Claims{Issuer: "iss", ExpiresAt: now + 3600}
	token, err := Sign(c, priv, Options{Algorithm: "EdDSA"})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	// Whitelist that excludes EdDSA rejects the valid token.
	_, err = Verify(token, pub, Options{
		Algorithm:         "EdDSA",
		AllowedAlgorithms: []string{"ES256", "ES256K"},
		Now:               func() time.Time { return time.Unix(now+10, 0) },
	})
	if !errors.Is(err, ErrAlgNotAllowed) {
		t.Errorf("Verify with excluding whitelist: got error %v, want errors.Is(_, %v)", err, ErrAlgNotAllowed)
	}

	// Whitelist that includes EdDSA accepts the valid token.
	_, err = Verify(token, pub, Options{
		Algorithm:         "EdDSA",
		AllowedAlgorithms: []string{"EdDSA", "ES256"},
		Now:               func() time.Time { return time.Unix(now+10, 0) },
	})
	if err != nil {
		t.Errorf("Verify with including whitelist: got error %v, want nil", err)
	}

	// An alg:none token is rejected by the whitelist as not allowed before
	// it is rejected as alg:none — either typed error is acceptable, but
	// alg:none must win since it is checked first.
	noneHeader := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none"}`))
	noneToken := noneHeader + "." + base64.RawURLEncoding.EncodeToString(mustMarshalClaims(c)) + "."
	_, err = Verify(noneToken, pub, Options{AllowedAlgorithms: []string{"EdDSA"}})
	if !errors.Is(err, ErrAlgNone) {
		t.Errorf("Verify alg none with whitelist: got error %v, want errors.Is(_, %v)", err, ErrAlgNone)
	}
}

// TestSignAlgorithmWhitelist verifies Sign enforces the per-key whitelist
// for both an explicit algorithm and a derived one.
func TestSignAlgorithmWhitelist(t *testing.T) {
	t.Parallel()

	_, privBytes, err := stded25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	priv, err := ed25519.NewPrivateKey(privBytes)
	if err != nil {
		t.Fatalf("NewPrivateKey: %v", err)
	}

	c := Claims{Issuer: "iss", ExpiresAt: time.Now().Unix() + 60}

	// Explicit alg not in the whitelist is rejected.
	_, err = Sign(c, priv, Options{Algorithm: "EdDSA", AllowedAlgorithms: []string{"ES256"}})
	if !errors.Is(err, ErrAlgNotAllowed) {
		t.Errorf("Sign explicit alg not allowed: got error %v, want errors.Is(_, %v)", err, ErrAlgNotAllowed)
	}

	// Derived alg not in the whitelist is rejected.
	_, err = Sign(c, priv, Options{AllowedAlgorithms: []string{"ES256"}})
	if !errors.Is(err, ErrAlgNotAllowed) {
		t.Errorf("Sign derived alg not allowed: got error %v, want errors.Is(_, %v)", err, ErrAlgNotAllowed)
	}

	// Derived alg in the whitelist succeeds.
	_, err = Sign(c, priv, Options{AllowedAlgorithms: []string{"EdDSA", "ES256"}})
	if err != nil {
		t.Errorf("Sign derived alg allowed: got error %v, want nil", err)
	}
}

// TestRequiredClaimsProfile verifies that a required-claim profile rejects a
// token missing any required claim, and accepts a token that has them all.
func TestRequiredClaimsProfile(t *testing.T) {
	t.Parallel()

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
	// The access-token profile requires iss, sub, exp, and aud.
	profile := []string{"iss", "sub", "exp", "aud"}

	tests := []struct {
		name    string
		claims  Claims
		wantErr error
	}{
		{
			name: "all required claims present",
			claims: Claims{
				Issuer: "iss", Subject: "sub", Audience: []string{"aud"},
				ExpiresAt: now + 3600, IssuedAt: now,
			},
			wantErr: nil,
		},
		{name: "missing iss", claims: Claims{Subject: "sub", Audience: []string{"aud"}, ExpiresAt: now + 3600}, wantErr: ErrMissingRequiredClaim},
		{name: "missing sub", claims: Claims{Issuer: "iss", Audience: []string{"aud"}, ExpiresAt: now + 3600}, wantErr: ErrMissingRequiredClaim},
		{name: "missing aud", claims: Claims{Issuer: "iss", Subject: "sub", ExpiresAt: now + 3600}, wantErr: ErrMissingRequiredClaim},
		{name: "missing exp", claims: Claims{Issuer: "iss", Subject: "sub", Audience: []string{"aud"}, IssuedAt: now}, wantErr: ErrMissingRequiredClaim},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			token, err := Sign(tt.claims, priv, Options{Algorithm: "EdDSA"})
			if err != nil {
				t.Fatalf("Sign: %v", err)
			}
			_, err = Verify(token, pub, Options{
				Algorithm:      "EdDSA",
				RequiredClaims: profile,
				Now:            func() time.Time { return time.Unix(now+10, 0) },
			})
			if tt.wantErr == nil {
				if err != nil {
					t.Errorf("Verify: got error %v, want nil", err)
				}
			} else if !errors.Is(err, tt.wantErr) {
				t.Errorf("Verify: got error %v, want errors.Is(_, %v)", err, tt.wantErr)
			}
		})
	}
}

// TestOneClockSource verifies that all time-based validation (exp, nbf, iat)
// uses the single opts.Now clock: a token that is valid at one simulated time
// and invalid at another flips correctly, and iat in the future is rejected.
func TestOneClockSource(t *testing.T) {
	t.Parallel()

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

	// exp boundary: valid at exp-1, expired at exp.
	c := Claims{Issuer: "iss", ExpiresAt: now + 100}
	token, err := Sign(c, priv, Options{Algorithm: "EdDSA"})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if _, err := Verify(token, pub, Options{Algorithm: "EdDSA", Now: func() time.Time { return time.Unix(now+99, 0) }}); err != nil {
		t.Errorf("Verify before exp: got error %v, want nil", err)
	}
	if _, err := Verify(token, pub, Options{Algorithm: "EdDSA", Now: func() time.Time { return time.Unix(now+100, 0) }}); !errors.Is(err, ErrExpired) {
		t.Errorf("Verify at exp: got error %v, want errors.Is(_, ErrExpired)", err)
	}

	// nbf boundary: not yet valid before nbf, valid at nbf.
	c = Claims{Issuer: "iss", NotBefore: now + 100, ExpiresAt: now + 1000}
	token, err = Sign(c, priv, Options{Algorithm: "EdDSA"})
	if err != nil {
		t.Fatalf("Sign nbf: %v", err)
	}
	if _, err := Verify(token, pub, Options{Algorithm: "EdDSA", Now: func() time.Time { return time.Unix(now+99, 0) }}); !errors.Is(err, ErrNotYetValid) {
		t.Errorf("Verify before nbf: got error %v, want errors.Is(_, ErrNotYetValid)", err)
	}
	if _, err := Verify(token, pub, Options{Algorithm: "EdDSA", Now: func() time.Time { return time.Unix(now+100, 0) }}); err != nil {
		t.Errorf("Verify at nbf: got error %v, want nil", err)
	}

	// iat in the future is rejected against the same clock.
	c = Claims{Issuer: "iss", IssuedAt: now + 100, ExpiresAt: now + 1000}
	token, err = Sign(c, priv, Options{Algorithm: "EdDSA"})
	if err != nil {
		t.Fatalf("Sign iat: %v", err)
	}
	if _, err := Verify(token, pub, Options{Algorithm: "EdDSA", Now: func() time.Time { return time.Unix(now, 0) }}); !errors.Is(err, ErrNotYetValid) {
		t.Errorf("Verify future iat: got error %v, want errors.Is(_, ErrNotYetValid)", err)
	}
}

// TestVerifyIssuerAndAudience verifies issuer and audience validation produce
// typed errors.
func TestVerifyIssuerAndAudience(t *testing.T) {
	t.Parallel()

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
	c := Claims{Issuer: "real-iss", Audience: []string{"real-aud"}, ExpiresAt: now + 3600}
	token, err := Sign(c, priv, Options{Algorithm: "EdDSA"})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	if _, err := Verify(token, pub, Options{
		Algorithm:      "EdDSA",
		ExpectedIssuer: "wrong-iss",
		Now:            func() time.Time { return time.Unix(now+10, 0) },
	}); !errors.Is(err, ErrIssuer) {
		t.Errorf("Verify wrong issuer: got error %v, want errors.Is(_, %v)", err, ErrIssuer)
	}

	if _, err := Verify(token, pub, Options{
		Algorithm:        "EdDSA",
		ExpectedAudience: []string{"wrong-aud"},
		Now:              func() time.Time { return time.Unix(now+10, 0) },
	}); !errors.Is(err, ErrAudience) {
		t.Errorf("Verify wrong audience: got error %v, want errors.Is(_, %v)", err, ErrAudience)
	}

	// Correct issuer and audience pass.
	if _, err := Verify(token, pub, Options{
		Algorithm:        "EdDSA",
		ExpectedIssuer:   "real-iss",
		ExpectedAudience: []string{"real-aud"},
		Now:              func() time.Time { return time.Unix(now+10, 0) },
	}); err != nil {
		t.Errorf("Verify correct iss/aud: got error %v, want nil", err)
	}
}

// mustMarshalClaims is a test helper that marshals claims to JSON or fails.
func mustMarshalClaims(c Claims) []byte {
	b, err := json.Marshal(c)
	if err != nil {
		panic(fmt.Sprintf("marshal claims: %v", err))
	}
	return b
}
