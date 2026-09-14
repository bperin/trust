package signature

import (
	"context"
	"crypto"
	"errors"
	"fmt"
	"os"
	"reflect"
	"sync"
	"testing"

	"github.com/bperin/trust/crypto/ecdsa"
	"github.com/bperin/trust/crypto/ed25519"
	"github.com/bperin/trust/crypto/rsa"
	"github.com/bperin/trust/crypto/secp256k1"
	"github.com/bperin/trust/crypto/x25519"
)

// rsaKeyPool holds pre-generated RSA keyPairs for the round-trip
// table. RSA-2048 key generation is slow enough that regenerating a
// key per test case dominates the suite's runtime, so the cost is
// paid once in TestMain and the pooled keys are shared read-only.
// Guarded by sync.Once so helpers may also seed lazily without
// double-generating.
var (
	rsaKeyPoolOnce sync.Once
	rsaKeyPool     []keyPair
	rsaKeyPoolErr  error
)

// seedRSAKeyPool generates the pooled RSA keys (PSS-SHA256 and
// PKCS1v1.5-SHA256) exactly once. A failure is recorded in
// rsaKeyPoolErr and surfaced by pooledRSAKey.
func seedRSAKeyPool() {
	rsaKeyPoolOnce.Do(func() {
		pssPriv, pssPub, err := rsa.GeneratePSSKey(2048, crypto.SHA256)
		if err != nil {
			rsaKeyPoolErr = fmt.Errorf("rsa.GeneratePSSKey: %w", err)
			return
		}
		pkcs1Priv, pkcs1Pub, err := rsa.GeneratePKCS1Key(2048, crypto.SHA256)
		if err != nil {
			rsaKeyPoolErr = fmt.Errorf("rsa.GeneratePKCS1Key: %w", err)
			return
		}
		rsaKeyPool = []keyPair{
			{priv: pssPriv, pub: pssPub, alg: AlgorithmPS256},
			{priv: pkcs1Priv, pub: pkcs1Pub, alg: AlgorithmRS256},
		}
	})
}

// TestMain seeds the RSA key pool once before the suite runs.
func TestMain(m *testing.M) {
	seedRSAKeyPool()
	os.Exit(m.Run())
}

// pooledRSAKey returns the pooled keyPair for an RSA algorithm,
// failing the test if the pool was not seeded or has no entry.
func pooledRSAKey(t *testing.T, alg Algorithm) keyPair {
	t.Helper()
	seedRSAKeyPool()
	if rsaKeyPoolErr != nil {
		t.Fatalf("RSA key pool seed: %v", rsaKeyPoolErr)
	}
	for _, kp := range rsaKeyPool {
		if kp.alg == alg {
			return kp
		}
	}
	t.Fatalf("no pooled RSA key for %s", alg.JOSE())
	return keyPair{}
}

// TestLocalSigner_RoundTrip verifies that for every registered
// algorithm a LocalSigner (1) exposes the correct concrete trust
// public-key type and (2) produces a signature that Verify accepts.
func TestLocalSigner_RoundTrip(t *testing.T) {
	t.Parallel()

	digest := []byte("trust local-signer round-trip digest")

	tests := []struct {
		name    string
		alg     Algorithm
		keyPair func(t *testing.T) keyPair
		wantPub reflect.Type
	}{
		{
			// Ed25519 — [RFC 8032] §5.1.
			name:    "EdDSA/Ed25519",
			alg:     AlgorithmEdDSA,
			keyPair: func(t *testing.T) keyPair { return generateKeyPair(t, AlgorithmEdDSA) },
			wantPub: reflect.TypeOf((*ed25519.PublicKey)(nil)),
		},
		{
			// secp256k1 — [RFC 8812] §3.1 (ES256K).
			name:    "ES256K/secp256k1",
			alg:     AlgorithmES256K,
			keyPair: func(t *testing.T) keyPair { return generateKeyPair(t, AlgorithmES256K) },
			wantPub: reflect.TypeOf((*secp256k1.PublicKey)(nil)),
		},
		{
			// ECDSA P-256 — [FIPS 186-4] §6.
			name:    "ES256/ECDSA-P256",
			alg:     AlgorithmES256,
			keyPair: func(t *testing.T) keyPair { return generateKeyPair(t, AlgorithmES256) },
			wantPub: reflect.TypeOf((*ecdsa.PublicKey)(nil)),
		},
		{
			// ECDSA P-384 — [FIPS 186-4] §6.
			name:    "ES384/ECDSA-P384",
			alg:     AlgorithmES384,
			keyPair: func(t *testing.T) keyPair { return generateKeyPair(t, AlgorithmES384) },
			wantPub: reflect.TypeOf((*ecdsa.PublicKey)(nil)),
		},
		{
			// RSA-PSS SHA-256 — [RFC 8017] §8.1.
			name:    "PS256/RSA-PSS-SHA256",
			alg:     AlgorithmPS256,
			keyPair: func(t *testing.T) keyPair { return pooledRSAKey(t, AlgorithmPS256) },
			wantPub: reflect.TypeOf((*rsa.PSSPublicKey)(nil)),
		},
		{
			// RSA PKCS#1 v1.5 SHA-256 — [RFC 8017] §8.2.
			name:    "RS256/RSA-PKCS1-SHA256",
			alg:     AlgorithmRS256,
			keyPair: func(t *testing.T) keyPair { return pooledRSAKey(t, AlgorithmRS256) },
			wantPub: reflect.TypeOf((*rsa.PKCS1PublicKey)(nil)),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			kp := tt.keyPair(t)

			signer, err := NewLocalSigner(kp.priv)
			if err != nil {
				t.Fatalf("NewLocalSigner: %v", err)
			}
			if signer == nil {
				t.Fatal("NewLocalSigner returned nil signer")
			}

			pub, err := signer.PublicKey(context.Background())
			if err != nil {
				t.Fatalf("PublicKey: %v", err)
			}
			if got := reflect.TypeOf(pub); got != tt.wantPub {
				t.Errorf("PublicKey type = %v, want %v", got, tt.wantPub)
			}

			sig, err := signer.Sign(context.Background(), digest)
			if err != nil {
				t.Fatalf("Sign: %v", err)
			}
			if len(sig) == 0 {
				t.Fatal("Sign returned empty signature")
			}

			valid, err := Verify(tt.alg, pub, sig, digest)
			if err != nil {
				t.Fatalf("Verify: %v", err)
			}
			if !valid {
				t.Error("Verify returned false for a LocalSigner-produced signature")
			}
		})
	}
}

// TestLocalSigner_Errors verifies that NewLocalSigner rejects nil,
// non-signing (x25519), and unrecognized key types. The unsupported
// cases must wrap ErrUnsupportedAlgorithm.
func TestLocalSigner_Errors(t *testing.T) {
	t.Parallel()

	x25519Priv, _, err := x25519.GenerateKey()
	if err != nil {
		t.Fatalf("x25519.GenerateKey: %v", err)
	}

	tests := []struct {
		name    string
		key     crypto.PrivateKey
		wantErr error // sentinel asserted via errors.Is; nil means "any error"
	}{
		{"nil key", nil, nil},
		{"x25519 non-signing key", x25519Priv, ErrUnsupportedAlgorithm},
		{"unknown key type", crypto.PrivateKey("nope"), ErrUnsupportedAlgorithm},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			signer, err := NewLocalSigner(tt.key)
			if err == nil {
				t.Fatalf("NewLocalSigner(%T) = nil error, want error", tt.key)
			}
			if signer != nil {
				t.Errorf("NewLocalSigner(%T) returned non-nil signer on error", tt.key)
			}
			if tt.wantErr != nil && !errors.Is(err, tt.wantErr) {
				t.Errorf("NewLocalSigner(%T): err = %v, want errors.Is(err, %v)", tt.key, err, tt.wantErr)
			}
		})
	}
}

// TestLocalSigner_ContextCanceled verifies that PublicKey and Sign
// honor the Signer contract by returning ctx.Err() when the context
// is already canceled.
func TestLocalSigner_ContextCanceled(t *testing.T) {
	t.Parallel()

	priv, _, err := ed25519.GenerateKey()
	if err != nil {
		t.Fatalf("ed25519.GenerateKey: %v", err)
	}
	signer, err := NewLocalSigner(priv)
	if err != nil {
		t.Fatalf("NewLocalSigner: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if _, err := signer.PublicKey(ctx); !errors.Is(err, context.Canceled) {
		t.Errorf("PublicKey with canceled ctx: err = %v, want context.Canceled", err)
	}
	if _, err := signer.Sign(ctx, []byte("digest")); !errors.Is(err, context.Canceled) {
		t.Errorf("Sign with canceled ctx: err = %v, want context.Canceled", err)
	}
}
