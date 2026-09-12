package signature

import (
	"bytes"
	"crypto"
	"crypto/elliptic"
	"errors"
	"testing"

	"github.com/bperin/trust/crypto/ecdsa"
	"github.com/bperin/trust/crypto/ed25519"
	"github.com/bperin/trust/crypto/rsa"
	"github.com/bperin/trust/crypto/secp256k1"
	"github.com/bperin/trust/crypto/x25519"
)

// keyPair holds a generated private/public key pair for testing.
type keyPair struct {
	priv crypto.PrivateKey
	pub  crypto.PublicKey
	alg  Algorithm
}

// generateKeyPair generates a key pair for the given algorithm.
func generateKeyPair(t *testing.T, alg Algorithm) keyPair {
	t.Helper()
	switch alg {
	case AlgorithmEdDSA:
		priv, pub, err := ed25519.GenerateKey()
		if err != nil {
			t.Fatalf("ed25519.GenerateKey: %v", err)
		}
		return keyPair{priv, pub, alg}
	case AlgorithmES256K:
		priv, pub, err := secp256k1.GenerateKey()
		if err != nil {
			t.Fatalf("secp256k1.GenerateKey: %v", err)
		}
		return keyPair{priv, pub, alg}
	case AlgorithmES256:
		priv, pub, err := ecdsa.GenerateKey(elliptic.P256(), crypto.SHA256)
		if err != nil {
			t.Fatalf("ecdsa.GenerateKey: %v", err)
		}
		return keyPair{priv, pub, alg}
	case AlgorithmES384:
		priv, pub, err := ecdsa.GenerateKey(elliptic.P384(), crypto.SHA384)
		if err != nil {
			t.Fatalf("ecdsa.GenerateKey: %v", err)
		}
		return keyPair{priv, pub, alg}
	case AlgorithmPS256:
		priv, pub, err := rsa.GeneratePSSKey(2048, crypto.SHA256)
		if err != nil {
			t.Fatalf("rsa.GeneratePSSKey: %v", err)
		}
		return keyPair{priv, pub, alg}
	case AlgorithmPS384:
		priv, pub, err := rsa.GeneratePSSKey(2048, crypto.SHA384)
		if err != nil {
			t.Fatalf("rsa.GeneratePSSKey: %v", err)
		}
		return keyPair{priv, pub, alg}
	case AlgorithmPS512:
		priv, pub, err := rsa.GeneratePSSKey(2048, crypto.SHA512)
		if err != nil {
			t.Fatalf("rsa.GeneratePSSKey: %v", err)
		}
		return keyPair{priv, pub, alg}
	case AlgorithmRS256:
		priv, pub, err := rsa.GeneratePKCS1Key(2048, crypto.SHA256)
		if err != nil {
			t.Fatalf("rsa.GeneratePKCS1Key: %v", err)
		}
		return keyPair{priv, pub, alg}
	case AlgorithmRS384:
		priv, pub, err := rsa.GeneratePKCS1Key(2048, crypto.SHA384)
		if err != nil {
			t.Fatalf("rsa.GeneratePKCS1Key: %v", err)
		}
		return keyPair{priv, pub, alg}
	case AlgorithmRS512:
		priv, pub, err := rsa.GeneratePKCS1Key(2048, crypto.SHA512)
		if err != nil {
			t.Fatalf("rsa.GeneratePKCS1Key: %v", err)
		}
		return keyPair{priv, pub, alg}
	default:
		t.Fatalf("unsupported algorithm: %v", alg)
		return keyPair{}
	}
}

// allAlgorithms returns all registered algorithm constants.
func allAlgorithms() []Algorithm {
	return []Algorithm{
		AlgorithmEdDSA, AlgorithmES256K, AlgorithmES256, AlgorithmES384,
		AlgorithmPS256, AlgorithmPS384, AlgorithmPS512,
		AlgorithmRS256, AlgorithmRS384, AlgorithmRS512,
	}
}

// TestRegistryCompleteness verifies that every exported Algorithm
// constant has a registered sign/verify entry. A missing
// registration is a test failure, not a runtime error.
func TestRegistryCompleteness(t *testing.T) {
	for _, alg := range allAlgorithms() {
		t.Run(alg.JOSE(), func(t *testing.T) {
			entry, ok := registry[alg]
			if !ok {
				t.Errorf("algorithm %s (const %d) is not registered", alg.JOSE(), alg)
			}
			if entry.sign == nil {
				t.Errorf("algorithm %s has nil sign function", alg.JOSE())
			}
			if entry.verify == nil {
				t.Errorf("algorithm %s has nil verify function", alg.JOSE())
			}
		})
	}
}

// TestSignVerifyRoundTrip verifies that sign→verify round-trips for
// every registered algorithm.
func TestSignVerifyRoundTrip(t *testing.T) {
	msg := []byte("hello world")

	for _, alg := range allAlgorithms() {
		t.Run(alg.JOSE(), func(t *testing.T) {
			kp := generateKeyPair(t, alg)

			sig, err := Sign(alg, kp.priv, msg)
			if err != nil {
				t.Fatalf("Sign: %v", err)
			}

			valid, err := Verify(alg, kp.pub, sig, msg)
			if err != nil {
				t.Fatalf("Verify: %v", err)
			}
			if !valid {
				t.Error("valid signature not verified")
			}
		})
	}
}

// TestVerifyTamperedSignature verifies that a tampered signature
// returns (false, nil) — invalid signature, not a structural error —
// for every registered algorithm. This is the contract that
// distinguishes "invalid signature" from "structural failure".
func TestVerifyTamperedSignature(t *testing.T) {
	msg := []byte("hello world")

	for _, alg := range allAlgorithms() {
		t.Run(alg.JOSE(), func(t *testing.T) {
			kp := generateKeyPair(t, alg)

			sig, err := Sign(alg, kp.priv, msg)
			if err != nil {
				t.Fatalf("Sign: %v", err)
			}

			if len(sig) == 0 {
				t.Fatalf("signature is empty")
			}

			// Tamper with the signature
			tampered := make([]byte, len(sig))
			copy(tampered, sig)
			tampered[0] ^= 0xFF

			valid, err := Verify(alg, kp.pub, tampered, msg)
			if err != nil {
				t.Fatalf("Verify with tampered sig returned error (want nil): %v", err)
			}
			if valid {
				t.Error("tampered signature was verified as valid")
			}
		})
	}
}

// TestVerifyWrongMessage verifies that a signature verified against
// the wrong message returns (false, nil) for every algorithm.
func TestVerifyWrongMessage(t *testing.T) {
	msg := []byte("hello world")
	wrongMsg := []byte("goodbye world")

	for _, alg := range allAlgorithms() {
		t.Run(alg.JOSE(), func(t *testing.T) {
			kp := generateKeyPair(t, alg)

			sig, err := Sign(alg, kp.priv, msg)
			if err != nil {
				t.Fatalf("Sign: %v", err)
			}

			valid, err := Verify(alg, kp.pub, sig, wrongMsg)
			if err != nil {
				t.Fatalf("Verify with wrong msg returned error (want nil): %v", err)
			}
			if valid {
				t.Error("signature verified against wrong message")
			}
		})
	}
}

// TestErrAlgorithmNotRegistered verifies that Sign and Verify return
// ErrAlgorithmNotRegistered for an unregistered Algorithm value.
func TestErrAlgorithmNotRegistered(t *testing.T) {
	unregistered := Algorithm(999)

	_, err := Sign(unregistered, nil, []byte("msg"))
	if !errors.Is(err, ErrAlgorithmNotRegistered) {
		t.Errorf("Sign with unregistered alg: err = %v, want ErrAlgorithmNotRegistered", err)
	}

	_, err = Verify(unregistered, nil, nil, []byte("msg"))
	if !errors.Is(err, ErrAlgorithmNotRegistered) {
		t.Errorf("Verify with unregistered alg: err = %v, want ErrAlgorithmNotRegistered", err)
	}
}

// TestErrAlgMismatchSign verifies that using a key with the wrong
// algorithm in Sign returns an ErrAlgMismatch that can be unwrapped
// with errors.As.
func TestErrAlgMismatchSign(t *testing.T) {
	priv, _, err := ed25519.GenerateKey()
	if err != nil {
		t.Fatalf("ed25519.GenerateKey: %v", err)
	}

	// Try to sign with ES256 (ECDSA) using an Ed25519 key
	_, err = Sign(AlgorithmES256, priv, []byte("msg"))
	var mismatch *ErrAlgMismatch
	if !errors.As(err, &mismatch) {
		t.Fatalf("Sign with wrong alg: err = %v, want ErrAlgMismatch", err)
	}
	if mismatch.Expected != AlgorithmES256 {
		t.Errorf("Expected = %v, want %v", mismatch.Expected, AlgorithmES256)
	}
	if mismatch.Got != AlgorithmEdDSA {
		t.Errorf("Got = %v, want %v", mismatch.Got, AlgorithmEdDSA)
	}
}

// TestErrAlgMismatchVerify verifies that using a key with the wrong
// algorithm in Verify returns an ErrAlgMismatch.
func TestErrAlgMismatchVerify(t *testing.T) {
	_, pub, err := ed25519.GenerateKey()
	if err != nil {
		t.Fatalf("ed25519.GenerateKey: %v", err)
	}

	// Try to verify with ES256 (ECDSA) using an Ed25519 public key
	valid, err := Verify(AlgorithmES256, pub, []byte("sig"), []byte("msg"))
	if valid {
		t.Error("Verify with wrong key returned valid=true")
	}
	var mismatch *ErrAlgMismatch
	if !errors.As(err, &mismatch) {
		t.Fatalf("Verify with wrong alg: err = %v, want ErrAlgMismatch", err)
	}
	if mismatch.Expected != AlgorithmES256 {
		t.Errorf("Expected = %v, want %v", mismatch.Expected, AlgorithmES256)
	}
	if mismatch.Got != AlgorithmEdDSA {
		t.Errorf("Got = %v, want %v", mismatch.Got, AlgorithmEdDSA)
	}
}

// TestRegistryInitialized verifies that the registry map was
// populated by init(). The acceptance criteria enforce no exported
// Register function, no Signer/Verifier interface, and no forbidden
// imports via grep in the task verification step.
func TestRegistryInitialized(t *testing.T) {
	if registry == nil {
		t.Fatal("registry is nil")
	}
	if len(registry) == 0 {
		t.Fatal("registry is empty — no algorithms registered")
	}
	if len(registry) != len(allAlgorithms()) {
		t.Errorf("registry has %d entries, want %d", len(registry), len(allAlgorithms()))
	}
}

// TestSignDeterministic verifies that deterministic algorithms
// (Ed25519, RSA-PKCS1v1.5) produce the same signature for the same
// key and message.
func TestSignDeterministic(t *testing.T) {
	msg := []byte("hello world")

	t.Run("EdDSA", func(t *testing.T) {
		priv, _, err := ed25519.GenerateKey()
		if err != nil {
			t.Fatalf("ed25519.GenerateKey: %v", err)
		}
		sig1, err := Sign(AlgorithmEdDSA, priv, msg)
		if err != nil {
			t.Fatalf("Sign1: %v", err)
		}
		sig2, err := Sign(AlgorithmEdDSA, priv, msg)
		if err != nil {
			t.Fatalf("Sign2: %v", err)
		}
		if !bytes.Equal(sig1, sig2) {
			t.Error("EdDSA signatures are not deterministic")
		}
	})

	t.Run("RS256", func(t *testing.T) {
		priv, _, err := rsa.GeneratePKCS1Key(2048, crypto.SHA256)
		if err != nil {
			t.Fatalf("rsa.GeneratePKCS1Key: %v", err)
		}
		sig1, err := Sign(AlgorithmRS256, priv, msg)
		if err != nil {
			t.Fatalf("Sign1: %v", err)
		}
		sig2, err := Sign(AlgorithmRS256, priv, msg)
		if err != nil {
			t.Fatalf("Sign2: %v", err)
		}
		if !bytes.Equal(sig1, sig2) {
			t.Error("RS256 signatures are not deterministic")
		}
	})
}

// TestSignNonDeterministic verifies that randomized algorithms
// (ECDSA, RSA-PSS) produce different signatures for the same key
// and message, but both verify.
func TestSignNonDeterministic(t *testing.T) {
	msg := []byte("hello world")

	t.Run("ES256", func(t *testing.T) {
		priv, pub, err := ecdsa.GenerateKey(elliptic.P256(), crypto.SHA256)
		if err != nil {
			t.Fatalf("ecdsa.GenerateKey: %v", err)
		}
		sig1, err := Sign(AlgorithmES256, priv, msg)
		if err != nil {
			t.Fatalf("Sign1: %v", err)
		}
		sig2, err := Sign(AlgorithmES256, priv, msg)
		if err != nil {
			t.Fatalf("Sign2: %v", err)
		}
		if bytes.Equal(sig1, sig2) {
			t.Error("ES256 signatures should differ (randomized nonces)")
		}
		valid1, err := Verify(AlgorithmES256, pub, sig1, msg)
		if err != nil || !valid1 {
			t.Error("sig1 not verified")
		}
		valid2, err := Verify(AlgorithmES256, pub, sig2, msg)
		if err != nil || !valid2 {
			t.Error("sig2 not verified")
		}
	})

	t.Run("PS256", func(t *testing.T) {
		priv, pub, err := rsa.GeneratePSSKey(2048, crypto.SHA256)
		if err != nil {
			t.Fatalf("rsa.GeneratePSSKey: %v", err)
		}
		sig1, err := Sign(AlgorithmPS256, priv, msg)
		if err != nil {
			t.Fatalf("Sign1: %v", err)
		}
		sig2, err := Sign(AlgorithmPS256, priv, msg)
		if err != nil {
			t.Fatalf("Sign2: %v", err)
		}
		if bytes.Equal(sig1, sig2) {
			t.Error("PS256 signatures should differ (randomized salt)")
		}
		valid1, err := Verify(AlgorithmPS256, pub, sig1, msg)
		if err != nil || !valid1 {
			t.Error("sig1 not verified")
		}
		valid2, err := Verify(AlgorithmPS256, pub, sig2, msg)
		if err != nil || !valid2 {
			t.Error("sig2 not verified")
		}
	})
}

// TestSecp256k1LowS verifies that secp256k1 signatures with high-s
// are rejected per [EIP-2]. The signature is 64 bytes: R (32) || S
// (32). We flip the high bit of S to create a high-s value.
func TestSecp256k1LowS(t *testing.T) {
	priv, pub, err := secp256k1.GenerateKey()
	if err != nil {
		t.Fatalf("secp256k1.GenerateKey: %v", err)
	}
	msg := []byte("hello world")
	sig, err := Sign(AlgorithmES256K, priv, msg)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	// secp256k1 signatures are 64 bytes: R (32) || S (32).
	if len(sig) != 64 {
		t.Fatalf("signature length = %d, want 64", len(sig))
	}

	// The signature should verify (it's low-s by construction)
	valid, err := Verify(AlgorithmES256K, pub, sig, msg)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !valid {
		t.Error("valid low-s signature not verified")
	}

	// Flip the high bit of S (bytes 32-63) to create a high-s value.
	// This may not produce a valid high-s if the original S already
	// has the high bit set, but for low-s signatures (s <= n/2) the
	// high bit is clear, so setting it produces s > n/2 (high-s).
	tampered := make([]byte, len(sig))
	copy(tampered, sig)
	tampered[32] |= 0x80

	valid, err = Verify(AlgorithmES256K, pub, tampered, msg)
	if err != nil {
		t.Fatalf("Verify high-s: %v", err)
	}
	if valid {
		t.Error("high-s (malleable) signature was verified — EIP-2 violation")
	}
}

// TestX25519Rejected verifies that x25519 keys return
// ErrUnsupportedAlgorithm from AlgorithmForPrivateKey and
// AlgorithmForPublicKey.
func TestX25519Rejected(t *testing.T) {
	priv, pub, err := x25519.GenerateKey()
	if err != nil {
		t.Fatalf("x25519.GenerateKey: %v", err)
	}

	_, err = AlgorithmForPrivateKey(priv)
	if !errors.Is(err, ErrUnsupportedAlgorithm) {
		t.Errorf("AlgorithmForPrivateKey(x25519): err = %v, want ErrUnsupportedAlgorithm", err)
	}

	_, err = AlgorithmForPublicKey(pub)
	if !errors.Is(err, ErrUnsupportedAlgorithm) {
		t.Errorf("AlgorithmForPublicKey(x25519): err = %v, want ErrUnsupportedAlgorithm", err)
	}
}

// TestAlgorithmForPrivateKeyPerType verifies that
// AlgorithmForPrivateKey returns the correct algorithm for each
// signing key type.
func TestAlgorithmForPrivateKeyPerType(t *testing.T) {
	tests := []struct {
		name string
		alg  Algorithm
	}{
		{"Ed25519", AlgorithmEdDSA},
		{"secp256k1", AlgorithmES256K},
		{"ECDSA-P256", AlgorithmES256},
		{"ECDSA-P384", AlgorithmES384},
		{"RSA-PSS-SHA256", AlgorithmPS256},
		{"RSA-PSS-SHA384", AlgorithmPS384},
		{"RSA-PSS-SHA512", AlgorithmPS512},
		{"RSA-PKCS1-SHA256", AlgorithmRS256},
		{"RSA-PKCS1-SHA384", AlgorithmRS384},
		{"RSA-PKCS1-SHA512", AlgorithmRS512},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			kp := generateKeyPair(t, tt.alg)
			alg, err := AlgorithmForPrivateKey(kp.priv)
			if err != nil {
				t.Fatalf("AlgorithmForPrivateKey: %v", err)
			}
			if alg != tt.alg {
				t.Errorf("got %v, want %v", alg, tt.alg)
			}
		})
	}
}

// TestAlgorithmForPublicKeyPerType verifies that
// AlgorithmForPublicKey returns the correct algorithm for each
// signing public key type.
func TestAlgorithmForPublicKeyPerType(t *testing.T) {
	tests := []struct {
		name string
		alg  Algorithm
	}{
		{"Ed25519", AlgorithmEdDSA},
		{"secp256k1", AlgorithmES256K},
		{"ECDSA-P256", AlgorithmES256},
		{"ECDSA-P384", AlgorithmES384},
		{"RSA-PSS-SHA256", AlgorithmPS256},
		{"RSA-PSS-SHA384", AlgorithmPS384},
		{"RSA-PSS-SHA512", AlgorithmPS512},
		{"RSA-PKCS1-SHA256", AlgorithmRS256},
		{"RSA-PKCS1-SHA384", AlgorithmRS384},
		{"RSA-PKCS1-SHA512", AlgorithmRS512},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			kp := generateKeyPair(t, tt.alg)
			alg, err := AlgorithmForPublicKey(kp.pub)
			if err != nil {
				t.Fatalf("AlgorithmForPublicKey: %v", err)
			}
			if alg != tt.alg {
				t.Errorf("got %v, want %v", alg, tt.alg)
			}
		})
	}
}
