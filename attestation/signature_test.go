package attestation

import (
	"bytes"
	"context"
	"crypto"
	"crypto/elliptic"
	"errors"
	"testing"
	"time"

	"github.com/bperin/trust/authority"
	"github.com/bperin/trust/crypto/ecdsa"
	"github.com/bperin/trust/crypto/ed25519"
	"github.com/bperin/trust/crypto/rsa"
	"github.com/bperin/trust/crypto/secp256k1"
	"github.com/bperin/trust/signature"
)

// sigKeyPair holds a generated private/public pair for one algorithm.
type sigKeyPair struct {
	priv crypto.PrivateKey
	pub  crypto.PublicKey
	alg  signature.Algorithm
}

// generateSigKeyPair generates a key pair for the given algorithm.
// RSA keys are 2048-bit and bound to SHA-256; ECDSA keys bind curve
// and hash.
func generateSigKeyPair(t *testing.T, alg signature.Algorithm) sigKeyPair {
	t.Helper()
	switch alg {
	case signature.AlgorithmEdDSA:
		priv, pub, err := ed25519.GenerateKey()
		if err != nil {
			t.Fatalf("ed25519.GenerateKey: %v", err)
		}
		return sigKeyPair{priv: priv, pub: pub, alg: alg}
	case signature.AlgorithmES256K:
		priv, pub, err := secp256k1.GenerateKey()
		if err != nil {
			t.Fatalf("secp256k1.GenerateKey: %v", err)
		}
		return sigKeyPair{priv: priv, pub: pub, alg: alg}
	case signature.AlgorithmES256:
		priv, pub, err := ecdsa.GenerateKey(elliptic.P256(), crypto.SHA256)
		if err != nil {
			t.Fatalf("ecdsa.GenerateKey: %v", err)
		}
		return sigKeyPair{priv: priv, pub: pub, alg: alg}
	case signature.AlgorithmES384:
		priv, pub, err := ecdsa.GenerateKey(elliptic.P384(), crypto.SHA384)
		if err != nil {
			t.Fatalf("ecdsa.GenerateKey: %v", err)
		}
		return sigKeyPair{priv: priv, pub: pub, alg: alg}
	case signature.AlgorithmPS256:
		priv, pub, err := rsa.GeneratePSSKey(2048, crypto.SHA256)
		if err != nil {
			t.Fatalf("rsa.GeneratePSSKey: %v", err)
		}
		return sigKeyPair{priv: priv, pub: pub, alg: alg}
	case signature.AlgorithmRS256:
		priv, pub, err := rsa.GeneratePKCS1Key(2048, crypto.SHA256)
		if err != nil {
			t.Fatalf("rsa.GeneratePKCS1Key: %v", err)
		}
		return sigKeyPair{priv: priv, pub: pub, alg: alg}
	default:
		t.Fatalf("no key generation for %s", alg.JOSE())
		return sigKeyPair{}
	}
}

// mockSigner is a test-only signature.Signer backed by a fixed
// public key and a canned signature. It proves SignAttestation
// depends on the Signer interface alone — never on a concrete key
// type or on kms/.
type mockSigner struct {
	pub crypto.PublicKey
	sig []byte
}

func (m *mockSigner) PublicKey(context.Context) (crypto.PublicKey, error) { return m.pub, nil }
func (m *mockSigner) Sign(context.Context, []byte) ([]byte, error)        { return m.sig, nil }

// TestSignVerify_RoundTrip verifies that for every registered
// algorithm a LocalSigner-signed attestation verifies against its
// public key, that the recorded algorithm matches the signer's key,
// and that signing leaves the canonical hash unchanged.
func TestSignVerify_RoundTrip(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		alg  signature.Algorithm
	}{
		// Ed25519 — [RFC 8037], [FIPS 186-5] §7.
		{"EdDSA/Ed25519", signature.AlgorithmEdDSA},
		// secp256k1 — [SEC 2 v2], [RFC 6979], [EIP-2]; ES256K per [RFC 8812].
		{"ES256K/secp256k1", signature.AlgorithmES256K},
		// ECDSA P-256 — [FIPS 186-4] §6.
		{"ES256/ECDSA-P256", signature.AlgorithmES256},
		// ECDSA P-384 — [FIPS 186-4] §6.
		{"ES384/ECDSA-P384", signature.AlgorithmES384},
		// RSA-PSS SHA-256 — [RFC 8017] §8.1.
		{"PS256/RSA-PSS-SHA256", signature.AlgorithmPS256},
		// RSA PKCS#1 v1.5 SHA-256 — [RFC 8017] §8.2.
		{"RS256/RSA-PKCS1-SHA256", signature.AlgorithmRS256},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			kp := generateSigKeyPair(t, tt.alg)
			signer, err := signature.NewLocalSigner(kp.priv)
			if err != nil {
				t.Fatalf("NewLocalSigner: %v", err)
			}

			att := testAttestation(t)
			att.Signature = []byte{0xde, 0xad} // stale signature to clear
			// Fields signing will set are pre-set so the only delta
			// across signing is the signature itself.
			att.Algorithm = tt.alg
			att.SigningKeyID = "leaf-key-1"
			unsignedHash, err := CanonicalHash(att)
			if err != nil {
				t.Fatalf("CanonicalHash(unsigned): %v", err)
			}

			if err := SignAttestation(context.Background(), att, signer, "leaf-key-1"); err != nil {
				t.Fatalf("SignAttestation: %v", err)
			}
			if att.Algorithm != tt.alg {
				t.Fatalf("Algorithm = %s, want %s", att.Algorithm.JOSE(), tt.alg.JOSE())
			}
			if att.SigningKeyID != "leaf-key-1" {
				t.Fatalf("SigningKeyID = %q, want %q", att.SigningKeyID, "leaf-key-1")
			}
			if len(att.Signature) == 0 {
				t.Fatal("SignAttestation left Signature empty")
			}
			if bytes.Equal(att.Signature, []byte{0xde, 0xad}) {
				t.Fatal("SignAttestation did not replace the stale signature")
			}
			signedHash, err := CanonicalHash(att)
			if err != nil {
				t.Fatalf("CanonicalHash(signed): %v", err)
			}
			if !hashEqual(unsignedHash, signedHash) {
				t.Fatal("signing changed the canonical hash — signature is not excluded from identity")
			}

			if err := VerifySignature(att, kp.pub); err != nil {
				t.Fatalf("VerifySignature: %v", err)
			}
		})
	}
}

// TestSignAttestation_MockSigner proves signer-agnosticism: a
// test-only signature.Signer with a fixed public key and canned
// signature is accepted, and att.Algorithm is derived from the
// mock's key — not from any concrete signer type.
func TestSignAttestation_MockSigner(t *testing.T) {
	t.Parallel()

	kp := generateSigKeyPair(t, signature.AlgorithmEdDSA)
	mock := &mockSigner{pub: kp.pub, sig: []byte{0x01, 0x02, 0x03}}

	att := testAttestation(t)
	if err := SignAttestation(context.Background(), att, mock, ""); err != nil {
		t.Fatalf("SignAttestation(mock): %v", err)
	}
	if att.Algorithm != signature.AlgorithmEdDSA {
		t.Fatalf("Algorithm = %s, want EdDSA", att.Algorithm.JOSE())
	}
	if !bytes.Equal(att.Signature, mock.sig) {
		t.Fatalf("Signature = %x, want the mock's canned signature %x", att.Signature, mock.sig)
	}
	// An empty keyID must leave an existing SigningKeyID untouched.
	if att.SigningKeyID != "leaf-key-1" {
		t.Fatalf("SigningKeyID = %q, want the pre-set value preserved for empty keyID", att.SigningKeyID)
	}
}

// TestSignAttestation_KeyID asserts a non-empty keyID is recorded on
// the attestation.
func TestSignAttestation_KeyID(t *testing.T) {
	t.Parallel()

	kp := generateSigKeyPair(t, signature.AlgorithmEdDSA)
	signer, err := signature.NewLocalSigner(kp.priv)
	if err != nil {
		t.Fatalf("NewLocalSigner: %v", err)
	}

	att := testAttestation(t)
	if err := SignAttestation(context.Background(), att, signer, "leaf-key-42"); err != nil {
		t.Fatalf("SignAttestation: %v", err)
	}
	if att.SigningKeyID != "leaf-key-42" {
		t.Fatalf("SigningKeyID = %q, want %q", att.SigningKeyID, "leaf-key-42")
	}
}

// TestVerifySignature_Tampered proves that mutating any hashed field
// after signing fails verification with ErrTamperedAttestation.
func TestVerifySignature_Tampered(t *testing.T) {
	t.Parallel()

	mutations := []struct {
		name   string
		mutate func(a *Attestation)
	}{
		{"Issuer", func(a *Attestation) { a.Issuer = "did:example:other" }},
		{"Capability", func(a *Attestation) { a.Capability = authority.CapabilitySign }},
		{"Evidence entry", func(a *Attestation) { a.Evidence[0].Identifier = "ev-tampered" }},
		{"Validity", func(a *Attestation) { a.Validity.NotAfter = a.Validity.NotAfter.Add(time.Hour) }},
		{"Status", func(a *Attestation) { a.Status = authority.StatusRevoked }},
	}
	for _, tc := range mutations {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			kp := generateSigKeyPair(t, signature.AlgorithmEdDSA)
			signer, err := signature.NewLocalSigner(kp.priv)
			if err != nil {
				t.Fatalf("NewLocalSigner: %v", err)
			}
			att := testAttestation(t)
			if err := SignAttestation(context.Background(), att, signer, "leaf-key-1"); err != nil {
				t.Fatalf("SignAttestation: %v", err)
			}
			tc.mutate(att)
			if err := VerifySignature(att, kp.pub); !errors.Is(err, ErrTamperedAttestation) {
				t.Fatalf("VerifySignature(tampered %s): got %v, want ErrTamperedAttestation", tc.name, err)
			}
		})
	}
}

// TestVerifySignature_WrongAlgorithmKey proves the algorithm-confusion
// defense: a key of a different algorithm is rejected with
// ErrWrongKey even before any signature bytes are examined.
func TestVerifySignature_WrongAlgorithmKey(t *testing.T) {
	t.Parallel()

	kp := generateSigKeyPair(t, signature.AlgorithmEdDSA)
	signer, err := signature.NewLocalSigner(kp.priv)
	if err != nil {
		t.Fatalf("NewLocalSigner: %v", err)
	}
	att := testAttestation(t)
	if err := SignAttestation(context.Background(), att, signer, "leaf-key-1"); err != nil {
		t.Fatalf("SignAttestation: %v", err)
	}

	_, otherPub, err := secp256k1.GenerateKey()
	if err != nil {
		t.Fatalf("secp256k1.GenerateKey: %v", err)
	}
	if err := VerifySignature(att, otherPub); !errors.Is(err, ErrWrongKey) {
		t.Fatalf("VerifySignature(wrong-algorithm key): got %v, want ErrWrongKey", err)
	}
}

// TestVerifySignature_WrongSameAlgorithmKey proves that a valid key
// of the same algorithm that did not produce the signature yields
// ErrTamperedAttestation.
func TestVerifySignature_WrongSameAlgorithmKey(t *testing.T) {
	t.Parallel()

	kp := generateSigKeyPair(t, signature.AlgorithmEdDSA)
	signer, err := signature.NewLocalSigner(kp.priv)
	if err != nil {
		t.Fatalf("NewLocalSigner: %v", err)
	}
	att := testAttestation(t)
	if err := SignAttestation(context.Background(), att, signer, "leaf-key-1"); err != nil {
		t.Fatalf("SignAttestation: %v", err)
	}

	otherPriv, otherPub, err := ed25519.GenerateKey()
	if err != nil {
		t.Fatalf("ed25519.GenerateKey: %v", err)
	}
	firstPub := kp.priv.(*ed25519.PrivateKey).Public().Bytes()
	otherPubBytes := otherPriv.Public().Bytes()
	if firstPub == otherPubBytes {
		t.Fatal("test setup: generated the same ed25519 key twice")
	}
	if err := VerifySignature(att, otherPub); !errors.Is(err, ErrTamperedAttestation) {
		t.Fatalf("VerifySignature(wrong same-algorithm key): got %v, want ErrTamperedAttestation", err)
	}
}

// TestSignAttestation_Nil asserts the nil-input rejections.
func TestSignAttestation_Nil(t *testing.T) {
	t.Parallel()

	kp := generateSigKeyPair(t, signature.AlgorithmEdDSA)
	signer, err := signature.NewLocalSigner(kp.priv)
	if err != nil {
		t.Fatalf("NewLocalSigner: %v", err)
	}

	if err := SignAttestation(context.Background(), nil, signer, "k"); !errors.Is(err, ErrNilAttestation) {
		t.Fatalf("SignAttestation(nil att): got %v, want ErrNilAttestation", err)
	}
	if err := SignAttestation(context.Background(), testAttestation(t), nil, "k"); err == nil {
		t.Fatal("SignAttestation(nil signer): got nil, want an error")
	}
}

// TestVerifySignature_Nil asserts the nil-attestation rejection.
func TestVerifySignature_Nil(t *testing.T) {
	t.Parallel()

	_, pub, err := ed25519.GenerateKey()
	if err != nil {
		t.Fatalf("ed25519.GenerateKey: %v", err)
	}
	if err := VerifySignature(nil, pub); !errors.Is(err, ErrNilAttestation) {
		t.Fatalf("VerifySignature(nil): got %v, want ErrNilAttestation", err)
	}
}

// TestSignAttestation_ResignDeterministic asserts re-signing an
// already-signed attestation clears the stale signature first and
// produces a signature that verifies.
func TestSignAttestation_ResignDeterministic(t *testing.T) {
	t.Parallel()

	kp := generateSigKeyPair(t, signature.AlgorithmEdDSA)
	signer, err := signature.NewLocalSigner(kp.priv)
	if err != nil {
		t.Fatalf("NewLocalSigner: %v", err)
	}

	att := testAttestation(t)
	if err := SignAttestation(context.Background(), att, signer, "leaf-key-1"); err != nil {
		t.Fatalf("SignAttestation(first): %v", err)
	}
	if len(att.Signature) == 0 {
		t.Fatal("first sign left Signature empty")
	}

	att.Signature = []byte{0x00, 0xff, 0x00} // garbage stale signature
	if err := SignAttestation(context.Background(), att, signer, "leaf-key-1"); err != nil {
		t.Fatalf("SignAttestation(re-sign): %v", err)
	}
	if len(att.Signature) == 0 {
		t.Fatal("re-sign left Signature empty")
	}
	if err := VerifySignature(att, kp.pub); err != nil {
		t.Fatalf("VerifySignature(re-signed): %v", err)
	}
}

// TestSignAttestation_DistinctAlgorithms asserts each registry
// algorithm records its own distinct att.Algorithm after signing.
func TestSignAttestation_DistinctAlgorithms(t *testing.T) {
	t.Parallel()

	algs := []signature.Algorithm{
		signature.AlgorithmEdDSA,
		signature.AlgorithmES256K,
		signature.AlgorithmES256,
		signature.AlgorithmES384,
		signature.AlgorithmPS256,
		signature.AlgorithmRS256,
	}
	seen := make(map[signature.Algorithm]bool, len(algs))
	for _, alg := range algs {
		kp := generateSigKeyPair(t, alg)
		signer, err := signature.NewLocalSigner(kp.priv)
		if err != nil {
			t.Fatalf("NewLocalSigner(%s): %v", alg.JOSE(), err)
		}
		att := testAttestation(t)
		if err := SignAttestation(context.Background(), att, signer, "k"); err != nil {
			t.Fatalf("SignAttestation(%s): %v", alg.JOSE(), err)
		}
		if att.Algorithm != alg {
			t.Fatalf("Algorithm = %s, want %s", att.Algorithm.JOSE(), alg.JOSE())
		}
		if seen[att.Algorithm] {
			t.Fatalf("algorithm %s recorded twice — not distinct", att.Algorithm.JOSE())
		}
		seen[att.Algorithm] = true
	}
}
