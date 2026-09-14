package kms

import (
	"context"
	"crypto/sha256"
	"errors"
	"testing"

	"github.com/bperin/trust/crypto/hash"
	"github.com/bperin/trust/crypto/secp256k1"
)

// TestComputeRecoveryID_KnownSignature verifies that for a signature
// produced by secp256k1.SignRecoverable, ComputeRecoveryID finds the
// correct recID (the one SignRecoverable returned) by trying 0–3.
//
// Reference: [SEC 1 v2] §4.3.3 (public-key recovery).
func TestComputeRecoveryID_KnownSignature(t *testing.T) {
	t.Parallel()
	priv, pub, err := secp256k1.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	// Use a Keccak-256 digest (EVM path) and a SHA-256 digest (JOSE
	// path) — recovery is hash-agnostic, only the 32-byte digest
	// matters.
	cases := []struct {
		name   string
		digest [32]byte
	}{
		{"keccak", hash.NewKeccak256().Sum([]byte("evm message"))},
		{"sha256", sha256.Sum256([]byte("jose message"))},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			sig, wantRecID, err := priv.SignRecoverable(tc.digest[:])
			if err != nil {
				t.Fatalf("SignRecoverable: %v", err)
			}

			gotRecID, err := ComputeRecoveryID(sig, tc.digest[:], pub)
			if err != nil {
				t.Fatalf("ComputeRecoveryID: %v", err)
			}
			if gotRecID != wantRecID {
				t.Fatalf("recID: got %d, want %d", gotRecID, wantRecID)
			}

			// The recovered key for the found recID must match pub.
			recovered, err := secp256k1.RecoverPubKey(sig, tc.digest[:], gotRecID)
			if err != nil {
				t.Fatalf("RecoverPubKey: %v", err)
			}
			if !recovered.Equal(pub) {
				t.Fatalf("recovered key mismatch: got %s, want %s",
					recovered.Redact(), pub.Redact())
			}
		})
	}
}

// TestComputeRecoveryID_WrongPublicKey verifies that when the public
// key does not match the signing key, ComputeRecoveryID returns an
// error wrapping ErrNoRecoveryID.
func TestComputeRecoveryID_WrongPublicKey(t *testing.T) {
	t.Parallel()
	priv, pub, err := secp256k1.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	// A second, unrelated key.
	_, otherPub, err := secp256k1.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey (other): %v", err)
	}

	digest := sha256.Sum256([]byte("some message"))
	sig, _, err := priv.SignRecoverable(digest[:])
	if err != nil {
		t.Fatalf("SignRecoverable: %v", err)
	}

	// Against the wrong (other) public key, no recID should match.
	_, err = ComputeRecoveryID(sig, digest[:], otherPub)
	if err == nil {
		t.Fatalf("ComputeRecoveryID with wrong pub: want error, got nil")
	}
	if !errors.Is(err, ErrNoRecoveryID) {
		t.Fatalf("error does not wrap ErrNoRecoveryID: %v", err)
	}

	// Sanity: against the correct pub it succeeds.
	recID, err := ComputeRecoveryID(sig, digest[:], pub)
	if err != nil {
		t.Fatalf("ComputeRecoveryID with correct pub: %v", err)
	}
	if recID > 3 {
		t.Fatalf("recID out of range: %d", recID)
	}
}

// TestComputeRecoveryID_NilPublicKey verifies a nil public key is
// rejected.
func TestComputeRecoveryID_NilPublicKey(t *testing.T) {
	t.Parallel()
	digest := sha256.Sum256([]byte("msg"))
	sig := make([]byte, 64)
	_, err := ComputeRecoveryID(sig, digest[:], nil)
	if err == nil {
		t.Fatalf("ComputeRecoveryID(nil pub): want error, got nil")
	}
}

// TestComputeRecoveryID_BadSignatureLength verifies a non-64-byte
// signature is rejected (RecoverPubKey enforces the length).
func TestComputeRecoveryID_BadSignatureLength(t *testing.T) {
	t.Parallel()
	_, pub, err := secp256k1.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	digest := sha256.Sum256([]byte("msg"))
	_, err = ComputeRecoveryID([]byte("too short"), digest[:], pub)
	if err == nil {
		t.Fatalf("ComputeRecoveryID(short sig): want error, got nil")
	}
}

// TestComputeRecoveryID_MockSignerRoundTrip exercises the full EVM
// path through the mock RemoteSigner: sign → 65-byte r||s||v →
// RecoverPubKey → matches PublicKey().
func TestComputeRecoveryID_MockSignerRoundTrip(t *testing.T) {
	t.Parallel()
	signer := newMockSigner(t)
	ctx := context.Background()

	pub, err := signer.PublicKey(ctx)
	if err != nil {
		t.Fatalf("PublicKey: %v", err)
	}
	digest := hash.NewKeccak256().Sum([]byte("evm round trip"))
	sig, err := signer.Sign(ctx, digest[:], SignOptions{Path: SignPathEVM})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if got, want := len(sig), 65; got != want {
		t.Fatalf("len(sig) = %d, want %d", got, want)
	}

	// The recID embedded in the signature must be the one
	// ComputeRecoveryID would compute independently.
	independentRecID, err := ComputeRecoveryID(sig[:64], digest[:], pub)
	if err != nil {
		t.Fatalf("ComputeRecoveryID: %v", err)
	}
	if sig[64] != independentRecID {
		t.Fatalf("embedded recID %d != computed recID %d", sig[64], independentRecID)
	}

	recovered, err := secp256k1.RecoverPubKey(sig[:64], digest[:], sig[64])
	if err != nil {
		t.Fatalf("RecoverPubKey: %v", err)
	}
	if !recovered.Equal(pub) {
		t.Fatalf("recovered key mismatch: got %s, want %s",
			recovered.Redact(), pub.Redact())
	}
}
