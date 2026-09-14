package authority

import (
	"context"
	"crypto"
	"crypto/elliptic"
	"crypto/subtle"
	"errors"
	"testing"

	"github.com/bperin/trust/crypto/ecdsa"
	"github.com/bperin/trust/crypto/ed25519"
	"github.com/bperin/trust/crypto/rsa"
	"github.com/bperin/trust/crypto/secp256k1"
	"github.com/bperin/trust/signature"
)

// Purity: this file exercises SignAuthority and VerifyAuthorityProof
// entirely through in-memory inputs — signature.LocalSigner over
// freshly generated keys and a test-only mock implementing
// signature.Signer. It deliberately imports no network (net,
// net/http), filesystem (os, io/fs, path/filepath), or environment
// packages: VerifyAuthorityProof is a pure function and needs none.
// The authority package also imports no kms/ — the proof path depends
// on the signature.Signer interface alone, which the mock proves.

// keyPair holds a generated private/public pair for one algorithm.
type keyPair struct {
	priv crypto.PrivateKey
	pub  crypto.PublicKey
	alg  signature.Algorithm
}

// generateKeyPair generates a key pair for the given algorithm.
// Mirrors the signature package's test helper: RSA keys are 2048-bit
// and bound to SHA-256; ECDSA keys bind curve and hash.
func generateKeyPair(t *testing.T, alg signature.Algorithm) keyPair {
	t.Helper()
	switch alg {
	case signature.AlgorithmEdDSA:
		priv, pub, err := ed25519.GenerateKey()
		if err != nil {
			t.Fatalf("ed25519.GenerateKey: %v", err)
		}
		return keyPair{priv: priv, pub: pub, alg: alg}
	case signature.AlgorithmES256K:
		priv, pub, err := secp256k1.GenerateKey()
		if err != nil {
			t.Fatalf("secp256k1.GenerateKey: %v", err)
		}
		return keyPair{priv: priv, pub: pub, alg: alg}
	case signature.AlgorithmES256:
		priv, pub, err := ecdsa.GenerateKey(elliptic.P256(), crypto.SHA256)
		if err != nil {
			t.Fatalf("ecdsa.GenerateKey: %v", err)
		}
		return keyPair{priv: priv, pub: pub, alg: alg}
	case signature.AlgorithmES384:
		priv, pub, err := ecdsa.GenerateKey(elliptic.P384(), crypto.SHA384)
		if err != nil {
			t.Fatalf("ecdsa.GenerateKey: %v", err)
		}
		return keyPair{priv: priv, pub: pub, alg: alg}
	case signature.AlgorithmPS256:
		priv, pub, err := rsa.GeneratePSSKey(2048, crypto.SHA256)
		if err != nil {
			t.Fatalf("rsa.GeneratePSSKey: %v", err)
		}
		return keyPair{priv: priv, pub: pub, alg: alg}
	case signature.AlgorithmRS256:
		priv, pub, err := rsa.GeneratePKCS1Key(2048, crypto.SHA256)
		if err != nil {
			t.Fatalf("rsa.GeneratePKCS1Key: %v", err)
		}
		return keyPair{priv: priv, pub: pub, alg: alg}
	default:
		t.Fatalf("no key generation for %s", alg.JOSE())
		return keyPair{}
	}
}

// TestSignAuthority_Verify_RoundTrip verifies that for every
// registered algorithm a LocalSigner-signed authority verifies
// against its public key.
func TestSignAuthority_Verify_RoundTrip(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		alg  signature.Algorithm
	}{
		// Ed25519 — [RFC 8032].
		{"EdDSA/Ed25519", signature.AlgorithmEdDSA},
		// secp256k1 — [RFC 8812] §3.1 (ES256K).
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

			kp := generateKeyPair(t, tt.alg)
			signer, err := signature.NewLocalSigner(kp.priv)
			if err != nil {
				t.Fatalf("NewLocalSigner: %v", err)
			}

			auth := testAuthority()
			auth.Proof = Proof{} // start unsigned
			if err := SignAuthority(context.Background(), auth, signer, "key-round-trip"); err != nil {
				t.Fatalf("SignAuthority: %v", err)
			}
			if auth.Proof.Algorithm != tt.alg {
				t.Fatalf("Proof.Algorithm = %s, want %s", auth.Proof.Algorithm.JOSE(), tt.alg.JOSE())
			}
			if len(auth.Proof.Signature) == 0 {
				t.Fatal("SignAuthority left Proof.Signature empty")
			}

			if err := VerifyAuthorityProof(auth, kp.pub); err != nil {
				t.Fatalf("VerifyAuthorityProof: %v", err)
			}
		})
	}
}

// mockSigner is a test-only signature.Signer returning canned values.
// It proves the authority proof path consumes the Signer interface
// alone — no kms/ implementation is needed or imported.
type mockSigner struct {
	pub       crypto.PublicKey
	sig       []byte
	pubErr    error
	signErr   error
	gotDigest []byte
	signCalls int
}

// compile-time check that mockSigner satisfies signature.Signer.
var _ signature.Signer = (*mockSigner)(nil)

// PublicKey returns the canned public key or error.
func (m *mockSigner) PublicKey(_ context.Context) (crypto.PublicKey, error) {
	if m.pubErr != nil {
		return nil, m.pubErr
	}
	return m.pub, nil
}

// Sign records the digest it was given and returns the canned
// signature or error.
func (m *mockSigner) Sign(_ context.Context, digest []byte) ([]byte, error) {
	m.signCalls++
	m.gotDigest = append([]byte(nil), digest...)
	if m.signErr != nil {
		return nil, m.signErr
	}
	return m.sig, nil
}

// TestSignAuthority_MockSigner exercises the proof path through the
// signature.Signer interface only (no kms/): SignAuthority must set
// Proof.Algorithm from the signer's public key, set Proof.KeyID to
// the supplied keyID, sign the canonical hash, and store the result
// in Proof.Signature.
func TestSignAuthority_MockSigner(t *testing.T) {
	t.Parallel()

	_, pub, err := ed25519.GenerateKey()
	if err != nil {
		t.Fatalf("ed25519.GenerateKey: %v", err)
	}
	cannedSig := []byte{0xDE, 0xAD, 0xBE, 0xEF}
	m := &mockSigner{pub: pub, sig: cannedSig}

	auth := testAuthority()
	auth.Proof = Proof{}
	if err := SignAuthority(context.Background(), auth, m, "kms-key-42"); err != nil {
		t.Fatalf("SignAuthority: %v", err)
	}

	if got, want := auth.Proof.Algorithm, signature.AlgorithmEdDSA; got != want {
		t.Errorf("Proof.Algorithm = %s, want %s", got.JOSE(), want.JOSE())
	}
	if got, want := auth.Proof.KeyID, "kms-key-42"; got != want {
		t.Errorf("Proof.KeyID = %q, want %q", got, want)
	}
	if subtle.ConstantTimeCompare(auth.Proof.Signature, cannedSig) != 1 {
		t.Errorf("Proof.Signature = %x, want %x", auth.Proof.Signature, cannedSig)
	}
	if m.signCalls != 1 {
		t.Fatalf("Sign called %d times, want 1", m.signCalls)
	}
	// The digest handed to the signer must be the canonical hash of
	// the authority with Algorithm and KeyID already committed.
	wantHash, err := CanonicalHash(auth)
	if err != nil {
		t.Fatalf("CanonicalHash: %v", err)
	}
	if subtle.ConstantTimeCompare(m.gotDigest, wantHash[:]) != 1 {
		t.Fatalf("Sign digest = %x, want canonical hash %x", m.gotDigest, wantHash)
	}
}

// TestSignAuthority_SignerErrors verifies that failures inside the
// signer propagate as errors from SignAuthority.
func TestSignAuthority_SignerErrors(t *testing.T) {
	t.Parallel()

	_, pub, err := ed25519.GenerateKey()
	if err != nil {
		t.Fatalf("ed25519.GenerateKey: %v", err)
	}

	tests := []struct {
		name   string
		signer *mockSigner
	}{
		{"PublicKey fails", &mockSigner{pubErr: errors.New("kms unreachable")}},
		{"Sign fails", &mockSigner{pub: pub, signErr: errors.New("signing denied")}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			auth := testAuthority()
			if err := SignAuthority(context.Background(), auth, tt.signer, "k"); err == nil {
				t.Fatal("SignAuthority = nil error, want error")
			}
		})
	}
}

// TestSignAuthority_NilInputs verifies nil guards: a nil authority and
// a nil signer each return an error.
func TestSignAuthority_NilInputs(t *testing.T) {
	t.Parallel()

	priv, _, err := ed25519.GenerateKey()
	if err != nil {
		t.Fatalf("ed25519.GenerateKey: %v", err)
	}
	signer, err := signature.NewLocalSigner(priv)
	if err != nil {
		t.Fatalf("NewLocalSigner: %v", err)
	}

	if err := SignAuthority(context.Background(), nil, signer, "k"); err == nil {
		t.Error("SignAuthority(nil auth) = nil error, want error")
	}
	if err := SignAuthority(context.Background(), testAuthority(), nil, "k"); err == nil {
		t.Error("SignAuthority(nil signer) = nil error, want error")
	}
}

// TestVerifyAuthorityProof_Tampered verifies that flipping a byte in
// Proof.Signature, and separately mutating Proof.KeyID after signing,
// each produce ErrTamperedAuthority — KeyID is inside the canonical
// hash, so changing it invalidates the signature.
func TestVerifyAuthorityProof_Tampered(t *testing.T) {
	t.Parallel()

	kp := generateKeyPair(t, signature.AlgorithmEdDSA)
	signer, err := signature.NewLocalSigner(kp.priv)
	if err != nil {
		t.Fatalf("NewLocalSigner: %v", err)
	}

	sign := func(t *testing.T) *Authority {
		t.Helper()
		auth := testAuthority()
		auth.Proof = Proof{}
		if err := SignAuthority(context.Background(), auth, signer, "key-1"); err != nil {
			t.Fatalf("SignAuthority: %v", err)
		}
		return auth
	}

	tests := []struct {
		name   string
		mutate func(*Authority)
	}{
		{
			name: "flipped signature byte",
			mutate: func(a *Authority) {
				a.Proof.Signature[0] ^= 0xFF
			},
		},
		{
			name: "truncated signature",
			mutate: func(a *Authority) {
				a.Proof.Signature = a.Proof.Signature[:len(a.Proof.Signature)/2]
			},
		},
		{
			name: "changed KeyID",
			mutate: func(a *Authority) {
				a.Proof.KeyID = "key-2"
			},
		},
		{
			name: "changed subject",
			mutate: func(a *Authority) {
				a.Subject = "did:example:mallory"
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			auth := sign(t)
			tt.mutate(auth)
			err := VerifyAuthorityProof(auth, kp.pub)
			if !errors.Is(err, ErrTamperedAuthority) {
				t.Fatalf("VerifyAuthorityProof = %v, want errors.Is(err, ErrTamperedAuthority)", err)
			}
		})
	}
}

// TestVerifyAuthorityProof_AlgorithmMismatch verifies the
// algorithm-confusion defense: an authority signed with Ed25519 and
// verified against a secp256k1 public key returns ErrWrongKey before
// signature.Verify is reached.
func TestVerifyAuthorityProof_AlgorithmMismatch(t *testing.T) {
	t.Parallel()

	ed := generateKeyPair(t, signature.AlgorithmEdDSA)
	k1 := generateKeyPair(t, signature.AlgorithmES256K)

	signer, err := signature.NewLocalSigner(ed.priv)
	if err != nil {
		t.Fatalf("NewLocalSigner: %v", err)
	}
	auth := testAuthority()
	auth.Proof = Proof{}
	if err := SignAuthority(context.Background(), auth, signer, "key-1"); err != nil {
		t.Fatalf("SignAuthority: %v", err)
	}

	err = VerifyAuthorityProof(auth, k1.pub)
	if !errors.Is(err, ErrWrongKey) {
		t.Fatalf("VerifyAuthorityProof = %v, want errors.Is(err, ErrWrongKey)", err)
	}
}

// TestVerifyAuthorityProof_WrongKeySameAlgorithm verifies that a
// different key of the same algorithm is reported as tamper, not as a
// wrong-key mismatch — the algorithm check passes, the signature does
// not.
func TestVerifyAuthorityProof_WrongKeySameAlgorithm(t *testing.T) {
	t.Parallel()

	kp := generateKeyPair(t, signature.AlgorithmEdDSA)
	other := generateKeyPair(t, signature.AlgorithmEdDSA)

	signer, err := signature.NewLocalSigner(kp.priv)
	if err != nil {
		t.Fatalf("NewLocalSigner: %v", err)
	}
	auth := testAuthority()
	auth.Proof = Proof{}
	if err := SignAuthority(context.Background(), auth, signer, "key-1"); err != nil {
		t.Fatalf("SignAuthority: %v", err)
	}

	err = VerifyAuthorityProof(auth, other.pub)
	if !errors.Is(err, ErrTamperedAuthority) {
		t.Fatalf("VerifyAuthorityProof = %v, want errors.Is(err, ErrTamperedAuthority)", err)
	}
	if errors.Is(err, ErrWrongKey) {
		t.Fatalf("VerifyAuthorityProof = %v, must not wrap ErrWrongKey", err)
	}
}

// TestVerifyAuthorityProof_NilAndBadKey verifies the nil-authority
// guard and that an unresolvable public key type returns ErrWrongKey.
func TestVerifyAuthorityProof_NilAndBadKey(t *testing.T) {
	t.Parallel()

	_, pub, err := ed25519.GenerateKey()
	if err != nil {
		t.Fatalf("ed25519.GenerateKey: %v", err)
	}

	if err := VerifyAuthorityProof(nil, pub); err == nil {
		t.Error("VerifyAuthorityProof(nil auth) = nil error, want error")
	}

	auth := testAuthority()
	tests := []struct {
		name string
		pub  crypto.PublicKey
		want error
	}{
		{"nil public key", nil, ErrWrongKey},
		{"unknown key type", crypto.PublicKey("nope"), ErrWrongKey},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := VerifyAuthorityProof(auth, tt.pub)
			if !errors.Is(err, tt.want) {
				t.Fatalf("VerifyAuthorityProof = %v, want errors.Is(err, %v)", err, tt.want)
			}
		})
	}
}

// TestSignAuthority_ResignChangesCommitment verifies that signing the
// same authority under a different keyID produces a different
// signature — the canonical hash commits to KeyID.
func TestSignAuthority_ResignChangesCommitment(t *testing.T) {
	t.Parallel()

	priv, pub, err := ed25519.GenerateKey()
	if err != nil {
		t.Fatalf("ed25519.GenerateKey: %v", err)
	}
	signer, err := signature.NewLocalSigner(priv)
	if err != nil {
		t.Fatalf("NewLocalSigner: %v", err)
	}

	a := testAuthority()
	a.Proof = Proof{}
	if err := SignAuthority(context.Background(), a, signer, "key-1"); err != nil {
		t.Fatalf("SignAuthority key-1: %v", err)
	}
	b := testAuthority()
	b.Proof = Proof{}
	if err := SignAuthority(context.Background(), b, signer, "key-2"); err != nil {
		t.Fatalf("SignAuthority key-2: %v", err)
	}

	// Ed25519 is deterministic ([RFC 8032]): identical keys and
	// differing KeyID must yield differing signatures.
	if subtle.ConstantTimeCompare(a.Proof.Signature, b.Proof.Signature) == 1 {
		t.Fatal("signatures equal across differing KeyID — KeyID not committed")
	}
	if err := VerifyAuthorityProof(a, pub); err != nil {
		t.Fatalf("VerifyAuthorityProof a: %v", err)
	}
	if err := VerifyAuthorityProof(b, pub); err != nil {
		t.Fatalf("VerifyAuthorityProof b: %v", err)
	}
}
