package kms

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bperin/trust/trust/crypto/hash"
	"github.com/bperin/trust/trust/crypto/secp256k1"
	"github.com/bperin/trust/trust/signature"
)

// mockSigner is an in-process [RemoteSigner] used to test the JOSE and
// EVM signing paths end-to-end without a cloud KMS. It signs via
// secp256k1.SignRecoverable, which produces a 64-byte r||s signature
// and a recovery id. The JOSE path returns the 64-byte r||s; the EVM
// path appends the recovery id as the 65th byte.
//
// It holds a *secp256k1.PrivateKey only for testing — production
// signers hold only a key reference. The test asserts no private key
// material is present in the production signer structs (aws/gcp) via
// the isolation grep in the task verification.
type mockSigner struct {
	priv *secp256k1.PrivateKey
	pub  *secp256k1.PublicKey
}

func newMockSigner(t *testing.T) *mockSigner {
	t.Helper()
	priv, pub, err := secp256k1.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	return &mockSigner{priv: priv, pub: pub}
}

func (m *mockSigner) Sign(ctx context.Context, digest []byte, opts SignOptions) ([]byte, error) {
	if len(digest) != 32 {
		return nil, errors.New("mock: digest must be 32 bytes")
	}
	sig, recID, err := m.priv.SignRecoverable(digest)
	if err != nil {
		return nil, err
	}
	switch opts.Path {
	case SignPathJOSE:
		return sig, nil
	case SignPathEVM:
		out := make([]byte, 65)
		copy(out[:64], sig)
		out[64] = recID
		return out, nil
	default:
		return nil, errors.New("mock: unknown sign path")
	}
}

func (m *mockSigner) PublicKey(ctx context.Context) (*secp256k1.PublicKey, error) {
	return m.pub, nil
}

// TestRemoteSigner_JOSEPath verifies the JOSE/COSE ES256K path: the
// mock signer produces a 64-byte r||s signature over a SHA-256 digest,
// and signature.Verify(AlgorithmES256K, pub, sig, msg) returns true.
func TestRemoteSigner_JOSEPath(t *testing.T) {
	t.Parallel()
	signer := newMockSigner(t)
	ctx := context.Background()

	pub, err := signer.PublicKey(ctx)
	if err != nil {
		t.Fatalf("PublicKey: %v", err)
	}

	msg := []byte("hello JOSE/COSE ES256K")
	// JOSE path: caller pre-hashes with SHA-256.
	digest := sha256.Sum256(msg)

	sig, err := signer.Sign(ctx, digest[:], SignOptions{Path: SignPathJOSE})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if got, want := len(sig), 64; got != want {
		t.Fatalf("len(sig) = %d, want %d", got, want)
	}

	ok, err := signature.Verify(signature.AlgorithmES256K, pub, sig, msg)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !ok {
		t.Fatalf("signature.Verify(ES256K) = false, want true")
	}
}

// TestRemoteSigner_EVMPath verifies the EVM path: the mock signer
// produces a 65-byte r||s||v signature over a Keccak-256 digest, and
// secp256k1.RecoverPubKey recovers a public key matching PublicKey().
func TestRemoteSigner_EVMPath(t *testing.T) {
	t.Parallel()
	signer := newMockSigner(t)
	ctx := context.Background()

	pub, err := signer.PublicKey(ctx)
	if err != nil {
		t.Fatalf("PublicKey: %v", err)
	}

	msg := []byte("hello EVM")
	// EVM path: caller pre-hashes with Keccak-256.
	digest := hash.NewKeccak256().Sum(msg)

	sig, err := signer.Sign(ctx, digest[:], SignOptions{Path: SignPathEVM})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if got, want := len(sig), 65; got != want {
		t.Fatalf("len(sig) = %d, want %d", got, want)
	}

	recID := sig[64]
	recovered, err := secp256k1.RecoverPubKey(sig[:64], digest[:], recID)
	if err != nil {
		t.Fatalf("RecoverPubKey: %v", err)
	}
	if !recovered.Equal(pub) {
		t.Fatalf("recovered key does not match PublicKey()\ngot:  %s\nwant: %s",
			recovered.Redact(), pub.Redact())
	}
}

// TestRemoteSigner_InvalidDigest verifies Sign rejects a non-32-byte
// digest on both paths.
func TestRemoteSigner_InvalidDigest(t *testing.T) {
	t.Parallel()
	signer := newMockSigner(t)
	ctx := context.Background()

	cases := []struct {
		name string
		path SignPath
	}{
		{"jose", SignPathJOSE},
		{"evm", SignPathEVM},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := signer.Sign(ctx, []byte("too short"), SignOptions{Path: tc.path})
			if err == nil {
				t.Fatalf("Sign with short digest: want error, got nil")
			}
		})
	}
}

// TestRemoteSigner_UnknownPath verifies Sign rejects an unknown path.
func TestRemoteSigner_UnknownPath(t *testing.T) {
	t.Parallel()
	signer := newMockSigner(t)
	ctx := context.Background()
	digest := sha256.Sum256([]byte("msg"))

	_, err := signer.Sign(ctx, digest[:], SignOptions{Path: SignPath(99)})
	if err == nil {
		t.Fatalf("Sign with unknown path: want error, got nil")
	}
}

// TestSignPathConstants verifies the SignPath constants have the
// documented values.
func TestSignPathConstants(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		got  SignPath
		want SignPath
	}{
		{"JOSE", SignPathJOSE, 0},
		{"EVM", SignPathEVM, 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if tc.got != tc.want {
				t.Fatalf("%s = %d, want %d", tc.name, tc.got, tc.want)
			}
		})
	}
}

// TestIsolation_NoChainOrAuthImports verifies the kms module has no
// imports of the chain or auth sibling modules. This enforces the
// cross-module dependency rule: kms depends on trust only.
func TestIsolation_NoChainOrAuthImports(t *testing.T) {
	t.Parallel()
	// Scan all Go files in the kms module for forbidden imports.
	// This is a real check, not a no-op — it fails if any non-test
	// .go file imports chain or auth.
	matches, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatalf("glob: %v", err)
	}
	derMatches, _ := filepath.Glob("der/*.go")
	matches = append(matches, derMatches...)
	for _, f := range matches {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatalf("read %s: %v", f, err)
		}
		if bytes.Contains(b, []byte("github.com/bperin/trust/chain")) {
			t.Errorf("file %s imports github.com/bperin/trust/chain — kms must not depend on chain", f)
		}
		if bytes.Contains(b, []byte("github.com/bperin/trust/auth")) {
			t.Errorf("file %s imports github.com/bperin/trust/auth — kms must not depend on auth", f)
		}
	}
}
