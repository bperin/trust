package kms

import (
	"bytes"
	"context"
	"crypto/sha256"
	"testing"

	"github.com/bperin/trust/crypto/hash"
	"github.com/bperin/trust/crypto/secp256k1"
	"github.com/bperin/trust/signature"
)

// recordingSigner wraps a RemoteSigner and captures the digest and
// SignOptions passed to Sign, so tests can assert KMSSigner
// pre-hashed the message correctly.
type recordingSigner struct {
	inner   RemoteSigner
	digest  []byte
	opts    SignOptions
	signErr error
}

func (r *recordingSigner) Sign(ctx context.Context, digest []byte, opts SignOptions) ([]byte, error) {
	if r.signErr != nil {
		return nil, r.signErr
	}
	r.digest = append([]byte(nil), digest...)
	r.opts = opts
	return r.inner.Sign(ctx, digest, opts)
}

func (r *recordingSigner) PublicKey(ctx context.Context) (*secp256k1.PublicKey, error) {
	return r.inner.PublicKey(ctx)
}

// TestKMSSigner_JOSEPath is the end-to-end proof of the KMS signing
// path: NewKMSSigner over a mock RemoteSigner, Sign a plain message,
// then signature.Verify(AlgorithmES256K, pub, sig, msg) must accept.
// This is the same Verify authority.VerifyAuthorityProof calls
// internally.
func TestKMSSigner_JOSEPath(t *testing.T) {
	t.Parallel()
	mock := newMockSigner(t)
	signer := NewKMSSigner(mock, SignPathJOSE)
	if signer == nil {
		t.Fatalf("NewKMSSigner returned nil")
	}
	ctx := context.Background()

	pub, err := signer.PublicKey(ctx)
	if err != nil {
		t.Fatalf("PublicKey: %v", err)
	}
	if _, ok := pub.(*secp256k1.PublicKey); !ok {
		t.Fatalf("PublicKey type = %T, want *secp256k1.PublicKey", pub)
	}

	msg := []byte("hello KMSSigner JOSE/COSE ES256K")
	sig, err := signer.Sign(ctx, msg)
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

// TestKMSSigner_EVMPath verifies the EVM path end-to-end: Sign a
// plain message, then recover the public key from the 65-byte
// r||s||v signature over the Keccak-256 digest of the message.
func TestKMSSigner_EVMPath(t *testing.T) {
	t.Parallel()
	mock := newMockSigner(t)
	signer := NewKMSSigner(mock, SignPathEVM)
	if signer == nil {
		t.Fatalf("NewKMSSigner returned nil")
	}
	ctx := context.Background()

	pub, err := signer.PublicKey(ctx)
	if err != nil {
		t.Fatalf("PublicKey: %v", err)
	}
	secpPub, ok := pub.(*secp256k1.PublicKey)
	if !ok {
		t.Fatalf("PublicKey type = %T, want *secp256k1.PublicKey", pub)
	}

	msg := []byte("hello KMSSigner EVM")
	sig, err := signer.Sign(ctx, msg)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if got, want := len(sig), 65; got != want {
		t.Fatalf("len(sig) = %d, want %d", got, want)
	}

	digest := hash.NewKeccak256().Sum(msg)
	recovered, err := secp256k1.RecoverPubKey(sig[:64], digest[:], sig[64])
	if err != nil {
		t.Fatalf("RecoverPubKey: %v", err)
	}
	if !recovered.Equal(secpPub) {
		t.Fatalf("recovered key does not match PublicKey()\ngot:  %s\nwant: %s",
			recovered.Redact(), secpPub.Redact())
	}
}

// TestKMSSigner_PreHash asserts the adapter pre-hashes before the
// remote call: the digest reaching RemoteSigner.Sign must equal
// sha256.Sum256(msg) on the JOSE path and Keccak-256(msg) on the EVM
// path.
func TestKMSSigner_PreHash(t *testing.T) {
	t.Parallel()
	msg := []byte("pre-hash me")

	cases := []struct {
		name string
		path SignPath
		want [32]byte
	}{
		{"jose", SignPathJOSE, sha256.Sum256(msg)},
		{"evm", SignPathEVM, hash.NewKeccak256().Sum(msg)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			rec := &recordingSigner{inner: newMockSigner(t)}
			signer := NewKMSSigner(rec, tc.path)

			if _, err := signer.Sign(context.Background(), msg); err != nil {
				t.Fatalf("Sign: %v", err)
			}
			if !bytes.Equal(rec.digest, tc.want[:]) {
				t.Fatalf("digest reaching remote = %x, want %x", rec.digest, tc.want)
			}
			if rec.opts.Path != tc.path {
				t.Fatalf("opts.Path = %d, want %d", rec.opts.Path, tc.path)
			}
		})
	}
}

// TestKMSSigner_PublicKeyType asserts PublicKey returns the remote's
// *secp256k1.PublicKey as a crypto.PublicKey and that it equals the
// remote's key.
func TestKMSSigner_PublicKeyType(t *testing.T) {
	t.Parallel()
	mock := newMockSigner(t)
	signer := NewKMSSigner(mock, SignPathJOSE)
	ctx := context.Background()

	pub, err := signer.PublicKey(ctx)
	if err != nil {
		t.Fatalf("PublicKey: %v", err)
	}
	secpPub, ok := pub.(*secp256k1.PublicKey)
	if !ok {
		t.Fatalf("PublicKey type = %T, want *secp256k1.PublicKey", pub)
	}
	if !secpPub.Equal(mock.pub) {
		t.Fatalf("PublicKey does not match remote key\ngot:  %s\nwant: %s",
			secpPub.Redact(), mock.pub.Redact())
	}
}

// TestKMSSigner_NewKMSSignerNonNil asserts the constructor returns a
// non-nil signer for both paths.
func TestKMSSigner_NewKMSSignerNonNil(t *testing.T) {
	t.Parallel()
	mock := newMockSigner(t)
	for _, path := range []SignPath{SignPathJOSE, SignPathEVM} {
		if s := NewKMSSigner(mock, path); s == nil {
			t.Fatalf("NewKMSSigner(path=%d) = nil", path)
		}
	}
}

// TestKMSSigner_SignCanceledContext asserts Sign honors ctx.Err()
// before the remote call — the remote must not be invoked.
func TestKMSSigner_SignCanceledContext(t *testing.T) {
	t.Parallel()
	rec := &recordingSigner{inner: newMockSigner(t)}
	signer := NewKMSSigner(rec, SignPathJOSE)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if _, err := signer.Sign(ctx, []byte("msg")); err == nil {
		t.Fatalf("Sign with canceled ctx: want error, got nil")
	}
	if rec.digest != nil {
		t.Fatalf("remote.Sign was invoked despite canceled ctx")
	}
}

// TestKMSSigner_UnknownPath asserts Sign rejects an unrecognized
// SignPath before calling the remote.
func TestKMSSigner_UnknownPath(t *testing.T) {
	t.Parallel()
	rec := &recordingSigner{inner: newMockSigner(t)}
	signer := NewKMSSigner(rec, SignPath(99))

	if _, err := signer.Sign(context.Background(), []byte("msg")); err == nil {
		t.Fatalf("Sign with unknown path: want error, got nil")
	}
	if rec.digest != nil {
		t.Fatalf("remote.Sign was invoked despite unknown path")
	}
}

// TestKMSSigner_RemoteError asserts remote Sign errors propagate.
func TestKMSSigner_RemoteError(t *testing.T) {
	t.Parallel()
	wantErr := context.DeadlineExceeded
	rec := &recordingSigner{inner: newMockSigner(t), signErr: wantErr}
	signer := NewKMSSigner(rec, SignPathJOSE)

	_, err := signer.Sign(context.Background(), []byte("msg"))
	if err == nil {
		t.Fatalf("Sign: want error, got nil")
	}
	if err != wantErr {
		t.Fatalf("Sign error = %v, want %v", err, wantErr)
	}
}
