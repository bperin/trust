package attestation

import (
	"bytes"
	"errors"
	"testing"
	"time"

	"github.com/bperin/trust/crypto/ed25519"
	jwkutil "github.com/bperin/trust/identity/jwk"
)

func TestIssueVerifyRoundTrip(t *testing.T) {
	t.Parallel()

	priv, pub, err := ed25519.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: got error %v, want nil", err)
	}

	claims := map[int64]any{
		ClaimIssuer:   "did:example:issuer",
		ClaimSubject:  "did:example:subject",
		ClaimAudience: "did:example:verifier",
		ClaimExpiry:   time.Now().Add(time.Hour).Unix(),
		ClaimNonce:    []byte("nonce-123"),
	}

	token, err := Issue(claims, priv, IssueOptions{
		VerificationMethod: "did:example:issuer#keys-1",
	})
	if err != nil {
		t.Fatalf("Issue: got error %v, want nil", err)
	}

	got, err := Verify(token, pub, VerifyOptions{
		ExpectedIssuer:   "did:example:issuer",
		ExpectedAudience: "did:example:verifier",
	})
	if err != nil {
		t.Fatalf("Verify: got error %v, want nil", err)
	}
	if got[ClaimIssuer] != "did:example:issuer" {
		t.Errorf("iss: got %v, want %q", got[ClaimIssuer], "did:example:issuer")
	}
	if got[ClaimSubject] != "did:example:subject" {
		t.Errorf("sub: got %v, want %q", got[ClaimSubject], "did:example:subject")
	}
	if !bytes.Equal(got[ClaimNonce].([]byte), []byte("nonce-123")) {
		t.Errorf("nonce: got %x, want %x", got[ClaimNonce], []byte("nonce-123"))
	}
}

func TestIssueRequiredFields(t *testing.T) {
	t.Parallel()

	priv, _, err := ed25519.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: got error %v, want nil", err)
	}

	tests := []struct {
		name    string
		claims  map[int64]any
		wantErr error
	}{
		{
			name:    "nil claims",
			claims:  nil,
			wantErr: ErrInvalidClaims,
		},
		{
			name:    "missing issuer",
			claims:  map[int64]any{ClaimSubject: "did:example:subject"},
			wantErr: ErrInvalidClaims,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, err := Issue(tt.claims, priv, IssueOptions{})
			if !errors.Is(err, tt.wantErr) {
				t.Errorf("Issue: got error %v, want errors.Is(_, %v)", err, tt.wantErr)
			}
		})
	}
}

func TestVerifyNegative(t *testing.T) {
	t.Parallel()

	priv, pub, err := ed25519.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: got error %v, want nil", err)
	}

	claims := map[int64]any{
		ClaimIssuer:   "did:example:issuer",
		ClaimSubject:  "did:example:subject",
		ClaimAudience: "did:example:verifier",
		ClaimExpiry:   time.Now().Add(time.Hour).Unix(),
	}

	token, err := Issue(claims, priv, IssueOptions{})
	if err != nil {
		t.Fatalf("Issue: got error %v, want nil", err)
	}

	_, wrongPub, err := ed25519.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey wrong: got error %v, want nil", err)
	}

	tests := []struct {
		name    string
		token   []byte
		key     any
		opts    VerifyOptions
		wantErr error
	}{
		{
			name:    "wrong key",
			token:   token,
			key:     wrongPub,
			opts:    VerifyOptions{},
			wantErr: jwkutil.ErrCoseInvalidSig,
		},
		{
			name:    "tampered token",
			token:   tampered(token),
			key:     pub,
			opts:    VerifyOptions{},
			wantErr: jwkutil.ErrCoseInvalidSig,
		},
		{
			name:    "issuer mismatch",
			token:   token,
			key:     pub,
			opts:    VerifyOptions{ExpectedIssuer: "did:example:other"},
			wantErr: ErrIssuerMismatch,
		},
		{
			name:    "audience mismatch",
			token:   token,
			key:     pub,
			opts:    VerifyOptions{ExpectedAudience: "did:example:other"},
			wantErr: ErrAudienceMismatch,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, err := Verify(tt.token, tt.key.(*ed25519.PublicKey), tt.opts)
			if !errors.Is(err, tt.wantErr) {
				t.Errorf("Verify: got error %v, want errors.Is(_, %v)", err, tt.wantErr)
			}
		})
	}
}

func TestVerifyExpired(t *testing.T) {
	t.Parallel()

	priv, pub, err := ed25519.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: got error %v, want nil", err)
	}

	claims := map[int64]any{
		ClaimIssuer:   "did:example:issuer",
		ClaimExpiry:   time.Now().Add(-time.Hour).Unix(),
		ClaimIssuedAt: time.Now().Add(-2 * time.Hour).Unix(),
	}

	token, err := Issue(claims, priv, IssueOptions{})
	if err != nil {
		t.Fatalf("Issue: got error %v, want nil", err)
	}

	_, err = Verify(token, pub, VerifyOptions{})
	if !errors.Is(err, ErrExpired) {
		t.Errorf("Verify expired token: got error %v, want errors.Is(_, ErrExpired)", err)
	}
}

func TestVerifyNotYetValid(t *testing.T) {
	t.Parallel()

	priv, pub, err := ed25519.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: got error %v, want nil", err)
	}

	claims := map[int64]any{
		ClaimIssuer:    "did:example:issuer",
		ClaimNotBefore: time.Now().Add(time.Hour).Unix(),
	}

	token, err := Issue(claims, priv, IssueOptions{})
	if err != nil {
		t.Fatalf("Issue: got error %v, want nil", err)
	}

	_, err = Verify(token, pub, VerifyOptions{})
	if !errors.Is(err, ErrNotYetValid) {
		t.Errorf("Verify future nbf: got error %v, want errors.Is(_, ErrNotYetValid)", err)
	}
}

func tampered(token []byte) []byte {
	out := make([]byte, len(token))
	copy(out, token)
	// Flip one bit in the signature. The signature is the last few bytes of
	// a COSE_Sign1 object, but flipping any byte invalidates the signature.
	out[len(out)-5] ^= 0x01
	return out
}
