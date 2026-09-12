package oauth

import (
	"crypto/sha256"
	"encoding/base64"
	"testing"
)

func TestVerifyPKCE(t *testing.T) {
	t.Parallel()

	// Vector: [RFC 7636] Appendix B — PKCE S256 test vector.
	// code_verifier:  dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk
	// code_challenge: E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM
	rfcVerifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	rfcChallenge := "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"

	tests := []struct {
		name      string
		verifier  string
		challenge string
		method    string
		wantErr   bool
	}{
		{
			name:      "valid S256 (RFC 7636 Appendix B)",
			verifier:  rfcVerifier,
			challenge: rfcChallenge,
			method:    MethodS256,
			wantErr:   false,
		},
		{
			name:      "wrong verifier",
			verifier:  "wrong-verifier-value-here",
			challenge: rfcChallenge,
			method:    MethodS256,
			wantErr:   true,
		},
		{
			name:      "wrong challenge",
			verifier:  rfcVerifier,
			challenge: "wrong-challenge-value-here",
			method:    MethodS256,
			wantErr:   true,
		},
		{
			name:      "plain method rejected",
			verifier:  rfcVerifier,
			challenge: rfcVerifier, // plain: challenge == verifier
			method:    MethodPlain,
			wantErr:   true,
		},
		{
			name:      "unknown method rejected",
			verifier:  rfcVerifier,
			challenge: rfcChallenge,
			method:    "unknown",
			wantErr:   true,
		},
		{
			name:      "empty verifier",
			verifier:  "",
			challenge: rfcChallenge,
			method:    MethodS256,
			wantErr:   true,
		},
		{
			name:      "empty challenge",
			verifier:  rfcVerifier,
			challenge: "",
			method:    MethodS256,
			wantErr:   true,
		},
		{
			name:      "empty method",
			verifier:  rfcVerifier,
			challenge: rfcChallenge,
			method:    "",
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := VerifyPKCE(tt.verifier, tt.challenge, tt.method)
			if tt.wantErr {
				if err == nil {
					t.Fatal("VerifyPKCE expected error, got nil")
				}
				if err != ErrInvalidPKCE {
					t.Fatalf("VerifyPKCE err = %v, want ErrInvalidPKCE", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("VerifyPKCE unexpected error: %v", err)
			}
		})
	}
}

func TestVerifyPKCE_Deterministic(t *testing.T) {
	t.Parallel()

	verifier := "test-verifier-1234567890"
	sum := sha256.Sum256([]byte(verifier))
	expected := base64.RawURLEncoding.EncodeToString(sum[:])

	// Same verifier always produces the same challenge.
	if err := VerifyPKCE(verifier, expected, MethodS256); err != nil {
		t.Fatalf("VerifyPKCE failed with deterministic challenge: %v", err)
	}

	// Different verifier produces different challenge.
	sum2 := sha256.Sum256([]byte("different-verifier"))
	different := base64.RawURLEncoding.EncodeToString(sum2[:])
	if err := VerifyPKCE(verifier, different, MethodS256); err == nil {
		t.Fatal("VerifyPKCE succeeded with wrong challenge — hash collision or bug")
	}
}
