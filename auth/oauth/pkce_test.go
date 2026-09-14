package oauth

import (
	"crypto/sha256"
	"encoding/base64"
	"strings"
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
			name:      "wrong verifier (valid grammar, mismatched hash)",
			verifier:  strings.Repeat("v", 43),
			challenge: rfcChallenge,
			method:    MethodS256,
			wantErr:   true,
		},
		{
			name:      "wrong challenge (valid grammar, mismatched hash)",
			verifier:  rfcVerifier,
			challenge: strings.Repeat("c", 43),
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

	verifier := "test-verifier-0123456789-abcdefghijklmnopqrstuvwx" // 50 chars, valid grammar
	sum := sha256.Sum256([]byte(verifier))
	expected := base64.RawURLEncoding.EncodeToString(sum[:])

	// Same verifier always produces the same challenge.
	if err := VerifyPKCE(verifier, expected, MethodS256); err != nil {
		t.Fatalf("VerifyPKCE failed with deterministic challenge: %v", err)
	}

	// Different verifier produces different challenge.
	other := "other-verifier-0123456789-abcdefghijklmnopqrstuv" // 49 chars, valid grammar
	sum2 := sha256.Sum256([]byte(other))
	different := base64.RawURLEncoding.EncodeToString(sum2[:])
	if err := VerifyPKCE(verifier, different, MethodS256); err == nil {
		t.Fatal("VerifyPKCE succeeded with wrong challenge — hash collision or bug")
	}
}

// TestVerifyPKCE_Grammar verifies [A13] grammar enforcement per
// [RFC 7636] §4.1–4.2: verifier and challenge must be 43–128 characters
// from the unreserved set (ALPHA / DIGIT / "-" / "." / "_" / "~").
func TestVerifyPKCE_Grammar(t *testing.T) {
	t.Parallel()

	// challengeFor computes the S256 challenge for a verifier — used to
	// build matching pairs for cases that must pass grammar validation.
	challengeFor := func(v string) string {
		sum := sha256.Sum256([]byte(v))
		return base64.RawURLEncoding.EncodeToString(sum[:])
	}

	rfcVerifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"  // 43 chars
	rfcChallenge := "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM" // 43 chars

	tests := []struct {
		name      string
		verifier  string
		challenge string
		method    string
		wantErr   bool
	}{
		{
			name:      "valid RFC 7636 vector",
			verifier:  rfcVerifier,
			challenge: rfcChallenge,
			method:    MethodS256,
			wantErr:   false,
		},
		{
			name:      "verifier at min length boundary (43)",
			verifier:  strings.Repeat("a", 43),
			challenge: challengeFor(strings.Repeat("a", 43)),
			method:    MethodS256,
			wantErr:   false,
		},
		{
			name:      "verifier at max length boundary (128)",
			verifier:  strings.Repeat("a", 128),
			challenge: challengeFor(strings.Repeat("a", 128)),
			method:    MethodS256,
			wantErr:   false,
		},
		{
			name:      "verifier with all unreserved specials",
			verifier:  "a-c.e_f~g-h.i_j~k-l.m_n~o-p.q_r~s-t.u_v~w-x.y_z", // 47 chars
			challenge: challengeFor("a-c.e_f~g-h.i_j~k-l.m_n~o-p.q_r~s-t.u_v~w-x.y_z"),
			method:    MethodS256,
			wantErr:   false,
		},
		{
			name:      "verifier too short (42 chars)",
			verifier:  strings.Repeat("a", 42),
			challenge: rfcChallenge,
			method:    MethodS256,
			wantErr:   true,
		},
		{
			name:      "verifier too long (129 chars)",
			verifier:  strings.Repeat("a", 129),
			challenge: rfcChallenge,
			method:    MethodS256,
			wantErr:   true,
		},
		{
			name:      "verifier with invalid char '='",
			verifier:  strings.Repeat("a", 42) + "=",
			challenge: rfcChallenge,
			method:    MethodS256,
			wantErr:   true,
		},
		{
			name:      "verifier with invalid char '+'",
			verifier:  strings.Repeat("a", 42) + "+",
			challenge: rfcChallenge,
			method:    MethodS256,
			wantErr:   true,
		},
		{
			name:      "verifier with invalid char '/'",
			verifier:  strings.Repeat("a", 42) + "/",
			challenge: rfcChallenge,
			method:    MethodS256,
			wantErr:   true,
		},
		{
			name:      "verifier with space",
			verifier:  strings.Repeat("a", 42) + " ",
			challenge: rfcChallenge,
			method:    MethodS256,
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
			name:      "challenge too short (42 chars)",
			verifier:  rfcVerifier,
			challenge: strings.Repeat("c", 42),
			method:    MethodS256,
			wantErr:   true,
		},
		{
			name:      "challenge too long (129 chars)",
			verifier:  rfcVerifier,
			challenge: strings.Repeat("c", 129),
			method:    MethodS256,
			wantErr:   true,
		},
		{
			name:      "challenge with base64 padding '='",
			verifier:  rfcVerifier,
			challenge: rfcChallenge + "a=" + strings.Repeat("c", 41), // 44 chars incl '='
			method:    MethodS256,
			wantErr:   true,
		},
		{
			name:      "challenge with invalid char '+'",
			verifier:  rfcVerifier,
			challenge: strings.Repeat("c", 42) + "+",
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
				if err != ErrInvalidPKCE {
					t.Fatalf("VerifyPKCE(%q, %q, %q): got err = %v, want ErrInvalidPKCE",
						tt.verifier, tt.challenge, tt.method, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("VerifyPKCE(%q, %q, %q): got err = %v, want nil",
					tt.verifier, tt.challenge, tt.method, err)
			}
		})
	}
}
