package credential

import (
	"crypto"
	"errors"
	"strings"
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

	cred := Credential{
		ID:     "urn:uuid:123e4567-e89b-12d3-a456-426614174000",
		Type:   []string{"VerifiableCredential"},
		Issuer: "did:example:issuer",
		CredentialSubject: map[string]any{
			"id":        "did:example:subject",
			"givenName": "Alice",
		},
	}

	token, err := Issue(cred, priv, IssueOptions{
		Audience:           "did:example:verifier",
		ExpiresAt:          time.Now().Add(time.Hour),
		VerificationMethod: "did:example:issuer#keys-1",
	})
	if err != nil {
		t.Fatalf("Issue: got error %v, want nil", err)
	}

	got, err := Verify(token, pub, VerifyOptions{
		ExpectedIssuer:   "did:example:issuer",
		ExpectedAudience: []string{"did:example:verifier"},
	})
	if err != nil {
		t.Fatalf("Verify: got error %v, want nil", err)
	}
	if got.Issuer != cred.Issuer {
		t.Errorf("issuer: got %q, want %q", got.Issuer, cred.Issuer)
	}
	if got.ID != cred.ID {
		t.Errorf("id: got %q, want %q", got.ID, cred.ID)
	}
	gotName, _ := got.CredentialSubject["givenName"].(string)
	if gotName != "Alice" {
		t.Errorf("credentialSubject.givenName: got %q, want %q", gotName, "Alice")
	}
}

func TestIssueVerifyRequiredFields(t *testing.T) {
	t.Parallel()

	priv, _, err := ed25519.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: got error %v, want nil", err)
	}

	tests := []struct {
		name    string
		cred    Credential
		wantErr error
	}{
		{
			name:    "missing issuer",
			cred:    Credential{Type: []string{"VerifiableCredential"}, CredentialSubject: map[string]any{"id": "did:example:subject"}},
			wantErr: ErrInvalidCredential,
		},
		{
			name:    "missing type",
			cred:    Credential{Issuer: "did:example:issuer", CredentialSubject: map[string]any{"id": "did:example:subject"}},
			wantErr: ErrInvalidCredential,
		},
		{
			name:    "missing credentialSubject",
			cred:    Credential{Issuer: "did:example:issuer", Type: []string{"VerifiableCredential"}},
			wantErr: ErrInvalidCredential,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, err := Issue(tt.cred, priv, IssueOptions{})
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

	cred := Credential{
		ID:     "urn:uuid:123e4567-e89b-12d3-a456-426614174000",
		Type:   []string{"VerifiableCredential"},
		Issuer: "did:example:issuer",
		CredentialSubject: map[string]any{
			"id":        "did:example:subject",
			"givenName": "Alice",
		},
	}

	token, err := Issue(cred, priv, IssueOptions{
		Audience:  "did:example:verifier",
		ExpiresAt: time.Now().Add(time.Hour),
	})
	if err != nil {
		t.Fatalf("Issue: got error %v, want nil", err)
	}

	_, wrongPub, err := ed25519.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey wrong: got error %v, want nil", err)
	}

	parts := strings.Split(token, ".")
	sigFirst := parts[2][0]
	replacement := byte('A')
	if replacement == sigFirst {
		replacement = 'B'
	}
	parts[2] = string(replacement) + parts[2][1:]
	tamperedToken := strings.Join(parts, ".")

	tests := []struct {
		name    string
		token   string
		key     crypto.PublicKey
		opts    VerifyOptions
		wantErr error
	}{
		{
			name:    "tampered token",
			token:   tamperedToken,
			key:     pub,
			opts:    VerifyOptions{},
			wantErr: jwkutil.ErrInvalidSignature,
		},
		{
			name:    "wrong key",
			token:   token,
			key:     wrongPub,
			opts:    VerifyOptions{},
			wantErr: jwkutil.ErrInvalidSignature,
		},
		{
			name:    "issuer mismatch",
			token:   token,
			key:     pub,
			opts:    VerifyOptions{ExpectedIssuer: "did:example:other"},
			wantErr: jwkutil.ErrIssuerMismatch,
		},
		{
			name:    "audience mismatch",
			token:   token,
			key:     pub,
			opts:    VerifyOptions{ExpectedAudience: []string{"did:example:other"}},
			wantErr: jwkutil.ErrAudienceMismatch,
		},
		{
			name:    "missing vc claim",
			token:   "", // set below
			key:     pub,
			opts:    VerifyOptions{},
			wantErr: ErrMissingClaim,
		},
	}

	// Create a token that is valid JWS but has no "vc" claim.
	noVC, err := jwkutil.Sign([]byte(`{"iss":"did:example:issuer"}`), priv, jwkutil.SignOptions{Algorithm: "EdDSA"})
	if err != nil {
		t.Fatalf("sign no-vc token: got error %v, want nil", err)
	}
	tests[4].token = noVC

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, err := Verify(tt.token, tt.key, tt.opts)
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

	cred := Credential{
		Type:   []string{"VerifiableCredential"},
		Issuer: "did:example:issuer",
		CredentialSubject: map[string]any{
			"id": "did:example:subject",
		},
	}

	token, err := Issue(cred, priv, IssueOptions{ExpiresAt: time.Now().Add(-time.Hour)})
	if err != nil {
		t.Fatalf("Issue: got error %v, want nil", err)
	}

	_, err = Verify(token, pub, VerifyOptions{})
	if !errors.Is(err, jwkutil.ErrExpired) {
		t.Errorf("Verify expired token: got error %v, want errors.Is(_, jwkutil.ErrExpired)", err)
	}
}

func TestPresentVerifyPresentationRoundTrip(t *testing.T) {
	t.Parallel()

	issuerPriv, issuerPub, err := ed25519.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey issuer: got error %v, want nil", err)
	}
	holderPriv, holderPub, err := ed25519.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey holder: got error %v, want nil", err)
	}

	cred := Credential{
		Type:   []string{"VerifiableCredential"},
		Issuer: "did:example:issuer",
		CredentialSubject: map[string]any{
			"id": "did:example:subject",
		},
	}

	credToken, err := Issue(cred, issuerPriv, IssueOptions{})
	if err != nil {
		t.Fatalf("Issue credential: got error %v, want nil", err)
	}

	presToken, err := Present([]string{credToken}, holderPriv, PresentOptions{
		Holder:   "did:example:holder",
		ID:       "urn:uuid:presentation-1",
		Audience: "did:example:verifier",
	})
	if err != nil {
		t.Fatalf("Present: got error %v, want nil", err)
	}

	got, err := VerifyPresentation(presToken, holderPub, VerifyPresentationOptions{
		ExpectedHolder:   "did:example:holder",
		ExpectedAudience: []string{"did:example:verifier"},
	})
	if err != nil {
		t.Fatalf("VerifyPresentation: got error %v, want nil", err)
	}
	if got.Holder != "did:example:holder" {
		t.Errorf("holder: got %q, want %q", got.Holder, "did:example:holder")
	}
	if got.ID != "urn:uuid:presentation-1" {
		t.Errorf("id: got %q, want %q", got.ID, "urn:uuid:presentation-1")
	}
	if len(got.VerifiableCredential) != 1 || got.VerifiableCredential[0] != credToken {
		t.Errorf("verifiableCredential: got %v, want [%s]", got.VerifiableCredential, credToken)
	}

	// The embedded credential should verify against the issuer key.
	embedded, err := Verify(got.VerifiableCredential[0], issuerPub, VerifyOptions{})
	if err != nil {
		t.Fatalf("Verify embedded credential: got error %v, want nil", err)
	}
	if embedded.Issuer != cred.Issuer {
		t.Errorf("embedded issuer: got %q, want %q", embedded.Issuer, cred.Issuer)
	}
}

func TestPresentRequiredFields(t *testing.T) {
	t.Parallel()

	priv, _, err := ed25519.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: got error %v, want nil", err)
	}

	tests := []struct {
		name    string
		creds   []string
		opts    PresentOptions
		wantErr error
	}{
		{
			name:    "no credentials",
			creds:   nil,
			opts:    PresentOptions{Holder: "did:example:holder"},
			wantErr: ErrInvalidPresentation,
		},
		{
			name:    "no holder",
			creds:   []string{"dummy"},
			opts:    PresentOptions{},
			wantErr: ErrInvalidPresentation,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, err := Present(tt.creds, priv, tt.opts)
			if !errors.Is(err, tt.wantErr) {
				t.Errorf("Present: got error %v, want errors.Is(_, %v)", err, tt.wantErr)
			}
		})
	}
}

func TestVerifyPresentationNegative(t *testing.T) {
	t.Parallel()

	priv, pub, err := ed25519.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: got error %v, want nil", err)
	}

	presToken, err := Present([]string{"dummy-credential"}, priv, PresentOptions{Holder: "did:example:holder"})
	if err != nil {
		t.Fatalf("Present: got error %v, want nil", err)
	}

	tests := []struct {
		name    string
		opts    VerifyPresentationOptions
		wantErr error
	}{
		{
			name:    "holder mismatch",
			opts:    VerifyPresentationOptions{ExpectedHolder: "did:example:other"},
			wantErr: jwkutil.ErrIssuerMismatch,
		},
		{
			name:    "audience mismatch",
			opts:    VerifyPresentationOptions{ExpectedAudience: []string{"did:example:other"}},
			wantErr: jwkutil.ErrAudienceMismatch,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, err := VerifyPresentation(presToken, pub, tt.opts)
			if !errors.Is(err, tt.wantErr) {
				t.Errorf("VerifyPresentation: got error %v, want errors.Is(_, %v)", err, tt.wantErr)
			}
		})
	}
}

func TestIssueAlgorithmOptions(t *testing.T) {
	t.Parallel()

	priv, pub, err := ed25519.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: got error %v, want nil", err)
	}

	cred := Credential{
		Type:   []string{"VerifiableCredential"},
		Issuer: "did:example:issuer",
		CredentialSubject: map[string]any{
			"id": "did:example:subject",
		},
	}

	token, err := Issue(cred, priv, IssueOptions{Algorithm: "EdDSA"})
	if err != nil {
		t.Fatalf("Issue with explicit alg: got error %v, want nil", err)
	}
	if !strings.HasPrefix(token, "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9.") {
		t.Errorf("token prefix: got %q, want EdDSA JWT header", token[:strings.Index(token, ".")+1])
	}

	_, err = Verify(token, pub, VerifyOptions{Algorithm: "EdDSA"})
	if err != nil {
		t.Errorf("Verify with explicit alg: got error %v, want nil", err)
	}
}
