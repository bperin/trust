package credential

import (
	"crypto"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/bperin/trust/crypto/ed25519"
	"github.com/bperin/trust/crypto/hash"
	"github.com/bperin/trust/evidence"
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

// validVersionedClaim returns a well-formed claim for the versioned-claim
// tests. Fixed timestamps keep the claim deterministic.
func validVersionedClaim() *VersionedClaim {
	issued := time.Date(2024, 1, 15, 12, 0, 0, 0, time.UTC)
	return &VersionedClaim{
		Version:   1,
		Schema:    "https://example.com/schemas/price/v1",
		Subject:   "did:example:subject",
		Resource:  "urn:example:sku:123",
		Issuer:    "did:example:issuer",
		IssuedAt:  issued,
		NotBefore: issued,
		NotAfter:  issued.Add(365 * 24 * time.Hour),
		Payload: map[string]interface{}{
			"amount":   25,
			"currency": "USD",
		},
		Evidence: []evidence.EvidenceRef{
			{
				Type:        "json",
				URI:         "ipfs://bafy-evidence-1",
				ContentHash: evidence.HashContent([]byte("evidence one")),
			},
			{
				Type:        "pdf",
				URI:         "ipfs://bafy-evidence-2",
				ContentHash: evidence.HashContent([]byte("evidence two")),
			},
		},
	}
}

func TestVersionedClaimCanonicalHashKnownAnswer(t *testing.T) {
	t.Parallel()

	// Fixed claim: every field is a compile-time-constant input so the
	// canonical form below is derivable by hand per [RFC 8785] §3.2 —
	// object keys sorted by UTF-16 code unit, no whitespace, numbers in
	// ECMAScript shortest round-trip form. ContentHash is a [32]byte
	// array, so it marshals as a JSON array of numbers, not base64.
	var ones [32]byte
	for i := range ones {
		ones[i] = 0x01
	}
	claim := &VersionedClaim{
		Version:   1,
		Schema:    "https://example.com/schemas/price/v1",
		Subject:   "did:example:subject",
		Resource:  "urn:example:sku:123",
		Issuer:    "did:example:issuer",
		IssuedAt:  time.Date(2024, 1, 15, 12, 0, 0, 0, time.UTC),
		NotBefore: time.Date(2024, 1, 15, 12, 0, 0, 0, time.UTC),
		NotAfter:  time.Date(2025, 1, 15, 12, 0, 0, 0, time.UTC),
		Payload:   map[string]interface{}{"amount": 25, "currency": "USD"},
		Evidence: []evidence.EvidenceRef{
			{Type: "json", URI: "ipfs://bafy-evidence", ContentHash: ones},
		},
	}

	// Vector: [RFC 8785] §3.2 JCS canonical form derived by hand; the
	// digest is [FIPS 180-4] SHA-256 over those bytes. Key order:
	// evidence < issuedAt < issuer < notAfter < notBefore < payload <
	// resource < schema < subject < version.
	hashArray := strings.Repeat("1,", 31) + "1" // 32 elements, each 0x01
	wantJSON := `{"evidence":[{"contentHash":[` + hashArray + `],"type":"json","uri":"ipfs://bafy-evidence"}],` +
		`"issuedAt":"2024-01-15T12:00:00Z","issuer":"did:example:issuer",` +
		`"notAfter":"2025-01-15T12:00:00Z","notBefore":"2024-01-15T12:00:00Z",` +
		`"payload":{"amount":25,"currency":"USD"},"resource":"urn:example:sku:123",` +
		`"schema":"https://example.com/schemas/price/v1","subject":"did:example:subject","version":1}`
	want := hash.NewSHA256().Sum([]byte(wantJSON))

	got, err := CanonicalHash(claim)
	if err != nil {
		t.Fatalf("CanonicalHash: got error %v, want nil", err)
	}
	if subtle.ConstantTimeCompare(got[:], want[:]) != 1 {
		t.Errorf("CanonicalHash: got %x, want %x (SHA-256 of %s)", got, want, wantJSON)
	}
}

func TestVersionedClaimRoundTrip(t *testing.T) {
	t.Parallel()

	claim := validVersionedClaim()

	raw, err := json.Marshal(claim)
	if err != nil {
		t.Fatalf("Marshal: got error %v, want nil", err)
	}
	before, err := CanonicalHash(claim)
	if err != nil {
		t.Fatalf("CanonicalHash before marshal: got error %v, want nil", err)
	}

	var decoded VersionedClaim
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("Unmarshal: got error %v, want nil", err)
	}
	after, err := CanonicalHash(&decoded)
	if err != nil {
		t.Fatalf("CanonicalHash after unmarshal: got error %v, want nil", err)
	}

	if subtle.ConstantTimeCompare(before[:], after[:]) != 1 {
		t.Errorf("round-trip hash: got %x, want %x", after, before)
	}
	if err := Validate(&decoded); err != nil {
		t.Errorf("Validate round-tripped claim: got error %v, want nil", err)
	}
}

func TestVersionedClaimValidate(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		mutate   func(*VersionedClaim)
		nilClaim bool
		wantErr  error
	}{
		{
			name:    "valid claim with evidence",
			mutate:  func(*VersionedClaim) {},
			wantErr: nil,
		},
		{
			name:     "nil claim",
			nilClaim: true,
			wantErr:  ErrMissingField,
		},
		{
			name:    "version zero",
			mutate:  func(c *VersionedClaim) { c.Version = 0 },
			wantErr: ErrWrongVersion,
		},
		{
			name:    "missing schema",
			mutate:  func(c *VersionedClaim) { c.Schema = "" },
			wantErr: ErrMissingField,
		},
		{
			name:    "missing subject",
			mutate:  func(c *VersionedClaim) { c.Subject = "" },
			wantErr: ErrMissingField,
		},
		{
			name:    "missing resource",
			mutate:  func(c *VersionedClaim) { c.Resource = "" },
			wantErr: ErrMissingField,
		},
		{
			name:    "missing issuer",
			mutate:  func(c *VersionedClaim) { c.Issuer = "" },
			wantErr: ErrMissingField,
		},
		{
			name:    "inverted validity window",
			mutate:  func(c *VersionedClaim) { c.NotBefore, c.NotAfter = c.NotAfter, c.NotBefore },
			wantErr: ErrInvalidWindow,
		},
		{
			name:    "evidence zero content hash",
			mutate:  func(c *VersionedClaim) { c.Evidence[1].ContentHash = [32]byte{} },
			wantErr: ErrEvidenceHashMissing,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var claim *VersionedClaim
			if !tt.nilClaim {
				claim = validVersionedClaim()
				tt.mutate(claim)
			}
			err := Validate(claim)
			if !errors.Is(err, tt.wantErr) {
				t.Errorf("Validate: got error %v, want errors.Is(_, %v)", err, tt.wantErr)
			}
		})
	}
}

func TestVersionedClaimEvidenceVerifyContent(t *testing.T) {
	t.Parallel()

	claim := validVersionedClaim()
	if err := Validate(claim); err != nil {
		t.Fatalf("Validate: got error %v, want nil", err)
	}

	// Correct content verifies against the ref's ContentHash.
	if err := evidence.VerifyContent(claim.Evidence[0], []byte("evidence one")); err != nil {
		t.Errorf("VerifyContent correct content: got error %v, want nil", err)
	}

	tests := []struct {
		name    string
		ref     evidence.EvidenceRef
		content []byte
		wantErr error
	}{
		{
			name:    "wrong content",
			ref:     claim.Evidence[0],
			content: []byte("forged evidence"),
			wantErr: evidence.ErrContentHashMismatch,
		},
		{
			name: "zero content hash",
			ref: evidence.EvidenceRef{
				Type: "json",
				URI:  "ipfs://bafy-evidence",
			},
			content: []byte("evidence one"),
			wantErr: evidence.ErrMissingContentHash,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := evidence.VerifyContent(tt.ref, tt.content)
			if !errors.Is(err, tt.wantErr) {
				t.Errorf("VerifyContent: got error %v, want errors.Is(_, %v)", err, tt.wantErr)
			}
		})
	}
}

func TestVersionedClaimCanonicalHashDeterminism(t *testing.T) {
	t.Parallel()

	// Two independently built claims with the same logical content —
	// including payload keys inserted in different order — must produce
	// the same canonical hash.
	a := validVersionedClaim()
	b := validVersionedClaim()
	b.Payload = map[string]interface{}{
		"currency": "USD",
		"amount":   25,
	}

	hashA, err := CanonicalHash(a)
	if err != nil {
		t.Fatalf("CanonicalHash a: got error %v, want nil", err)
	}
	hashB, err := CanonicalHash(b)
	if err != nil {
		t.Fatalf("CanonicalHash b: got error %v, want nil", err)
	}
	if subtle.ConstantTimeCompare(hashA[:], hashB[:]) != 1 {
		t.Errorf("determinism: got %x, want %x", hashB, hashA)
	}

	// A differing claim must produce a different identity.
	c := validVersionedClaim()
	c.Subject = "did:example:other"
	hashC, err := CanonicalHash(c)
	if err != nil {
		t.Fatalf("CanonicalHash c: got error %v, want nil", err)
	}
	if subtle.ConstantTimeCompare(hashA[:], hashC[:]) == 1 {
		t.Errorf("distinct claims: got identical hash %x, want different", hashC)
	}
}

func TestCanonicalHashNilClaim(t *testing.T) {
	t.Parallel()

	_, err := CanonicalHash(nil)
	if !errors.Is(err, ErrMissingField) {
		t.Errorf("CanonicalHash(nil): got error %v, want errors.Is(_, ErrMissingField)", err)
	}
}
