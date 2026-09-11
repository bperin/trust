package credential

import (
	"crypto"
	"crypto/elliptic"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/bperin/trust/crypto/ecdsa"
	"github.com/bperin/trust/crypto/ed25519"
	"github.com/bperin/trust/crypto/rsa"
	"github.com/bperin/trust/crypto/secp256k1"
	jwkutil "github.com/bperin/trust/identity/jwk"
)

// Sentinel errors returned by Issue, Verify, Present and
// VerifyPresentation. Check them with errors.Is.
var (
	// ErrInvalidCredential is returned when a credential lacks required
	// fields or is otherwise malformed.
	ErrInvalidCredential = errors.New("credential: invalid credential")
	// ErrInvalidPresentation is returned when a presentation lacks
	// required fields or is otherwise malformed.
	ErrInvalidPresentation = errors.New("credential: invalid presentation")
	// ErrInvalidToken is returned when a JWT token is malformed or its
	// payload is not a JSON claims object.
	ErrInvalidToken = errors.New("credential: invalid token")
	// ErrMissingClaim is returned when an expected JWT claim or embedded
	// credential/presentation object is absent.
	ErrMissingClaim = errors.New("credential: missing claim")
	// ErrExpired is returned when the credential or presentation has an
	// "exp" claim in the past.
	ErrExpired = errors.New("credential: token expired")
)

// Credential is a [W3C VC-DATA-MODEL] Verifiable Credential. It omits the
// embedded proof in the JWT encoding; the proof is the JWS signature itself.
type Credential struct {
	// Context is the JSON-LD context array. Defaults to the VC v1 context
	// when issuing if empty.
	Context []string `json:"@context,omitempty"`
	// ID is an optional URI that identifies this credential.
	ID string `json:"id,omitempty"`
	// Type is the credential type array, e.g. ["VerifiableCredential"].
	Type []string `json:"type"`
	// Issuer identifies the credential issuer, typically a DID.
	Issuer string `json:"issuer"`
	// IssuanceDate is an RFC3339 timestamp.
	IssuanceDate string `json:"issuanceDate"`
	// ExpirationDate is an optional RFC3339 timestamp.
	ExpirationDate string `json:"expirationDate,omitempty"`
	// CredentialSubject contains the claims about the subject. The "id"
	// member, when present, becomes the JWT "sub" claim.
	CredentialSubject map[string]any `json:"credentialSubject"`
	// Proof is only populated for non-JWT credentials; Issue does not set it.
	Proof *Proof `json:"proof,omitempty"`
}

// Proof is a [W3C VC-DATA-MODEL] proof object. This package issues JWT
// proofs, so Proof is provided for callers that need embedded proof support.
type Proof struct {
	Type               string `json:"type"`
	Created            string `json:"created"`
	ProofPurpose       string `json:"proofPurpose"`
	VerificationMethod string `json:"verificationMethod"`
	// JWS carries a detached or compact JWS for JWT proofs.
	JWS string `json:"jws,omitempty"`
	// ProofValue carries a base-encoded signature for non-JWT proofs.
	ProofValue string `json:"proofValue,omitempty"`
}

// Presentation is a [W3C VC-DATA-MODEL] Verifiable Presentation. The
// VerifiableCredential field holds JWT strings in the JWT encoding.
type Presentation struct {
	Context              []string `json:"@context,omitempty"`
	ID                   string   `json:"id,omitempty"`
	Type                 []string `json:"type"`
	Holder               string   `json:"holder,omitempty"`
	VerifiableCredential []string `json:"verifiableCredential"`
}

// IssueOptions configures Issue.
type IssueOptions struct {
	// Audience is the intended recipient for the JWT "aud" claim.
	Audience string
	// ExpiresAt sets the JWT "exp" claim. If zero, no exp claim is added.
	ExpiresAt time.Time
	// ID overrides the credential ID for the JWT "jti" claim.
	ID string
	// VerificationMethod is the URI of the signing key, placed in the JWS
	// "kid" header.
	VerificationMethod string
	// Algorithm, if non-empty, pins the JWS "alg" value. If empty, the
	// algorithm is derived from the key type.
	Algorithm string
	// Headers are extra protected JWS headers. "alg" and "typ" may not be
	// set here.
	Headers map[string]any
}

// VerifyOptions configures Verify.
type VerifyOptions struct {
	// ExpectedIssuer, when non-empty, requires the JWT "iss" claim to match.
	ExpectedIssuer string
	// ExpectedAudience, when non-empty, requires the JWT "aud" claim to
	// contain at least one of the values.
	ExpectedAudience []string
	// Algorithm, when non-empty, pins the expected JWS "alg" value.
	Algorithm string
}

// PresentOptions configures Present.
type PresentOptions struct {
	// Audience is the intended recipient for the JWT "aud" claim.
	Audience string
	// ExpiresAt sets the JWT "exp" claim.
	ExpiresAt time.Time
	// Holder identifies the presenter and becomes the JWT "iss" claim.
	Holder string
	// ID is an optional presentation identifier.
	ID string
	// VerificationMethod is the signing key URI for the JWS "kid" header.
	VerificationMethod string
	// Algorithm, if non-empty, pins the JWS "alg" value.
	Algorithm string
	// Headers are extra protected JWS headers. "alg" and "typ" may not be
	// set here.
	Headers map[string]any
}

// VerifyPresentationOptions configures VerifyPresentation.
type VerifyPresentationOptions struct {
	// ExpectedHolder, when non-empty, requires the JWT "iss" claim to match.
	ExpectedHolder string
	// ExpectedAudience, when non-empty, requires the JWT "aud" claim to
	// contain at least one of the values.
	ExpectedAudience []string
	// Algorithm, when non-empty, pins the expected JWS "alg" value.
	Algorithm string
}

const (
	vcContextV1 = "https://www.w3.org/2018/credentials/v1"
	vcType      = "VerifiableCredential"
	vpType      = "VerifiablePresentation"
	jwtType     = "JWT"
)

// Issue implements [W3C VC-DATA-MODEL] §4.7 and [VC-JWT] §6.1 — it issues a
// Verifiable Credential as a JWT. The credential is embedded in the "vc"
// claim and signed with the issuer's private key.
func Issue(cred Credential, key crypto.PrivateKey, opts IssueOptions) (string, error) {
	if cred.Issuer == "" {
		return "", fmt.Errorf("%w: issuer is required", ErrInvalidCredential)
	}
	if len(cred.Type) == 0 {
		return "", fmt.Errorf("%w: type is required", ErrInvalidCredential)
	}
	if cred.CredentialSubject == nil {
		return "", fmt.Errorf("%w: credentialSubject is required", ErrInvalidCredential)
	}

	alg := opts.Algorithm
	if alg == "" {
		derived, err := algorithmForPrivateKey(key)
		if err != nil {
			return "", err
		}
		alg = derived
	}

	claims, err := buildCredentialClaims(cred, opts)
	if err != nil {
		return "", err
	}

	headers := make(map[string]any, len(opts.Headers)+2)
	headers["typ"] = jwtType
	if opts.VerificationMethod != "" {
		headers["kid"] = opts.VerificationMethod
	}
	for k, v := range opts.Headers {
		if k == "alg" || k == "typ" {
			return "", fmt.Errorf("%w: header %q is controlled by the issuer", jwkutil.ErrInvalidMember, k)
		}
		headers[k] = v
	}

	payload, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("credential issue: marshal claims: %w", err)
	}

	return jwkutil.Sign(payload, key, jwkutil.SignOptions{Algorithm: alg, Headers: headers})
}

// Verify implements [VC-JWT] §6.2 — it verifies a JWT credential and
// returns the embedded [Credential].
func Verify(token string, key crypto.PublicKey, opts VerifyOptions) (*Credential, error) {
	payload, err := jwkutil.Verify(token, key, jwkutil.VerifyOptions{
		Algorithm:        opts.Algorithm,
		ExpectedIssuer:   opts.ExpectedIssuer,
		ExpectedAudience: opts.ExpectedAudience,
	})
	if err != nil {
		return nil, fmt.Errorf("credential verify: %w", err)
	}

	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidToken, err)
	}

	vcRaw, ok := claims["vc"]
	if !ok {
		return nil, fmt.Errorf("%w: vc", ErrMissingClaim)
	}

	vcBytes, err := json.Marshal(vcRaw)
	if err != nil {
		return nil, fmt.Errorf("credential verify: marshal vc: %w", err)
	}

	var cred Credential
	if err := json.Unmarshal(vcBytes, &cred); err != nil {
		return nil, fmt.Errorf("credential verify: unmarshal credential: %w", err)
	}

	return &cred, nil
}

// Present implements [W3C VC-DATA-MODEL] §4.8 and [VC-JWT] §6.3 — it
// creates a Verifiable Presentation JWT that wraps one or more JWT
// credentials.
func Present(creds []string, key crypto.PrivateKey, opts PresentOptions) (string, error) {
	if len(creds) == 0 {
		return "", fmt.Errorf("%w: at least one credential is required", ErrInvalidPresentation)
	}
	if opts.Holder == "" {
		return "", fmt.Errorf("%w: holder is required", ErrInvalidPresentation)
	}

	alg := opts.Algorithm
	if alg == "" {
		derived, err := algorithmForPrivateKey(key)
		if err != nil {
			return "", err
		}
		alg = derived
	}

	claims, err := buildPresentationClaims(creds, opts)
	if err != nil {
		return "", err
	}

	headers := make(map[string]any, len(opts.Headers)+2)
	headers["typ"] = jwtType
	if opts.VerificationMethod != "" {
		headers["kid"] = opts.VerificationMethod
	}
	for k, v := range opts.Headers {
		if k == "alg" || k == "typ" {
			return "", fmt.Errorf("%w: header %q is controlled by the presenter", jwkutil.ErrInvalidMember, k)
		}
		headers[k] = v
	}

	payload, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("credential present: marshal claims: %w", err)
	}

	return jwkutil.Sign(payload, key, jwkutil.SignOptions{Algorithm: alg, Headers: headers})
}

// VerifyPresentation implements [VC-JWT] §6.4 — it verifies a presentation
// JWT and returns the embedded [Presentation]. Callers must verify each
// embedded credential separately if they were not issued by the holder.
func VerifyPresentation(token string, key crypto.PublicKey, opts VerifyPresentationOptions) (*Presentation, error) {
	payload, err := jwkutil.Verify(token, key, jwkutil.VerifyOptions{
		Algorithm:        opts.Algorithm,
		ExpectedIssuer:   opts.ExpectedHolder,
		ExpectedAudience: opts.ExpectedAudience,
	})
	if err != nil {
		return nil, fmt.Errorf("credential verify presentation: %w", err)
	}

	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidToken, err)
	}

	vpRaw, ok := claims["vp"]
	if !ok {
		return nil, fmt.Errorf("%w: vp", ErrMissingClaim)
	}

	vpBytes, err := json.Marshal(vpRaw)
	if err != nil {
		return nil, fmt.Errorf("credential verify presentation: marshal vp: %w", err)
	}

	var pres Presentation
	if err := json.Unmarshal(vpBytes, &pres); err != nil {
		return nil, fmt.Errorf("credential verify presentation: unmarshal presentation: %w", err)
	}

	return &pres, nil
}

func buildCredentialClaims(cred Credential, opts IssueOptions) (map[string]any, error) {
	now := time.Now().UTC()

	if len(cred.Context) == 0 {
		cred.Context = []string{vcContextV1}
	}
	if cred.IssuanceDate == "" {
		cred.IssuanceDate = now.Format(time.RFC3339)
	}

	claims := map[string]any{
		"iss": cred.Issuer,
		"vc":  cred,
		"iat": now.Unix(),
	}

	if cred.ID != "" {
		claims["jti"] = cred.ID
	} else if opts.ID != "" {
		claims["jti"] = opts.ID
	}

	if cred.ExpirationDate != "" {
		t, err := time.Parse(time.RFC3339, cred.ExpirationDate)
		if err == nil && !t.IsZero() {
			claims["exp"] = t.Unix()
		}
	}
	if !opts.ExpiresAt.IsZero() {
		claims["exp"] = opts.ExpiresAt.Unix()
	}

	subjectID, _ := cred.CredentialSubject["id"].(string)
	if subjectID != "" {
		claims["sub"] = subjectID
	}
	if opts.Audience != "" {
		claims["aud"] = opts.Audience
	}

	return claims, nil
}

func buildPresentationClaims(creds []string, opts PresentOptions) (map[string]any, error) {
	now := time.Now().UTC()

	vp := map[string]any{
		"@context":             []string{vcContextV1},
		"type":                 []string{vpType},
		"verifiableCredential": creds,
	}
	if opts.Holder != "" {
		vp["holder"] = opts.Holder
	}
	if opts.ID != "" {
		vp["id"] = opts.ID
	}

	claims := map[string]any{
		"iss": opts.Holder,
		"vp":  vp,
		"iat": now.Unix(),
	}
	if opts.ID != "" {
		claims["jti"] = opts.ID
	}
	if !opts.ExpiresAt.IsZero() {
		claims["exp"] = opts.ExpiresAt.Unix()
	}
	if opts.Audience != "" {
		claims["aud"] = opts.Audience
	}

	return claims, nil
}

func algorithmForPrivateKey(key crypto.PrivateKey) (string, error) {
	switch k := key.(type) {
	case *ed25519.PrivateKey:
		return "EdDSA", nil
	case *secp256k1.PrivateKey:
		return "ES256K", nil
	case *ecdsa.PrivateKey:
		switch k.Curve() {
		case elliptic.P256():
			return "ES256", nil
		case elliptic.P384():
			return "ES384", nil
		}
		return "", fmt.Errorf("%w: unsupported ECDSA curve for credential", jwkutil.ErrUnsupportedAlg)
	case *rsa.PSSPrivateKey:
		switch k.Public().Hash() {
		case crypto.SHA256:
			return "PS256", nil
		case crypto.SHA384:
			return "PS384", nil
		case crypto.SHA512:
			return "PS512", nil
		}
		return "", fmt.Errorf("%w: unsupported RSA-PSS hash for credential", jwkutil.ErrUnsupportedAlg)
	case *rsa.PKCS1PrivateKey:
		switch k.Public().Hash() {
		case crypto.SHA256:
			return "RS256", nil
		case crypto.SHA384:
			return "RS384", nil
		case crypto.SHA512:
			return "RS512", nil
		}
		return "", fmt.Errorf("%w: unsupported RSA-PKCS1 hash for credential", jwkutil.ErrUnsupportedAlg)
	}
	return "", fmt.Errorf("%w: key type %T", jwkutil.ErrUnsupportedAlg, key)
}
