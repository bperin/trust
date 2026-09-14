// Package claims implements JWT ([RFC 7519]) claim representation, signing,
// and verification. It is the authoritative owner of JWT claim policy for the
// auth module: registered-claim rejection in [Claims.Extra] (finding A14),
// per-key algorithm whitelisting, "alg":"none" rejection, required-claim
// profiles, and time/issuer/audience validation against a single clock.
//
// Signature and algorithm verification delegate to the generic JWK/JWS key
// representation in trust/identity/jwk via [VerifySignature], which performs
// no claim validation. This keeps one clock source (opts.Now) in this package
// and avoids the duplicated validation that arises when the JWS layer also
// validates claims.
package claims

import (
	"crypto"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	jwkutil "github.com/bperin/trust/identity/jwk"
	"github.com/bperin/trust/signature"
)

// Sentinel errors returned by Sign and Verify. Check them with errors.Is.
// Wrap with fmt.Errorf and %w at boundaries.
var (
	// ErrMalformedJWT is returned when the token is not a valid compact JWS.
	ErrMalformedJWT = errors.New("claims: malformed JWT")
	// ErrExpired is returned when the "exp" claim is in the past.
	ErrExpired = errors.New("claims: token is expired")
	// ErrNotYetValid is returned when the "nbf" or "iat" claim is in the
	// future.
	ErrNotYetValid = errors.New("claims: token not yet valid")
	// ErrIssuer is returned when the "iss" claim does not match the expected
	// issuer.
	ErrIssuer = errors.New("claims: invalid issuer")
	// ErrAudience is returned when the "aud" claim does not contain any
	// expected audience.
	ErrAudience = errors.New("claims: invalid audience")
	// ErrInvalid is returned when the payload is not a JSON claims object.
	ErrInvalid = errors.New("claims: invalid claims")
	// ErrAlgNone is returned when the token "alg" header is "none". The alg
	// header is never trusted: "alg":"none" is rejected before any signature
	// work per the security rule in AGENTS.md.
	ErrAlgNone = errors.New("claims: alg none is not allowed")
	// ErrAlgNotAllowed is returned when the token "alg" header is not in the
	// per-key algorithm whitelist configured in [Options.AllowedAlgorithms].
	ErrAlgNotAllowed = errors.New("claims: algorithm not allowed")
	// ErrReservedClaim is returned when [Claims.Extra] contains a registered
	// claim name (finding A14). Registered claims are represented by
	// dedicated struct fields; allowing them in Extra would let an attacker
	// overwrite the registered claim during marshaling.
	ErrReservedClaim = errors.New("claims: reserved claim name in extra")
	// ErrMissingRequiredClaim is returned when a claim required by the
	// configured [Options.RequiredClaims] profile is absent.
	ErrMissingRequiredClaim = errors.New("claims: missing required claim")
)

// reservedClaims are the [RFC 7519] §4.1 registered claim names. They are
// represented by dedicated [Claims] fields and must never appear in
// [Claims.Extra] — an Extra entry with one of these names would overwrite the
// registered claim when the struct is marshaled (finding A14).
var reservedClaims = map[string]struct{}{
	"iss": {},
	"sub": {},
	"aud": {},
	"exp": {},
	"nbf": {},
	"iat": {},
	"jti": {},
}

// Claims represents standard JWT claims ([RFC 7519] §4.1).
type Claims struct {
	Issuer    string   `json:"iss,omitempty"`
	Subject   string   `json:"sub,omitempty"`
	Audience  []string `json:"aud,omitempty"`
	ExpiresAt int64    `json:"exp,omitempty"`
	NotBefore int64    `json:"nbf,omitempty"`
	IssuedAt  int64    `json:"iat,omitempty"`
	ID        string   `json:"jti,omitempty"`

	// Extra allows custom or additional claims. It must not contain a
	// registered claim name (iss, sub, aud, exp, nbf, iat, jti); doing so is
	// rejected as finding A14 — a reserved name here would overwrite the
	// registered claim during marshaling.
	Extra map[string]any `json:"-"`
}

// claimsAlias is reserved for future anonymous-field marshaling.
type claimsAlias Claims

// UnmarshalJSON implements custom unmarshaling to capture extra claims.
// Registered claim names are routed to their dedicated fields and never
// enter Extra, so a token cannot smuggle a reserved name into Extra via
// unmarshaling.
func (c *Claims) UnmarshalJSON(data []byte) error {
	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}

	if v, ok := raw["iss"]; ok {
		if s, ok := v.(string); ok {
			c.Issuer = s
		}
	}
	if v, ok := raw["sub"]; ok {
		if s, ok := v.(string); ok {
			c.Subject = s
		}
	}
	if v, ok := raw["aud"]; ok {
		switch aud := v.(type) {
		case string:
			c.Audience = []string{aud}
		case []any:
			var auds []string
			for _, item := range aud {
				if s, ok := item.(string); ok {
					auds = append(auds, s)
				}
			}
			c.Audience = auds
		}
	}
	if v, ok := raw["exp"]; ok {
		if f, ok := v.(float64); ok {
			c.ExpiresAt = int64(f)
		}
	}
	if v, ok := raw["nbf"]; ok {
		if f, ok := v.(float64); ok {
			c.NotBefore = int64(f)
		}
	}
	if v, ok := raw["iat"]; ok {
		if f, ok := v.(float64); ok {
			c.IssuedAt = int64(f)
		}
	}
	if v, ok := raw["jti"]; ok {
		if s, ok := v.(string); ok {
			c.ID = s
		}
	}

	extra := make(map[string]any)
	for k, v := range raw {
		switch k {
		case "iss", "sub", "aud", "exp", "nbf", "iat", "jti":
			// skip standard claims
		default:
			extra[k] = v
		}
	}
	if len(extra) > 0 {
		c.Extra = extra
	}
	return nil
}

// MarshalJSON implements custom marshaling to include extra claims. A
// reserved claim name in Extra is rejected (finding A14): it would overwrite
// the registered claim field in the output object.
func (c Claims) MarshalJSON() ([]byte, error) {
	for k := range c.Extra {
		if _, reserved := reservedClaims[k]; reserved {
			return nil, fmt.Errorf("%w: %q", ErrReservedClaim, k)
		}
	}

	m := make(map[string]any)
	if c.Issuer != "" {
		m["iss"] = c.Issuer
	}
	if c.Subject != "" {
		m["sub"] = c.Subject
	}
	if len(c.Audience) == 1 {
		m["aud"] = c.Audience[0]
	} else if len(c.Audience) > 1 {
		m["aud"] = c.Audience
	}
	if c.ExpiresAt != 0 {
		m["exp"] = c.ExpiresAt
	}
	if c.NotBefore != 0 {
		m["nbf"] = c.NotBefore
	}
	if c.IssuedAt != 0 {
		m["iat"] = c.IssuedAt
	}
	if c.ID != "" {
		m["jti"] = c.ID
	}
	for k, v := range c.Extra {
		m[k] = v
	}
	return json.Marshal(m)
}

// Validate reports whether the claims are internally consistent: Extra must
// not contain a registered claim name (finding A14). It does not check
// time/issuer/audience policy — those depend on verification options and the
// clock, and are enforced by [Verify].
func (c Claims) Validate() error {
	for k := range c.Extra {
		if _, reserved := reservedClaims[k]; reserved {
			return fmt.Errorf("%w: %q", ErrReservedClaim, k)
		}
	}
	return nil
}

// Options configures signing ([Sign]) and verification ([Verify]).
type Options struct {
	// Algorithm is the JWS "alg" value. For Sign, when empty, the algorithm
	// is derived from the key type. For Verify, when non-empty, it pins the
	// expected "alg" in addition to the algorithm required by the key type.
	Algorithm string
	// AllowedAlgorithms is the per-key algorithm whitelist. When non-empty,
	// Verify rejects any token whose "alg" header is not in the list. This
	// is defense in depth on top of the key-type binding enforced by the
	// JWS layer: the alg header is never trusted.
	AllowedAlgorithms []string
	// ExpectedIssuer, when non-empty, requires the "iss" claim to equal it
	// exactly.
	ExpectedIssuer string
	// ExpectedAudience, when non-empty, requires the "aud" claim to contain
	// at least one of the values.
	ExpectedAudience []string
	// RequiredClaims is the required-claim profile: each named claim must be
	// present (non-zero) in the verified token. Use this to enforce a
	// profile, e.g. {"iss", "sub", "exp", "aud"} for access tokens.
	RequiredClaims []string
	// Headers are additional protected JWS headers for Sign, such as "kid"
	// or "typ". The "alg" and "crit" members may not be set here.
	Headers map[string]any
	// Now is the single clock source for time-based claim validation. When
	// nil, time.Now is used. All of exp, nbf, and iat are validated against
	// this one clock — there is no duplicated validation in the JWS layer.
	Now func() time.Time
}

// Sign signs the Claims with the given private key using the generic JWK/JWS
// key representation in trust/identity/jwk. When opts.Algorithm is empty, the
// algorithm is derived from the key type via signature.AlgorithmForPrivateKey.
// "alg":"none" is rejected before any key work.
func Sign(claims Claims, privateKey crypto.PrivateKey, opts Options) (string, error) {
	if err := claims.Validate(); err != nil {
		return "", fmt.Errorf("claims sign: %w", err)
	}
	if opts.Algorithm == "none" {
		return "", fmt.Errorf("claims sign: %w", ErrAlgNone)
	}
	if len(opts.AllowedAlgorithms) > 0 && opts.Algorithm != "" && !algAllowed(opts.Algorithm, opts.AllowedAlgorithms) {
		return "", fmt.Errorf("claims sign: %w: %q", ErrAlgNotAllowed, opts.Algorithm)
	}

	payload, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("claims sign: %w", err)
	}
	alg := opts.Algorithm
	if alg == "" {
		derived, err := signature.AlgorithmForPrivateKey(privateKey)
		if err != nil {
			return "", fmt.Errorf("claims sign: %w", err)
		}
		alg = derived.JOSE()
	}
	if len(opts.AllowedAlgorithms) > 0 && !algAllowed(alg, opts.AllowedAlgorithms) {
		return "", fmt.Errorf("claims sign: %w: %q", ErrAlgNotAllowed, alg)
	}
	return jwkutil.Sign(payload, privateKey, jwkutil.SignOptions{
		Algorithm: alg,
		Headers:   opts.Headers,
	})
}

// Verify parses and verifies a JWT token string using the public key and
// options. Signature and algorithm verification delegate to the generic JWS
// primitive [jwkutil.VerifySignature], which performs no claim validation;
// all claim policy — alg whitelist, "alg":"none" rejection, exp/nbf/iat/iss/aud
// validation, required-claim profiles, and reserved-claim rejection — is
// enforced here against the single clock in opts.Now.
func Verify(token string, publicKey crypto.PublicKey, opts Options) (*Claims, error) {
	// Reject "alg":"none" and enforce the per-key whitelist before any
	// signature work. The alg header is never trusted.
	alg, err := tokenAlgorithm(token)
	if err != nil {
		return nil, fmt.Errorf("claims verify: %w", err)
	}
	if alg == "none" {
		return nil, fmt.Errorf("claims verify: %w", ErrAlgNone)
	}
	if len(opts.AllowedAlgorithms) > 0 && !algAllowed(alg, opts.AllowedAlgorithms) {
		return nil, fmt.Errorf("claims verify: %w: %q", ErrAlgNotAllowed, alg)
	}

	// Generic JWS signature verification — no claim validation in the JWS
	// layer, so there is a single clock source (opts.Now) for claims.
	payload, err := jwkutil.VerifySignature(token, publicKey, jwkutil.VerifyOptions{
		Algorithm: opts.Algorithm,
	})
	if err != nil {
		return nil, fmt.Errorf("claims verify: %w", err)
	}

	var claims Claims
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalid, err)
	}

	// One clock source for all time-based validation.
	now := time.Now()
	if opts.Now != nil {
		now = opts.Now()
	}
	unixNow := now.Unix()

	if claims.ExpiresAt != 0 && unixNow >= claims.ExpiresAt {
		return nil, fmt.Errorf("%w: exp %d vs now %d", ErrExpired, claims.ExpiresAt, unixNow)
	}
	if claims.NotBefore != 0 && unixNow < claims.NotBefore {
		return nil, fmt.Errorf("%w: nbf %d vs now %d", ErrNotYetValid, claims.NotBefore, unixNow)
	}
	if claims.IssuedAt != 0 && unixNow < claims.IssuedAt {
		return nil, fmt.Errorf("%w: iat %d vs now %d", ErrNotYetValid, claims.IssuedAt, unixNow)
	}

	if opts.ExpectedIssuer != "" {
		if claims.Issuer != opts.ExpectedIssuer {
			return nil, fmt.Errorf("%w: got %q, want %q", ErrIssuer, claims.Issuer, opts.ExpectedIssuer)
		}
	}
	if len(opts.ExpectedAudience) > 0 {
		if !audienceContains(claims.Audience, opts.ExpectedAudience) {
			return nil, fmt.Errorf("%w: got %v, want one of %v", ErrAudience, claims.Audience, opts.ExpectedAudience)
		}
	}

	// Required-claim profile: each named claim must be present.
	if err := checkRequiredClaims(&claims, opts.RequiredClaims); err != nil {
		return nil, err
	}

	// A14: a reserved claim name in Extra would have overwritten a
	// registered claim. UnmarshalJSON routes registered names to fields, so
	// this is defensive — but a directly-constructed Claims with a reserved
	// Extra entry that was serialized elsewhere must still be rejected.
	if err := claims.Validate(); err != nil {
		return nil, fmt.Errorf("claims verify: %w", err)
	}

	return &claims, nil
}

// VerifyWithJWK parses and verifies a JWT token string using JWK bytes.
func VerifyWithJWK(token string, jwk []byte, opts Options) (*Claims, error) {
	key, err := jwkutil.PublicFromJWK(jwk)
	if err != nil {
		return nil, fmt.Errorf("claims verify with jwk: %w", err)
	}
	return Verify(token, key, opts)
}

// tokenAlgorithm extracts the "alg" member from the JWS protected header
// without verifying the signature. It is used only to reject "alg":"none"
// and enforce the per-key whitelist before any cryptographic work — the alg
// header is never trusted to select the verification algorithm.
func tokenAlgorithm(token string) (string, error) {
	dot := strings.IndexByte(token, '.')
	if dot < 0 || strings.Count(token, ".") != 2 {
		return "", fmt.Errorf("%w: not a compact serialization", ErrMalformedJWT)
	}
	headerJSON, err := base64.RawURLEncoding.DecodeString(token[:dot])
	if err != nil {
		return "", fmt.Errorf("%w: decode header: %v", ErrMalformedJWT, err)
	}
	var header map[string]any
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		return "", fmt.Errorf("%w: parse header: %v", ErrMalformedJWT, err)
	}
	alg, _ := header["alg"].(string)
	return alg, nil
}

// algAllowed reports whether alg is in the whitelist. Comparison is exact;
// the whitelist is a small, trusted set per key.
func algAllowed(alg string, allowed []string) bool {
	for _, a := range allowed {
		if a == alg {
			return true
		}
	}
	return false
}

// checkRequiredClaims reports whether every named claim in required is
// present (non-zero) in claims per the configured profile.
func checkRequiredClaims(claims *Claims, required []string) error {
	for _, name := range required {
		if !claimPresent(claims, name) {
			return fmt.Errorf("%w: %q", ErrMissingRequiredClaim, name)
		}
	}
	return nil
}

// claimPresent reports whether the named registered claim has a non-zero
// value. Custom claims in Extra are not covered by profiles — profiles
// govern registered claims.
func claimPresent(claims *Claims, name string) bool {
	switch name {
	case "iss":
		return claims.Issuer != ""
	case "sub":
		return claims.Subject != ""
	case "aud":
		return len(claims.Audience) > 0
	case "exp":
		return claims.ExpiresAt != 0
	case "nbf":
		return claims.NotBefore != 0
	case "iat":
		return claims.IssuedAt != 0
	case "jti":
		return claims.ID != ""
	default:
		// Unknown profile entries are treated as custom claims in Extra.
		_, ok := claims.Extra[name]
		return ok
	}
}

// audienceContains reports whether the "aud" claim contains at least one
// expected audience per [RFC 7519] §4.1.3.
func audienceContains(audience, expected []string) bool {
	for _, want := range expected {
		for _, got := range audience {
			if got == want {
				return true
			}
		}
	}
	return false
}
