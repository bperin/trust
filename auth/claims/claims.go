package claims

import (
	"crypto"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	jwkutil "github.com/bperin/trust/identity/jwk"
	"github.com/bperin/trust/signature"
)

var (
	ErrMalformedJWT = errors.New("claims: malformed JWT")
	ErrExpired      = errors.New("claims: token is expired")
	ErrNotYetValid  = errors.New("claims: token not yet valid")
	ErrIssuer       = errors.New("claims: invalid issuer")
	ErrAudience     = errors.New("claims: invalid audience")
	ErrInvalid      = errors.New("claims: invalid claims")
)

// Claims represents standard JWT claims (RFC 7519).
type Claims struct {
	Issuer    string   `json:"iss,omitempty"`
	Subject   string   `json:"sub,omitempty"`
	Audience  []string `json:"aud,omitempty"`
	ExpiresAt int64    `json:"exp,omitempty"`
	NotBefore int64    `json:"nbf,omitempty"`
	IssuedAt  int64    `json:"iat,omitempty"`
	ID        string   `json:"jti,omitempty"`

	// Extra allows custom or additional claims.
	Extra map[string]any `json:"-"`
}

type claimsAlias Claims

// UnmarshalJSON implements custom unmarshaling to capture extra claims.
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

// MarshalJSON implements custom marshaling to include extra claims.
func (c Claims) MarshalJSON() ([]byte, error) {
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

// Options configures validation or signing.
type Options struct {
	Algorithm        string
	ExpectedIssuer   string
	ExpectedAudience []string
	Headers          map[string]any
	Now              func() time.Time
}

// Sign signs the Claims with the given private key using trust/identity/jwk (jwkutil).
// When opts.Algorithm is empty, the algorithm is derived from the key type
// via signature.AlgorithmForPrivateKey.
func Sign(claims Claims, privateKey crypto.PrivateKey, opts Options) (string, error) {
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
	return jwkutil.Sign(payload, privateKey, jwkutil.SignOptions{
		Algorithm: alg,
		Headers:   opts.Headers,
	})
}

// Verify parses and verifies a JWT token string using the public key and options.
func Verify(token string, publicKey crypto.PublicKey, opts Options) (*Claims, error) {
	verifyOpts := jwkutil.VerifyOptions{
		Algorithm:        opts.Algorithm,
		ExpectedIssuer:   opts.ExpectedIssuer,
		ExpectedAudience: opts.ExpectedAudience,
	}

	payload, err := jwkutil.Verify(token, publicKey, verifyOpts)
	if err != nil {
		return nil, fmt.Errorf("claims verify: %w", err)
	}

	var claims Claims
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalid, err)
	}

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
