package jwkutil

import (
	"crypto"
	"crypto/elliptic"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/bperin/trust/crypto/ecdsa"
	"github.com/bperin/trust/crypto/ed25519"
	"github.com/bperin/trust/crypto/hash"
	"github.com/bperin/trust/crypto/rsa"
	"github.com/bperin/trust/crypto/secp256k1"
)

// Sentinel errors returned by Sign, Verify, and VerifyWithJWK. Check them
// with errors.Is. The JWK sentinels ErrAlgNone, ErrAlgMismatch, and
// ErrAlgRequired are shared with the key serialization in this package.
var (
	// ErrMalformedJWS is returned when the compact serialization is not
	// exactly three dot-separated segments.
	ErrMalformedJWS = errors.New("jwkutil: malformed JWS compact serialization")
	// ErrInvalidSegment is returned when a segment is not canonical
	// unpadded base64url: padding characters, characters outside the
	// base64url alphabet, or non-canonical trailing bits are rejected.
	ErrInvalidSegment = errors.New("jwkutil: segment is not canonical base64url")
	// ErrCritUnsupported is returned when the protected header carries a
	// "crit" member. No extensions are implemented, so every crit header is
	// refused per [RFC 7515] §4.1.11.
	ErrCritUnsupported = errors.New("jwkutil: crit header is not supported")
	// ErrUnsupportedAlg is returned when the JWS "alg" value is not one of
	// the asymmetric algorithms this package implements, or the key type is
	// not a trust key.
	ErrUnsupportedAlg = errors.New("jwkutil: unsupported JWS algorithm")
	// ErrInvalidSignature is returned when the signature does not verify.
	ErrInvalidSignature = errors.New("jwkutil: invalid JWS signature")
	// ErrExpired is returned when the payload carries an "exp" claim that
	// has passed.
	ErrExpired = errors.New("jwkutil: token is expired")
	// ErrNotYetValid is returned when the payload carries an "nbf" or "iat"
	// claim in the future.
	ErrNotYetValid = errors.New("jwkutil: token not yet valid")
	// ErrIssuerMismatch is returned when the payload "iss" claim does not
	// match the expected issuer.
	ErrIssuerMismatch = errors.New("jwkutil: issuer mismatch")
	// ErrAudienceMismatch is returned when the payload "aud" claim does not
	// contain any expected audience.
	ErrAudienceMismatch = errors.New("jwkutil: audience mismatch")
	// ErrInvalidClaims is returned when claims validation is requested but
	// the payload is not a JSON object, or a time claim is not a number.
	ErrInvalidClaims = errors.New("jwkutil: payload is not a JSON claims object")
)

// SignOptions configures [Sign].
type SignOptions struct {
	// Algorithm is the JWS "alg" value. Required. It must match the key
	// type; the algorithm is never taken from the payload or headers.
	Algorithm string
	// Headers are additional protected header members, such as "kid" or
	// "typ". The "alg" and "crit" members may not be set here.
	Headers map[string]any
}

// VerifyOptions configures claim validation in [Verify]. Algorithm pins the
// expected "alg" value independently of the key; ExpectedIssuer and
// ExpectedAudience activate "iss" and "aud" checks. Time claims "exp",
// "nbf", and "iat" are validated whenever present in a JSON payload,
// regardless of the zero-value options.
type VerifyOptions struct {
	// Algorithm optionally pins the expected JWS "alg" value in addition to
	// the algorithm required by the key type.
	Algorithm string
	// ExpectedIssuer, when non-empty, requires the payload "iss" claim to
	// equal it exactly.
	ExpectedIssuer string
	// ExpectedAudience, when non-empty, requires the payload "aud" claim to
	// contain at least one of the values.
	ExpectedAudience []string
}

// ecdsaASN1 is the DER SEQUENCE of the signature integers used by
// [encoding/asn1] and the crypto/ecdsa wrapper.
type ecdsaASN1 struct {
	R, S *big.Int
}

// Sign implements [RFC 7515] §5.1 — it produces a JWS in compact
// serialization over payload using key. The protected header is built from
// opts; the signing input is BASE64URL(header) || '.' || BASE64URL(payload)
// and the signature is computed with the trust primitive matching the key.
// The algorithm must match the key type: an Ed25519 key signs EdDSA, a
// secp256k1 key signs ES256K, and so on. "alg":"none" and symmetric
// algorithms are refused.
func Sign(payload []byte, key crypto.PrivateKey, opts SignOptions) (string, error) {
	if opts.Algorithm == "" {
		return "", fmt.Errorf("jws sign: %w", ErrAlgRequired)
	}
	if opts.Algorithm == "none" {
		return "", fmt.Errorf("jws sign: %w", ErrAlgNone)
	}
	for name := range opts.Headers {
		if name == "alg" || name == "crit" {
			return "", fmt.Errorf("jws sign: header %q is controlled by the signer: %w", name, ErrInvalidMember)
		}
	}
	header := make(map[string]any, len(opts.Headers)+1)
	header["alg"] = opts.Algorithm
	for name, value := range opts.Headers {
		header[name] = value
	}
	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", fmt.Errorf("jws sign: marshal header: %w", err)
	}
	encHeader := base64.RawURLEncoding.EncodeToString(headerJSON)
	encPayload := base64.RawURLEncoding.EncodeToString(payload)
	signingInput := encHeader + "." + encPayload
	signature, err := signWithAlg(opts.Algorithm, key, signingInput)
	if err != nil {
		return "", fmt.Errorf("jws sign: %w", err)
	}
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(signature), nil
}

// signWithAlg dispatches to the trust primitive bound to key and checks that
// alg matches the key type.
func signWithAlg(alg string, key crypto.PrivateKey, signingInput string) ([]byte, error) {
	switch k := key.(type) {
	case *ed25519.PrivateKey:
		if alg != "EdDSA" {
			return nil, fmt.Errorf("%w: Ed25519 keys sign EdDSA, got %q", ErrAlgMismatch, alg)
		}
		return k.Sign([]byte(signingInput)), nil
	case *secp256k1.PrivateKey:
		if alg != "ES256K" {
			return nil, fmt.Errorf("%w: secp256k1 keys sign ES256K, got %q", ErrAlgMismatch, alg)
		}
		digest := hash.NewSHA256().Sum([]byte(signingInput))
		return k.Sign(digest[:])
	case *ecdsa.PrivateKey:
		size, curve, err := ecdsaParamsForAlg(alg)
		if err != nil {
			return nil, err
		}
		if k.Public().Curve() != curve {
			return nil, fmt.Errorf("%w: curve %v does not sign %q", ErrAlgMismatch, k.Public().Curve(), alg)
		}
		der, err := k.Sign([]byte(signingInput))
		if err != nil {
			return nil, err
		}
		return derToFixed(der, size)
	case *rsa.PSSPrivateKey:
		if want := "PS" + hashSuffix(k.Public().Hash()); alg != want {
			return nil, fmt.Errorf("%w: PSS key with %v signs %q, got %q", ErrAlgMismatch, k.Public().Hash(), want, alg)
		}
		return k.Sign([]byte(signingInput))
	case *rsa.PKCS1PrivateKey:
		if want := "RS" + hashSuffix(k.Public().Hash()); alg != want {
			return nil, fmt.Errorf("%w: PKCS1 key with %v signs %q, got %q", ErrAlgMismatch, k.Public().Hash(), want, alg)
		}
		return k.Sign([]byte(signingInput))
	default:
		return nil, fmt.Errorf("%w: key type %T", ErrUnsupportedAlg, key)
	}
}

// ecdsaParamsForAlg maps a JOSE ECDSA algorithm to the coordinate size and
// curve it requires.
func ecdsaParamsForAlg(alg string) (size int, curve elliptic.Curve, err error) {
	switch alg {
	case "ES256":
		return 32, elliptic.P256(), nil
	case "ES384":
		return 48, elliptic.P384(), nil
	default:
		return 0, nil, fmt.Errorf("%w: P-256/P-384 keys sign ES256/ES384, got %q", ErrAlgMismatch, alg)
	}
}

// derToFixed converts a DER-encoded ECDSA signature to the JOSE fixed-width
// R || S form required by [RFC 7518] §3.4.
func derToFixed(der []byte, size int) ([]byte, error) {
	var sig ecdsaASN1
	rest, err := asn1.Unmarshal(der, &sig)
	if err != nil || len(rest) != 0 {
		return nil, fmt.Errorf("decode ECDSA signature: %w", ErrInvalidSignature)
	}
	out := make([]byte, 2*size)
	sig.R.FillBytes(out[:size])
	sig.S.FillBytes(out[size:])
	return out, nil
}

// fixedToDer converts a JOSE fixed-width R || S signature to the DER form
// consumed by the crypto/ecdsa wrapper.
func fixedToDer(fixed []byte, size int) ([]byte, error) {
	if len(fixed) != 2*size {
		return nil, fmt.Errorf("ECDSA signature length: got %d bytes, want %d", len(fixed), 2*size)
	}
	return asn1.Marshal(ecdsaASN1{
		R: new(big.Int).SetBytes(fixed[:size]),
		S: new(big.Int).SetBytes(fixed[size:]),
	})
}

// parsedJWS is the decoded compact serialization.
type parsedJWS struct {
	header       map[string]any
	alg          string
	payload      []byte
	signature    []byte
	signingInput string
}

// parseCompact implements [RFC 7515] §5.2 steps 1-8 and §7.1 — it splits the
// compact serialization, requires canonical unpadded base64url segments
// that re-encode identically, and decodes the protected header with
// duplicate-member rejection. Tokens carrying "crit" or "alg":"none" are
// refused before any cryptographic work.
func parseCompact(token string) (*parsedJWS, error) {
	if strings.Count(token, ".") != 2 {
		return nil, fmt.Errorf("%w: got %d dots, want 2", ErrMalformedJWS, strings.Count(token, "."))
	}
	dot1 := strings.IndexByte(token, '.')
	dot2 := strings.LastIndexByte(token, '.')

	headerJSON, err := decodeSegment(token[:dot1])
	if err != nil {
		return nil, err
	}
	payload, err := decodeSegment(token[dot1+1 : dot2])
	if err != nil {
		return nil, err
	}
	signature, err := decodeSegment(token[dot2+1:])
	if err != nil {
		return nil, err
	}

	if err := checkDuplicateMembers(headerJSON); err != nil {
		return nil, err
	}
	var header map[string]any
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidMember, err)
	}
	if _, ok := header["crit"]; ok {
		return nil, fmt.Errorf("%w: no extensions are implemented", ErrCritUnsupported)
	}
	rawAlg, ok := header["alg"]
	if !ok {
		return nil, fmt.Errorf("%w: alg", ErrMissingMember)
	}
	alg, ok := rawAlg.(string)
	if !ok {
		return nil, fmt.Errorf("%w: alg is not a string", ErrInvalidMember)
	}
	if alg == "none" {
		return nil, ErrAlgNone
	}

	return &parsedJWS{
		header:       header,
		alg:          alg,
		payload:      payload,
		signature:    signature,
		signingInput: token[:dot2],
	}, nil
}

// decodeSegment decodes canonical unpadded base64url. A segment that is not
// exactly reproduced by re-encoding — padding, foreign alphabet characters,
// or non-canonical trailing bits — is rejected.
func decodeSegment(segment string) ([]byte, error) {
	decoded, err := base64.RawURLEncoding.DecodeString(segment)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidSegment, err)
	}
	if base64.RawURLEncoding.EncodeToString(decoded) != segment {
		return nil, fmt.Errorf("%w: non-canonical encoding", ErrInvalidSegment)
	}
	return decoded, nil
}

// keyAlg returns the JWS "alg" value required by the key type. An empty
// string means the key is not a supported trust key.
func keyAlg(key crypto.PublicKey) string {
	switch k := key.(type) {
	case *ed25519.PublicKey:
		return "EdDSA"
	case *secp256k1.PublicKey:
		return "ES256K"
	case *ecdsa.PublicKey:
		switch k.Curve() {
		case elliptic.P256():
			return "ES256"
		case elliptic.P384():
			return "ES384"
		}
	case *rsa.PSSPublicKey:
		return "PS" + hashSuffix(k.Hash())
	case *rsa.PKCS1PublicKey:
		return "RS" + hashSuffix(k.Hash())
	}
	return ""
}

// Verify implements [RFC 7515] §5.2 — it validates the compact serialization
// of token against key and returns the payload. The algorithm is pinned by
// the key type: the header "alg" may only match it, never select it, and an
// optional opts.Algorithm pins it a second time. Payload claims are
// validated when present: "exp", "nbf", and "iat" against the current time,
// and "iss"/"aud" when pinned in opts.
func Verify(token string, key crypto.PublicKey, opts VerifyOptions) ([]byte, error) {
	parsed, err := parseCompact(token)
	if err != nil {
		return nil, fmt.Errorf("jws verify: %w", err)
	}
	if key == nil {
		return nil, fmt.Errorf("jws verify: key is nil: %w", ErrUnsupportedAlg)
	}
	required := keyAlg(key)
	if required == "" {
		return nil, fmt.Errorf("jws verify: %w: key type %T", ErrUnsupportedAlg, key)
	}
	if parsed.alg != required {
		return nil, fmt.Errorf("jws verify: %w: token alg %q, key requires %q", ErrAlgMismatch, parsed.alg, required)
	}
	if opts.Algorithm != "" && parsed.alg != opts.Algorithm {
		return nil, fmt.Errorf("jws verify: %w: token alg %q, caller pinned %q", ErrAlgMismatch, parsed.alg, opts.Algorithm)
	}
	if !verifyWithKey(parsed, key) {
		return nil, ErrInvalidSignature
	}
	if err := checkClaims(parsed.payload, opts); err != nil {
		return nil, fmt.Errorf("jws verify: %w", err)
	}
	return parsed.payload, nil
}

// VerifyWithJWK implements [RFC 7515] §5.2 with a [RFC 7517] JWK — it loads
// the public key from jwk and delegates to [Verify].
func VerifyWithJWK(token string, jwk []byte, opts VerifyOptions) ([]byte, error) {
	key, err := PublicFromJWK(jwk)
	if err != nil {
		return nil, fmt.Errorf("jws verify with jwk: %w", err)
	}
	return Verify(token, key, opts)
}

// verifyWithKey dispatches signature verification to the trust primitive
// bound to key. JOSE ECDSA signatures are converted from fixed-width R || S
// to DER; ES256K hashes the signing input with SHA-256 first per
// [RFC 8812].
func verifyWithKey(parsed *parsedJWS, key crypto.PublicKey) bool {
	input := []byte(parsed.signingInput)
	switch k := key.(type) {
	case *ed25519.PublicKey:
		return k.Verify(parsed.signature, input)
	case *secp256k1.PublicKey:
		digest := hash.NewSHA256().Sum(input)
		return k.Verify(parsed.signature, digest[:])
	case *ecdsa.PublicKey:
		size := 32
		if k.Curve() == elliptic.P384() {
			size = 48
		}
		der, err := fixedToDer(parsed.signature, size)
		if err != nil {
			return false
		}
		return k.Verify(der, input)
	case *rsa.PSSPublicKey:
		return k.Verify(parsed.signature, input)
	case *rsa.PKCS1PublicKey:
		return k.Verify(parsed.signature, input)
	}
	return false
}

// checkClaims validates the payload claims per [RFC 7519] §4.1. Time claims
// are checked whenever present in a JSON payload; issuer and audience are
// checked when pinned in opts. A payload that is not a JSON object fails
// only when issuer or audience checks were requested.
func checkClaims(payload []byte, opts VerifyOptions) error {
	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		if opts.ExpectedIssuer != "" || len(opts.ExpectedAudience) > 0 {
			return fmt.Errorf("%w: payload is not a JSON object", ErrInvalidClaims)
		}
		return nil
	}
	if claims == nil {
		if opts.ExpectedIssuer != "" || len(opts.ExpectedAudience) > 0 {
			return fmt.Errorf("%w: payload is null", ErrInvalidClaims)
		}
		return nil
	}

	now := time.Now().Unix()
	for name, sentinel := range map[string]error{
		"exp": ErrExpired,
		"nbf": ErrNotYetValid,
		"iat": ErrNotYetValid,
	} {
		raw, ok := claims[name]
		if !ok {
			continue
		}
		when, ok := raw.(float64)
		if !ok {
			return fmt.Errorf("%w: %s is not a number", ErrInvalidClaims, name)
		}
		if name == "exp" {
			if now >= int64(when) {
				return fmt.Errorf("%w: exp %d vs now %d", sentinel, int64(when), now)
			}
		} else if now < int64(when) {
			return fmt.Errorf("%w: %s %d vs now %d", sentinel, name, int64(when), now)
		}
	}

	if opts.ExpectedIssuer != "" {
		iss, ok := claims["iss"].(string)
		if !ok || iss != opts.ExpectedIssuer {
			return fmt.Errorf("%w: got %v, want %q", ErrIssuerMismatch, claims["iss"], opts.ExpectedIssuer)
		}
	}
	if len(opts.ExpectedAudience) > 0 {
		if !audienceContains(claims["aud"], opts.ExpectedAudience) {
			return fmt.Errorf("%w: got %v, want one of %v", ErrAudienceMismatch, claims["aud"], opts.ExpectedAudience)
		}
	}
	return nil
}

// audienceContains reports whether the "aud" claim — a string or an array of
// strings — contains at least one expected audience per [RFC 7519] §4.1.3.
func audienceContains(raw any, expected []string) bool {
	var audiences []string
	switch aud := raw.(type) {
	case string:
		audiences = append(audiences, aud)
	case []any:
		for _, entry := range aud {
			s, ok := entry.(string)
			if !ok {
				return false
			}
			audiences = append(audiences, s)
		}
	default:
		return false
	}
	for _, want := range expected {
		for _, got := range audiences {
			if got == want {
				return true
			}
		}
	}
	return false
}
