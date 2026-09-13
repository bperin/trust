package jwkutil

import (
	"crypto"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"

	stdecdsa "crypto/ecdsa"
	stded25519 "crypto/ed25519"
	stdrsa "crypto/rsa"

	"github.com/bperin/trust/crypto/ecdsa"
	"github.com/bperin/trust/crypto/ed25519"
	"github.com/bperin/trust/crypto/rsa"
	"github.com/bperin/trust/signature"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jws"
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
//
// EdDSA, ES256, ES384, PS256/384/512, and RS256/384/512 delegate to
// [github.com/lestrrat-go/jwx/v3/jws]. secp256k1 (ES256K) is isolated
// behind the existing signature.Sign path because jwx registers
// secp256k1 only under the jwx_es256k build tag (see the package-level
// secp256k1 gap documentation in jwk.go).
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

	// secp256k1 (ES256K): route to the existing hand-rolled path. jwx
	// registers secp256k1 only under the jwx_es256k build tag; relying
	// on a build tag is fragile. The existing signature.Sign path uses
	// the same decred/dcrd library jwx would use behind the tag.
	if opts.Algorithm == "ES256K" {
		return signSecp256k1(payload, key, opts)
	}

	// Validate that the algorithm is one of the asymmetric algorithms
	// this package supports. Symmetric algorithms (HS256, etc.) and
	// unknown strings are rejected before any key work.
	if _, ok := signature.AlgorithmForJOSE(opts.Algorithm); !ok {
		return "", fmt.Errorf("jws sign: %w: %q", ErrUnsupportedAlg, opts.Algorithm)
	}

	// Validate the algorithm against the key type before delegating to
	// jwx. jwx does not enforce the curve-alg binding (P-384 with ES256
	// succeeds in jwx) or the PSS/PKCS1 binding, and its error messages
	// do not wrap signature.ErrAlgMismatch. The trust security rule is
	// stricter: the algorithm must match the key type exactly.
	keyAlg, err := signature.AlgorithmForPrivateKey(key)
	if err != nil {
		// If the key is actually a public key (e.g. the caller passed
		// a public key to Sign), produce ErrAlgMismatch rather than
		// the generic ErrUnsupportedAlgorithm.
		if pubAlg, pubErr := signature.AlgorithmForPublicKey(key); pubErr == nil {
			return "", fmt.Errorf("jws sign: %w", &signature.ErrAlgMismatch{
				Got:      pubAlg,
				Expected: keyAlg,
			})
		}
		return "", fmt.Errorf("jws sign: %w", err)
	}
	if keyAlg.JOSE() != opts.Algorithm {
		// The caller's algorithm does not match the key type. Resolve
		// the caller's alg to an Algorithm for the error; if it is not
		// a known JOSE algorithm, use 0 (unregistered).
		gotAlg, _ := signature.AlgorithmForJOSE(opts.Algorithm)
		return "", fmt.Errorf("jws sign: %w", &signature.ErrAlgMismatch{
			Got:      gotAlg,
			Expected: keyAlg,
		})
	}

	// All other algorithms: delegate to jwx/v3/jws.
	alg, err := jwa.KeyAlgorithmFrom(opts.Algorithm)
	if err != nil {
		return "", fmt.Errorf("jws sign: %w: %q", ErrUnsupportedAlg, opts.Algorithm)
	}

	// jwx expects stdlib key types, not trust's concrete wrappers.
	// Convert the trust private key to the stdlib raw key that jwx's
	// keyconv can consume.
	rawKey, err := toStdlibPrivateKey(key, opts.Algorithm)
	if err != nil {
		return "", fmt.Errorf("jws sign: %w", err)
	}

	// Build protected headers for jwx if the caller supplied extras.
	var signOpts []jws.SignOption
	if len(opts.Headers) > 0 {
		hdrs := jws.NewHeaders()
		for name, value := range opts.Headers {
			if err := hdrs.Set(name, value); err != nil {
				return "", fmt.Errorf("jws sign: set header %q: %w", name, err)
			}
		}
		signOpts = append(signOpts, jws.WithKey(alg, rawKey, jws.WithProtectedHeaders(hdrs)))
	} else {
		signOpts = append(signOpts, jws.WithKey(alg, rawKey))
	}

	token, err := jws.Sign(payload, signOpts...)
	if err != nil {
		return "", fmt.Errorf("jws sign: %w", err)
	}
	return string(token), nil
}

// signSecp256k1 signs a JWS using the existing trust signature.Sign path
// for secp256k1 (ES256K). This is the ISOLATE path — jwx does not
// register secp256k1 without the jwx_es256k build tag.
func signSecp256k1(payload []byte, key crypto.PrivateKey, opts SignOptions) (string, error) {
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

	alg, ok := signature.AlgorithmForJOSE(opts.Algorithm)
	if !ok {
		return "", fmt.Errorf("jws sign: %w: %q", ErrUnsupportedAlg, opts.Algorithm)
	}
	sig, err := signature.Sign(alg, key, []byte(signingInput))
	if err != nil {
		return "", fmt.Errorf("jws sign: %w", err)
	}
	// The trust secp256k1 signer returns fixed-width R || S (64 bytes)
	// directly, so no DER-to-fixed-width conversion is needed. This
	// differs from the stdlib ECDSA signers (P-256/P-384) which return
	// DER-encoded signatures.
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

// toStdlibPrivateKey converts a trust concrete private key to the stdlib
// raw key type that jwx's keyconv functions can consume. This mirrors the
// conversion in jwk.go's marshalViaJWX path.
func toStdlibPrivateKey(key crypto.PrivateKey, alg string) (any, error) {
	switch k := key.(type) {
	case *ed25519.PrivateKey:
		return stded25519.NewKeyFromSeed(k.Seed()), nil
	case *ecdsa.PrivateKey:
		pub := k.Public()
		return &stdecdsa.PrivateKey{
			PublicKey: stdecdsa.PublicKey{
				Curve: pub.Curve(),
				X:     pub.X(),
				Y:     pub.Y(),
			},
			D: k.D(),
		}, nil
	case *rsa.PSSPrivateKey:
		pub := k.Public()
		return &stdrsa.PrivateKey{
			PublicKey: stdrsa.PublicKey{N: pub.N(), E: pub.E()},
			D:         k.D(),
		}, nil
	case *rsa.PKCS1PrivateKey:
		pub := k.Public()
		return &stdrsa.PrivateKey{
			PublicKey: stdrsa.PublicKey{N: pub.N(), E: pub.E()},
			D:         k.D(),
		}, nil
	default:
		return nil, fmt.Errorf("%w: key type %T", ErrUnsupportedAlg, key)
	}
}

// toStdlibPublicKey converts a trust concrete public key to the stdlib
// raw key type that jwx's keyconv functions can consume.
func toStdlibPublicKey(key crypto.PublicKey) (any, error) {
	switch k := key.(type) {
	case *ed25519.PublicKey:
		b := k.Bytes()
		return stded25519.PublicKey(append([]byte(nil), b[:]...)), nil
	case *ecdsa.PublicKey:
		return &stdecdsa.PublicKey{
			Curve: k.Curve(),
			X:     k.X(),
			Y:     k.Y(),
		}, nil
	case *rsa.PSSPublicKey:
		return &stdrsa.PublicKey{N: k.N(), E: k.E()}, nil
	case *rsa.PKCS1PublicKey:
		return &stdrsa.PublicKey{N: k.N(), E: k.E()}, nil
	default:
		return nil, fmt.Errorf("%w: key type %T", ErrUnsupportedAlg, key)
	}
}

// ecdsaSize returns the coordinate size in bytes for an ECDSA
// algorithm, or 0 if the algorithm is not ECDSA. secp256k1 is excluded
// because the trust secp256k1 signer already returns fixed-width R||S,
// not DER — no conversion is needed.
func ecdsaSize(alg signature.Algorithm) int {
	switch alg {
	case signature.AlgorithmES256:
		return 32
	case signature.AlgorithmES384:
		return 48
	default:
		return 0
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

// Verify implements [RFC 7515] §5.2 — it validates the compact serialization
// of token against key and returns the payload. The algorithm is pinned by
// the key type: the header "alg" may only match it, never select it, and an
// optional opts.Algorithm pins it a second time. Payload claims are
// validated when present: "exp", "nbf", and "iat" against the current time,
// and "iss"/"aud" when pinned in opts.
//
// EdDSA, ES256, ES384, PS256/384/512, and RS256/384/512 delegate signature
// verification to [github.com/lestrrat-go/jwx/v3/jws]. secp256k1 (ES256K)
// is verified through the existing signature.Verify path. Claims
// validation (exp, nbf, iat, iss, aud) is performed by checkClaims after
// the signature verifies — jws.Verify does not validate JWT claims.
func Verify(token string, key crypto.PublicKey, opts VerifyOptions) ([]byte, error) {
	parsed, err := parseCompact(token)
	if err != nil {
		return nil, fmt.Errorf("jws verify: %w", err)
	}
	if key == nil {
		return nil, fmt.Errorf("jws verify: key is nil: %w", ErrUnsupportedAlg)
	}
	requiredAlg, err := signature.AlgorithmForPublicKey(key)
	if err != nil {
		return nil, fmt.Errorf("jws verify: %w: key type %T", ErrUnsupportedAlg, key)
	}
	required := requiredAlg.JOSE()
	if parsed.alg != required {
		return nil, fmt.Errorf("jws verify: %w: token alg %q, key requires %q", ErrAlgMismatch, parsed.alg, required)
	}
	if opts.Algorithm != "" && parsed.alg != opts.Algorithm {
		return nil, fmt.Errorf("jws verify: %w: token alg %q, caller pinned %q", ErrAlgMismatch, parsed.alg, opts.Algorithm)
	}

	// secp256k1 (ES256K): route to the existing hand-rolled verify path.
	if requiredAlg == signature.AlgorithmES256K {
		return verifySecp256k1(parsed, key, opts)
	}

	// All other algorithms: delegate signature verification to jwx/v3/jws.
	// jwx expects stdlib key types.
	rawKey, err := toStdlibPublicKey(key)
	if err != nil {
		return nil, fmt.Errorf("jws verify: %w", err)
	}
	alg, err := jwa.KeyAlgorithmFrom(parsed.alg)
	if err != nil {
		return nil, fmt.Errorf("jws verify: %w: %q", ErrUnsupportedAlg, parsed.alg)
	}

	payload, err := jws.Verify([]byte(token), jws.WithKey(alg, rawKey))
	if err != nil {
		return nil, fmt.Errorf("jws verify: %w", ErrInvalidSignature)
	}

	if err := checkClaims(payload, opts); err != nil {
		return nil, fmt.Errorf("jws verify: %w", err)
	}
	return payload, nil
}

// verifySecp256k1 verifies a JWS signed with ES256K through the existing
// trust signature.Verify path. This is the ISOLATE path — jwx does not
// register secp256k1 without the jwx_es256k build tag.
func verifySecp256k1(parsed *parsedJWS, key crypto.PublicKey, opts VerifyOptions) ([]byte, error) {
	// The trust secp256k1 verifier consumes fixed-width R || S directly,
	// which is the JWS compact serialization signature format. No
	// DER conversion is needed (unlike P-256/P-384 where the stdlib
	// verifier expects DER).
	valid, err := signature.Verify(signature.AlgorithmES256K, key, parsed.signature, []byte(parsed.signingInput))
	if err != nil {
		return nil, fmt.Errorf("jws verify: %w", err)
	}
	if !valid {
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
