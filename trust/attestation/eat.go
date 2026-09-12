package attestation

import (
	"crypto"
	"errors"
	"fmt"
	"time"

	jwkutil "github.com/bperin/trust/identity/jwk"
	"github.com/bperin/trust/signature"
	"github.com/fxamacker/cbor/v2"
)

// CWT claim labels from [RFC 8392] §3.1.1 and EAT nonce.
const (
	ClaimIssuer    = int64(1)
	ClaimSubject   = int64(2)
	ClaimAudience  = int64(3)
	ClaimExpiry    = int64(4)
	ClaimNotBefore = int64(5)
	ClaimIssuedAt  = int64(6)
	ClaimCWTID     = int64(7)
	ClaimNonce     = int64(10)
)

// Sentinel errors returned by Issue and Verify. Check them with errors.Is.
var (
	// ErrInvalidClaims is returned when the EAT claim set is missing
	// required values or is otherwise malformed.
	ErrInvalidClaims = errors.New("attestation: invalid claims")
	// ErrExpired is returned when the token "exp" claim is in the past.
	ErrExpired = errors.New("attestation: token expired")
	// ErrNotYetValid is returned when the token "nbf" or "iat" claim is
	// in the future.
	ErrNotYetValid = errors.New("attestation: token not yet valid")
	// ErrIssuerMismatch is returned when the token "iss" claim does not
	// match the expected issuer.
	ErrIssuerMismatch = errors.New("attestation: issuer mismatch")
	// ErrAudienceMismatch is returned when the token "aud" claim does not
	// match the expected audience.
	ErrAudienceMismatch = errors.New("attestation: audience mismatch")
)

// IssueOptions configures EAT Issue.
type IssueOptions struct {
	// VerificationMethod is the key identifier placed in the COSE
	// protected header as "kid" (label 4).
	VerificationMethod string
	// Algorithm, when non-zero, pins the COSE "alg" value. If zero, the
	// algorithm is derived from the key type.
	Algorithm int64
	// Protected holds additional protected header entries. The "alg"
	// label (1) may not be set here.
	Protected map[int64]any
}

// VerifyOptions configures EAT Verify.
type VerifyOptions struct {
	// Algorithm, when non-zero, pins the expected COSE "alg" value.
	Algorithm int64
	// ExpectedIssuer, when non-empty, requires the "iss" claim to match.
	ExpectedIssuer string
	// ExpectedAudience, when non-empty, requires the "aud" claim to match.
	ExpectedAudience string
}

// Issue implements EAT token issuance as a [RFC 9052] COSE_Sign1 token over
// a canonical CBOR CWT claim set per [RFC 8392].
func Issue(claims map[int64]any, key crypto.PrivateKey, opts IssueOptions) ([]byte, error) {
	if claims == nil {
		return nil, fmt.Errorf("%w: claims are nil", ErrInvalidClaims)
	}
	if _, ok := claims[ClaimIssuer]; !ok {
		return nil, fmt.Errorf("%w: iss claim is required", ErrInvalidClaims)
	}

	alg := opts.Algorithm
	if alg == 0 {
		derived, err := signature.AlgorithmForPrivateKey(key)
		if err != nil {
			return nil, err
		}
		alg = derived.COSE()
	}

	now := time.Now().UTC().Unix()
	if _, ok := claims[ClaimIssuedAt]; !ok {
		claims = copyClaims(claims)
		claims[ClaimIssuedAt] = now
	}

	payload, err := cborCanonical(claims)
	if err != nil {
		return nil, fmt.Errorf("attestation issue: canonical claims: %w", err)
	}

	protected := make(map[int64]any, len(opts.Protected)+1)
	for k, v := range opts.Protected {
		if k == 1 {
			return nil, fmt.Errorf("%w: alg is controlled by the issuer", jwkutil.ErrInvalidMember)
		}
		protected[k] = v
	}
	if opts.VerificationMethod != "" {
		protected[4] = opts.VerificationMethod
	}

	return jwkutil.CoseSign(payload, key, jwkutil.CoseSignOptions{
		Algorithm: alg,
		Protected: protected,
	})
}

// Verify implements EAT token verification as a [RFC 9052] COSE_Sign1 token.
// It returns the CWT claim set after signature, algorithm, and time/claim
// validation.
func Verify(token []byte, key crypto.PublicKey, opts VerifyOptions) (map[int64]any, error) {
	payload, err := jwkutil.CoseVerify(token, key, jwkutil.CoseVerifyOptions{Algorithm: opts.Algorithm})
	if err != nil {
		return nil, fmt.Errorf("attestation verify: %w", err)
	}

	var claims map[int64]any
	if err := cbor.Unmarshal(payload, &claims); err != nil {
		return nil, fmt.Errorf("%w: unmarshal claims: %v", ErrInvalidClaims, err)
	}

	if err := validateClaims(claims, opts); err != nil {
		return nil, err
	}

	return claims, nil
}

func validateClaims(claims map[int64]any, opts VerifyOptions) error {
	now := time.Now().UTC().Unix()

	if v, ok := claims[ClaimExpiry]; ok {
		exp, err := toInt64(v)
		if err != nil {
			return fmt.Errorf("%w: exp is not numeric", ErrInvalidClaims)
		}
		if now > exp {
			return ErrExpired
		}
	}
	if v, ok := claims[ClaimNotBefore]; ok {
		nbf, err := toInt64(v)
		if err != nil {
			return fmt.Errorf("%w: nbf is not numeric", ErrInvalidClaims)
		}
		if now < nbf {
			return ErrNotYetValid
		}
	}
	if v, ok := claims[ClaimIssuedAt]; ok {
		iat, err := toInt64(v)
		if err != nil {
			return fmt.Errorf("%w: iat is not numeric", ErrInvalidClaims)
		}
		if now < iat {
			return ErrNotYetValid
		}
	}

	if opts.ExpectedIssuer != "" {
		iss, ok := claims[ClaimIssuer].(string)
		if !ok || iss != opts.ExpectedIssuer {
			return ErrIssuerMismatch
		}
	}
	if opts.ExpectedAudience != "" {
		aud, ok := claims[ClaimAudience].(string)
		if !ok || aud != opts.ExpectedAudience {
			return ErrAudienceMismatch
		}
	}

	return nil
}

func cborCanonical(v any) ([]byte, error) {
	em, err := cbor.CanonicalEncOptions().EncMode()
	if err != nil {
		return nil, err
	}
	return em.Marshal(v)
}

func copyClaims(in map[int64]any) map[int64]any {
	out := make(map[int64]any, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func toInt64(v any) (int64, error) {
	switch n := v.(type) {
	case int:
		return int64(n), nil
	case int8:
		return int64(n), nil
	case int16:
		return int64(n), nil
	case int32:
		return int64(n), nil
	case int64:
		return n, nil
	case uint:
		return int64(n), nil
	case uint8:
		return int64(n), nil
	case uint16:
		return int64(n), nil
	case uint32:
		return int64(n), nil
	case uint64:
		return int64(n), nil
	case float64:
		return int64(n), nil
	default:
		return 0, fmt.Errorf("not an integer: %T", v)
	}
}
