package attestation

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/bperin/trust/authority"
	"github.com/bperin/trust/evidence"
	"github.com/bperin/trust/signature"
)

// CWT claim labels from [RFC 8392] §3.1.1.
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

// Private-use labels per [RFC 8392]; the -70001..-70008 range is
// reserved for this codec and pinned by an exact-value test. Complex
// structs are carried as canonical JSON byte strings.
const (
	labelAuthorityRef      = int64(-70001)
	labelCapability        = int64(-70002)
	labelClaim             = int64(-70003)
	labelEvidence          = int64(-70004)
	labelSigningKeyID      = int64(-70005)
	labelSigningKeyVersion = int64(-70006)
	labelAlgorithm         = int64(-70007)
	labelStatus            = int64(-70008)
)

// Sentinel errors returned by MarshalEAT and UnmarshalEAT. Check them
// with errors.Is.
var (
	ErrInvalidClaims   = errors.New("attestation: invalid claims")
	ErrMalformedEAT    = errors.New("attestation: malformed EAT token")
	ErrEATHashMismatch = errors.New("attestation: cti does not match canonical hash")
)

// MarshalEAT encodes att as an untagged [RFC 9052] COSE_Sign1 whose
// payload is a canonical CBOR claim map per [RFC 8392], with cti
// carrying the hex canonical hash. The COSE signature slot carries
// att.Signature verbatim; authenticity is established by
// VerifyAttestation, never by the COSE signature.
func MarshalEAT(att *Attestation) ([]byte, error) {
	if att == nil {
		return nil, ErrNilAttestation
	}
	claims, err := eatClaims(att)
	if err != nil {
		return nil, fmt.Errorf("attestation marshal: %w", err)
	}
	return marshalCOSESign1(att.Algorithm, att.SigningKeyID, claims, att.Signature)
}

// UnmarshalEAT parses an EAT token back into an Attestation, rejecting
// a cti mismatch with ErrEATHashMismatch. It does not verify the COSE
// signature; the slot is carried into Attestation.Signature for
// VerifySignature to judge.
func UnmarshalEAT(token []byte) (*Attestation, error) {
	claims, sig, err := parseCOSESign1(token)
	if err != nil {
		return nil, err
	}
	att, err := attFromClaims(claims)
	if err != nil {
		return nil, err
	}
	att.Signature = sig
	h, err := CanonicalHash(att)
	if err != nil {
		return nil, fmt.Errorf("attestation unmarshal: %w", err)
	}
	cti, _ := claims[ClaimCWTID].(string)
	if cti != hex.EncodeToString(h[:]) {
		return nil, ErrEATHashMismatch
	}
	return att, nil
}

func eatClaims(att *Attestation) (map[int64]any, error) {
	h, err := CanonicalHash(att)
	if err != nil {
		return nil, err
	}
	cti := hex.EncodeToString(h[:])

	capability, err := canonicalJSON(att.Capability)
	if err != nil {
		return nil, fmt.Errorf("capability: %w", err)
	}
	claimBytes, err := canonicalJSON(att.Claim)
	if err != nil {
		return nil, fmt.Errorf("claim: %w", err)
	}
	evidenceBytes := make([][]byte, len(att.Evidence))
	for i := range att.Evidence {
		b, err := canonicalJSON(att.Evidence[i])
		if err != nil {
			return nil, fmt.Errorf("evidence[%d]: %w", i, err)
		}
		evidenceBytes[i] = b
	}

	return map[int64]any{
		ClaimIssuer:            att.Issuer,
		ClaimExpiry:            att.Validity.NotAfter.Unix(),
		ClaimNotBefore:         att.Validity.NotBefore.Unix(),
		ClaimIssuedAt:          att.IssuedAt.Unix(),
		ClaimCWTID:             cti,
		labelAuthorityRef:      att.AuthorityRef,
		labelCapability:        capability,
		labelClaim:             claimBytes,
		labelEvidence:          evidenceBytes,
		labelSigningKeyID:      att.SigningKeyID,
		labelSigningKeyVersion: int64(att.SigningKeyVersion),
		labelAlgorithm:         att.Algorithm.COSE(),
		labelStatus:            int64(att.Status),
	}, nil
}

// attFromClaims decodes a claim map into an Attestation; requires iss
// and cti, ignores unknown labels, reconstructs times in UTC.
func attFromClaims(claims map[int64]any) (*Attestation, error) {
	issuer, _ := claims[ClaimIssuer].(string)
	if issuer == "" {
		return nil, fmt.Errorf("%w: iss claim is required", ErrInvalidClaims)
	}
	if _, ok := claims[ClaimCWTID]; !ok {
		return nil, fmt.Errorf("%w: cti claim is required", ErrInvalidClaims)
	}

	att := &Attestation{Issuer: issuer}
	var err error
	if att.Validity.NotAfter, err = unixClaim(claims, ClaimExpiry); err != nil {
		return nil, err
	}
	if att.Validity.NotBefore, err = unixClaim(claims, ClaimNotBefore); err != nil {
		return nil, err
	}
	if att.IssuedAt, err = unixClaim(claims, ClaimIssuedAt); err != nil {
		return nil, err
	}

	att.AuthorityRef, _ = claims[labelAuthorityRef].(string)
	att.SigningKeyID, _ = claims[labelSigningKeyID].(string)
	if v, ok := claims[labelSigningKeyVersion]; ok {
		n, err := toInt64(v)
		if err != nil {
			return nil, fmt.Errorf("%w: signingKeyVersion: %v", ErrInvalidClaims, err)
		}
		att.SigningKeyVersion = uint64(n)
	}
	if v, ok := claims[labelAlgorithm]; ok {
		n, err := toInt64(v)
		if err != nil {
			return nil, fmt.Errorf("%w: algorithm: %v", ErrInvalidClaims, err)
		}
		alg, ok := signature.AlgorithmForCOSE(n)
		if !ok {
			return nil, fmt.Errorf("%w: unknown algorithm label %d", ErrInvalidClaims, n)
		}
		att.Algorithm = alg
	}
	if v, ok := claims[labelStatus]; ok {
		n, err := toInt64(v)
		if err != nil {
			return nil, fmt.Errorf("%w: status: %v", ErrInvalidClaims, err)
		}
		att.Status = statusFromInt64(n)
	}
	if err := jsonClaim(claims, labelCapability, &att.Capability); err != nil {
		return nil, err
	}
	if err := jsonClaim(claims, labelClaim, &att.Claim); err != nil {
		return nil, err
	}
	if ev, ok := claims[labelEvidence]; ok {
		items, ok := ev.([]any)
		if !ok {
			return nil, fmt.Errorf("%w: evidence is not an array", ErrInvalidClaims)
		}
		if len(items) == 0 {
			att.Evidence = nil
		} else {
			att.Evidence = make([]evidence.Evidence, 0, len(items))
			for i, item := range items {
				b, ok := item.([]byte)
				if !ok {
					return nil, fmt.Errorf("%w: evidence[%d] is not a byte string", ErrInvalidClaims, i)
				}
				var e evidence.Evidence
				if err := json.Unmarshal(b, &e); err != nil {
					return nil, fmt.Errorf("%w: evidence[%d]: %v", ErrInvalidClaims, i, err)
				}
				att.Evidence = append(att.Evidence, e)
			}
		}
	}
	return att, nil
}

func statusFromInt64(n int64) authority.Status {
	switch authority.Status(n) {
	case authority.StatusActive, authority.StatusRevoked,
		authority.StatusSuperseded, authority.StatusExpired:
		return authority.Status(n)
	default:
		return 0
	}
}

func unixClaim(claims map[int64]any, label int64) (time.Time, error) {
	v, ok := claims[label]
	if !ok {
		return time.Time{}, nil
	}
	n, err := toInt64(v)
	if err != nil {
		return time.Time{}, fmt.Errorf("%w: label %d: %v", ErrInvalidClaims, label, err)
	}
	return time.Unix(n, 0).UTC(), nil
}

func jsonClaim(claims map[int64]any, label int64, out any) error {
	v, ok := claims[label]
	if !ok {
		return nil
	}
	b, ok := v.([]byte)
	if !ok {
		return fmt.Errorf("%w: label %d is not a byte string", ErrInvalidClaims, label)
	}
	if err := json.Unmarshal(b, out); err != nil {
		return fmt.Errorf("%w: label %d: %v", ErrInvalidClaims, label, err)
	}
	return nil
}
