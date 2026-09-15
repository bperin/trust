package attestation

import (
	"fmt"

	"github.com/bperin/trust/canonical"
	"github.com/bperin/trust/signature"
	"github.com/fxamacker/cbor/v2"
)

// marshalCOSESign1 emits an untagged [RFC 9052] COSE_Sign1 array; the
// signature slot carries sig verbatim (no genuine Sig_structure here).
func marshalCOSESign1(alg signature.Algorithm, keyID string, claims map[int64]any, sig []byte) ([]byte, error) {
	protected := map[int64]any{1: alg.COSE()}
	if keyID != "" {
		protected[4] = []byte(keyID)
	}
	protectedBytes, err := canonicalCBOR(protected)
	if err != nil {
		return nil, fmt.Errorf("protected header: %w", err)
	}
	payload, err := canonicalCBOR(claims)
	if err != nil {
		return nil, fmt.Errorf("payload: %w", err)
	}
	if sig == nil {
		sig = []byte{}
	}
	return canonicalCBOR([]any{protectedBytes, map[int64]any{}, payload, sig})
}

// parseCOSESign1 parses an untagged [RFC 9052] COSE_Sign1 array into
// its claim map and signature slot, without verifying the signature.
func parseCOSESign1(token []byte) (map[int64]any, []byte, error) {
	var parts []cbor.RawMessage
	if err := cbor.Unmarshal(token, &parts); err != nil {
		return nil, nil, fmt.Errorf("%w: not a COSE_Sign1 array: %v", ErrMalformedEAT, err)
	}
	if len(parts) != 4 {
		return nil, nil, fmt.Errorf("%w: COSE_Sign1 has %d elements, want 4", ErrMalformedEAT, len(parts))
	}
	var payload, sig []byte
	if err := cbor.Unmarshal(parts[2], &payload); err != nil {
		return nil, nil, fmt.Errorf("%w: payload: %v", ErrMalformedEAT, err)
	}
	if err := cbor.Unmarshal(parts[3], &sig); err != nil {
		return nil, nil, fmt.Errorf("%w: signature slot: %v", ErrMalformedEAT, err)
	}
	if len(payload) == 0 {
		return nil, nil, fmt.Errorf("%w: empty payload", ErrInvalidClaims)
	}
	var claims map[int64]any
	if err := cbor.Unmarshal(payload, &claims); err != nil {
		return nil, nil, fmt.Errorf("%w: payload claims: %v", ErrInvalidClaims, err)
	}
	if claims == nil {
		return nil, nil, fmt.Errorf("%w: empty payload", ErrInvalidClaims)
	}
	return claims, sig, nil
}

func canonicalCBOR(v any) ([]byte, error) {
	return canonical.CBOREncode(v)
}

func canonicalJSON(v any) ([]byte, error) {
	return canonical.JSONCanonicalize(v)
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
