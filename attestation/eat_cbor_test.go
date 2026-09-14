package attestation

import (
	"bytes"
	"encoding/json"
	"errors"
	"testing"

	"github.com/bperin/trust/authority"
	"github.com/bperin/trust/canonical"
	"github.com/bperin/trust/signature"
)

// TestEATCBOR_LabelMapping verifies the label↔field mapping: every
// attestation field lands under its documented label in the claim
// map, and the codec's private-use labels carry the expected value
// types.
func TestEATCBOR_LabelMapping(t *testing.T) {
	t.Parallel()

	att := testAttestation(t)
	claims, err := eatClaims(att)
	if err != nil {
		t.Fatalf("eatClaims: %v", err)
	}

	if got, ok := claims[ClaimIssuer].(string); !ok || got != att.Issuer {
		t.Errorf("iss: got %v, want %q", claims[ClaimIssuer], att.Issuer)
	}
	if got, ok := claims[labelAuthorityRef].(string); !ok || got != att.AuthorityRef {
		t.Errorf("authorityRef: got %v, want %q", claims[labelAuthorityRef], att.AuthorityRef)
	}
	if got, ok := claims[labelSigningKeyID].(string); !ok || got != att.SigningKeyID {
		t.Errorf("signingKeyID: got %v, want %q", claims[labelSigningKeyID], att.SigningKeyID)
	}
	if got, err := toInt64(claims[labelSigningKeyVersion]); err != nil || got != int64(att.SigningKeyVersion) {
		t.Errorf("signingKeyVersion: got (%v, %v), want %d", claims[labelSigningKeyVersion], err, att.SigningKeyVersion)
	}
	if got, err := toInt64(claims[labelAlgorithm]); err != nil {
		t.Errorf("algorithm: got %v (%v), want COSE label for %s", claims[labelAlgorithm], err, att.Algorithm.JOSE())
	} else if alg, ok := signature.AlgorithmForCOSE(got); !ok || alg != att.Algorithm {
		t.Errorf("algorithm: got COSE label %d, want %d (%s)", got, att.Algorithm.COSE(), att.Algorithm.JOSE())
	}
	if got, err := toInt64(claims[labelStatus]); err != nil || authority.Status(got) != att.Status {
		t.Errorf("status: got (%v, %v), want %d", claims[labelStatus], err, att.Status)
	}
	if got, ok := claims[labelClaim].([]byte); !ok || len(got) == 0 {
		t.Errorf("claim: got %T, want []byte", claims[labelClaim])
	}
	if got, ok := claims[labelEvidence].([][]byte); !ok || len(got) != len(att.Evidence) {
		t.Errorf("evidence: got %T with %v entries, want %d byte strings",
			claims[labelEvidence], len(att.Evidence), len(att.Evidence))
	}
	if got, err := toInt64(claims[ClaimIssuedAt]); err != nil || got != att.IssuedAt.Unix() {
		t.Errorf("iat: got %v, want %d", claims[ClaimIssuedAt], att.IssuedAt.Unix())
	}
	if got, err := toInt64(claims[ClaimNotBefore]); err != nil || got != att.Validity.NotBefore.Unix() {
		t.Errorf("nbf: got %v, want %d", claims[ClaimNotBefore], att.Validity.NotBefore.Unix())
	}
	if got, err := toInt64(claims[ClaimExpiry]); err != nil || got != att.Validity.NotAfter.Unix() {
		t.Errorf("exp: got %v, want %d", claims[ClaimExpiry], att.Validity.NotAfter.Unix())
	}
}

// TestEATCBOR_CapabilityRoundTrip proves the Capability struct
// survives the canonical-JSON byte-string encoding.
func TestEATCBOR_CapabilityRoundTrip(t *testing.T) {
	t.Parallel()

	att := testAttestation(t)
	claims, err := eatClaims(att)
	if err != nil {
		t.Fatalf("eatClaims: %v", err)
	}
	b, ok := claims[labelCapability].([]byte)
	if !ok {
		t.Fatalf("capability: got %T, want []byte", claims[labelCapability])
	}
	var got authority.Capability
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatalf("unmarshal capability: %v", err)
	}
	if got != att.Capability {
		t.Fatalf("capability: got %+v, want %+v", got, att.Capability)
	}
}

// TestEATCBOR_MalformedTokens proves malformed COSE_Sign1 inputs are
// rejected without panicking.
func TestEATCBOR_MalformedTokens(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		token []byte
	}{
		{"nil", nil},
		{"empty", []byte{}},
		{"text", []byte("hello")},
		{"truncated cbor", []byte{0x84, 0x01, 0x02}},
		{"random bytes", []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := UnmarshalEAT(tc.token)
			if !errors.Is(err, ErrMalformedEAT) {
				t.Fatalf("UnmarshalEAT: got %v, want ErrMalformedEAT", err)
			}
		})
	}
}

// TestEATCBOR_PayloadNotAMap proves a COSE_Sign1 whose payload is not
// a CBOR map errors with ErrInvalidClaims rather than panicking.
func TestEATCBOR_PayloadNotAMap(t *testing.T) {
	t.Parallel()

	payload, err := canonical.CBOREncode("just a string")
	if err != nil {
		t.Fatalf("CBOREncode: %v", err)
	}
	protected, err := canonical.CBOREncode(map[int64]any{1: int64(-8)})
	if err != nil {
		t.Fatalf("CBOREncode: %v", err)
	}
	token, err := canonical.CBOREncode([]any{protected, map[int64]any{}, payload, []byte{0x01}})
	if err != nil {
		t.Fatalf("CBOREncode: %v", err)
	}

	_, err = UnmarshalEAT(token)
	if !errors.Is(err, ErrInvalidClaims) {
		t.Fatalf("UnmarshalEAT: got %v, want ErrInvalidClaims", err)
	}
}

// TestEATCBOR_CanonicalEncoding_A08 pins the canonical CBOR encoding
// of a minimal claim map to known bytes, independent of MarshalEAT.
func TestEATCBOR_CanonicalEncoding_A08(t *testing.T) {
	t.Parallel()

	claims := map[int64]any{
		ClaimIssuer: "did:example:issuer",
		ClaimExpiry: int64(4102444800),
	}
	got, err := canonical.CBOREncode(claims)
	if err != nil {
		t.Fatalf("CBOREncode: %v", err)
	}

	// a2       — map of 2 entries
	// 01       — key 1 (iss)
	// 72       — tstr of length 18 ("did:example:issuer")
	// 04       — key 4 (exp)
	// 1a       — uint32 (4102444800 = 0xF4865700)
	want := hexDecode(t, "a201726469643a6578616d706c653a697373756572041af4865700")

	if !bytes.Equal(got, want) {
		t.Fatalf("claims CBOR: got %x, want %x", got, want)
	}
}
