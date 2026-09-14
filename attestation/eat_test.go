package attestation

import (
	"bytes"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/bperin/trust/canonical"
	"github.com/bperin/trust/signature"
	"github.com/fxamacker/cbor/v2"
)

// TestMarshalUnmarshalEAT_RoundTrip asserts MarshalEAT →
// UnmarshalEAT preserves every field of a fully populated
// attestation, with field-level equality assertions.
func TestMarshalUnmarshalEAT_RoundTrip(t *testing.T) {
	t.Parallel()

	att := testAttestation(t)
	att.Signature = []byte{0xde, 0xad, 0xbe, 0xef}

	token, err := MarshalEAT(att)
	if err != nil {
		t.Fatalf("MarshalEAT: %v", err)
	}
	got, err := UnmarshalEAT(token)
	if err != nil {
		t.Fatalf("UnmarshalEAT: %v", err)
	}

	if got.Issuer != att.Issuer {
		t.Errorf("Issuer: got %q, want %q", got.Issuer, att.Issuer)
	}
	if got.SigningKeyID != att.SigningKeyID {
		t.Errorf("SigningKeyID: got %q, want %q", got.SigningKeyID, att.SigningKeyID)
	}
	if got.SigningKeyVersion != att.SigningKeyVersion {
		t.Errorf("SigningKeyVersion: got %d, want %d", got.SigningKeyVersion, att.SigningKeyVersion)
	}
	if got.AuthorityRef != att.AuthorityRef {
		t.Errorf("AuthorityRef: got %q, want %q", got.AuthorityRef, att.AuthorityRef)
	}
	if got.Capability != att.Capability {
		t.Errorf("Capability: got %+v, want %+v", got.Capability, att.Capability)
	}
	if got.Claim.Issuer != att.Claim.Issuer {
		t.Errorf("Claim.Issuer: got %q, want %q", got.Claim.Issuer, att.Claim.Issuer)
	}
	if got.Claim.Subject != att.Claim.Subject {
		t.Errorf("Claim.Subject: got %q, want %q", got.Claim.Subject, att.Claim.Subject)
	}
	if got.Claim.Type != att.Claim.Type {
		t.Errorf("Claim.Type: got %+v, want %+v", got.Claim.Type, att.Claim.Type)
	}
	if got.Claim.Value != att.Claim.Value {
		t.Errorf("Claim.Value: got %v, want %v", got.Claim.Value, att.Claim.Value)
	}
	if !got.Claim.Validity.NotBefore.Equal(att.Claim.Validity.NotBefore) {
		t.Errorf("Claim.Validity.NotBefore: got %v, want %v", got.Claim.Validity.NotBefore, att.Claim.Validity.NotBefore)
	}
	if len(got.Evidence) != len(att.Evidence) {
		t.Fatalf("Evidence length: got %d, want %d", len(got.Evidence), len(att.Evidence))
	}
	for i := range att.Evidence {
		if got.Evidence[i].Identifier != att.Evidence[i].Identifier {
			t.Errorf("Evidence[%d].Identifier: got %q, want %q", i, got.Evidence[i].Identifier, att.Evidence[i].Identifier)
		}
		if !bytes.Equal(got.Evidence[i].ContentHash, att.Evidence[i].ContentHash) {
			t.Errorf("Evidence[%d].ContentHash: got %x, want %x", i, got.Evidence[i].ContentHash, att.Evidence[i].ContentHash)
		}
		if got.Evidence[i].MediaType != att.Evidence[i].MediaType {
			t.Errorf("Evidence[%d].MediaType: got %q, want %q", i, got.Evidence[i].MediaType, att.Evidence[i].MediaType)
		}
		if got.Evidence[i].Locator != att.Evidence[i].Locator {
			t.Errorf("Evidence[%d].Locator: got %q, want %q", i, got.Evidence[i].Locator, att.Evidence[i].Locator)
		}
		if got.Evidence[i].Provenance.Source != att.Evidence[i].Provenance.Source {
			t.Errorf("Evidence[%d].Provenance.Source: got %q, want %q", i, got.Evidence[i].Provenance.Source, att.Evidence[i].Provenance.Source)
		}
	}
	if !got.IssuedAt.Equal(att.IssuedAt) {
		t.Errorf("IssuedAt: got %v, want %v", got.IssuedAt, att.IssuedAt)
	}
	if !got.Validity.NotBefore.Equal(att.Validity.NotBefore) {
		t.Errorf("Validity.NotBefore: got %v, want %v", got.Validity.NotBefore, att.Validity.NotBefore)
	}
	if !got.Validity.NotAfter.Equal(att.Validity.NotAfter) {
		t.Errorf("Validity.NotAfter: got %v, want %v", got.Validity.NotAfter, att.Validity.NotAfter)
	}
	if got.Status != att.Status {
		t.Errorf("Status: got %d, want %d", got.Status, att.Status)
	}
	if got.Algorithm != att.Algorithm {
		t.Errorf("Algorithm: got %s, want %s", got.Algorithm.JOSE(), att.Algorithm.JOSE())
	}
	if !bytes.Equal(got.Signature, att.Signature) {
		t.Errorf("Signature: got %x, want %x", got.Signature, att.Signature)
	}
}

// TestEATLabels_Pinned pins the CWT and private-use label constants
// to their exact values — a silent renumbering breaks the wire
// format.
func TestEATLabels_Pinned(t *testing.T) {
	t.Parallel()

	cwtLabels := []struct {
		name  string
		label int64
		want  int64
	}{
		{"ClaimIssuer", ClaimIssuer, 1},
		{"ClaimSubject", ClaimSubject, 2},
		{"ClaimAudience", ClaimAudience, 3},
		{"ClaimExpiry", ClaimExpiry, 4},
		{"ClaimNotBefore", ClaimNotBefore, 5},
		{"ClaimIssuedAt", ClaimIssuedAt, 6},
		{"ClaimCWTID", ClaimCWTID, 7},
		{"ClaimNonce", ClaimNonce, 10},
	}
	for _, tc := range cwtLabels {
		if tc.label != tc.want {
			t.Errorf("%s = %d, want %d", tc.name, tc.label, tc.want)
		}
	}

	privateLabels := []struct {
		name  string
		label int64
		want  int64
	}{
		{"labelAuthorityRef", labelAuthorityRef, -70001},
		{"labelCapability", labelCapability, -70002},
		{"labelClaim", labelClaim, -70003},
		{"labelEvidence", labelEvidence, -70004},
		{"labelSigningKeyID", labelSigningKeyID, -70005},
		{"labelSigningKeyVersion", labelSigningKeyVersion, -70006},
		{"labelAlgorithm", labelAlgorithm, -70007},
		{"labelStatus", labelStatus, -70008},
	}
	for _, tc := range privateLabels {
		if tc.label != tc.want {
			t.Errorf("%s = %d, want %d", tc.name, tc.label, tc.want)
		}
	}
}

// TestEAT_CanonicalCBORFixture pins the canonical CBOR claim-map
// encoding to a precomputed hex fixture, so a silent change in the
// CBOR encoding options is caught.
func TestEAT_CanonicalCBORFixture(t *testing.T) {
	t.Parallel()

	att := testAttestation(t)
	att.Evidence = nil // keep the fixture minimal
	claims, err := eatClaims(att)
	if err != nil {
		t.Fatalf("eatClaims: %v", err)
	}
	got, err := canonical.CBOREncode(claims)
	if err != nil {
		t.Fatalf("CBOREncode: %v", err)
	}

	// Canonical CBOR map, keys in bytewise order (negative private-use
	// keys sort before positive CWT keys; among equals, shorter
	// Canonical CBOR map with keys in bytewise order of their encoded
	// form: the positive CWT labels (1, 4, 5, 6, 7) first, then the
	// negative private-use labels (0x3a-prefixed four-byte negatives).
	// The exact bytes are pinned below; regenerate deliberately if the
	// encoding intentionally changes.
	want := hexDecode(t, "ad01746469643a6578616d706c653a6174746573746572041a6955b900051a67748580061a683c40c0077840383663363866616138303931316137643233663464383432616132356137393765636134623062343833373562326162393739663064313864333130333234623a000111707840396638366430383138383463376436353961326665616130633535616430313561336266346631623262306238323263643135643663313562306630306130383a0001117158257b226e616d65223a22617474657374222c226e616d657370616365223a227472757374227d3a000111725901267b22697373756572223a226469643a6578616d706c653a636c61696d2d697373756572222c2270726f76656e616e6365223a7b226d6574686f64223a22222c22736f75726365223a22222c2274696d657374616d70223a22303030312d30312d30315430303a30303a30305a227d2c2273636f7065223a7b7d2c227375626a656374223a226469643a6578616d706c653a7375626a656374222c2274797065223a7b226e616d65223a22726f6c65222c226e616d657370616365223a2261636d65227d2c2276616c6964697479223a7b226e6f744166746572223a22323032352d30312d30315430363a30303a30305a222c226e6f744265666f7265223a22323032352d30312d30315430303a30303a30305a227d2c2276616c7565223a2261646d696e227d3a00011173803a000111746a6c6561662d6b65792d313a00011175013a00011176273a0001117701")

	if !bytes.Equal(got, want) {
		t.Fatalf("claims CBOR: got %x, want %x", got, want)
	}
}

// TestMarshalEAT_Nil asserts the nil-attestation rejection.
func TestMarshalEAT_Nil(t *testing.T) {
	t.Parallel()

	if _, err := MarshalEAT(nil); err == nil {
		t.Fatal("MarshalEAT(nil): got nil error, want an error")
	}
}

// TestUnmarshalEAT_Malformed proves malformed and truncated tokens
// return ErrMalformedEAT without panicking.
func TestUnmarshalEAT_Malformed(t *testing.T) {
	t.Parallel()

	att := testAttestation(t)
	token, err := MarshalEAT(att)
	if err != nil {
		t.Fatalf("MarshalEAT: %v", err)
	}

	tests := []struct {
		name  string
		token []byte
	}{
		{"empty", nil},
		{"single byte", []byte{0xa1}},
		{"random bytes", []byte{0x01, 0x02, 0x03, 0x04, 0x05}},
		{"truncated", token[:len(token)/2]},
		{"not an array", func() []byte {
			b, _ := cbor.Marshal("not a token")
			return b
		}()},
		{"wrong arity", func() []byte {
			b, _ := canonical.CBOREncode([]any{[]byte{}, map[int64]any{}, []byte{}})
			return b
		}()},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := UnmarshalEAT(tc.token)
			if !errors.Is(err, ErrMalformedEAT) && !errors.Is(err, ErrInvalidClaims) {
				t.Fatalf("UnmarshalEAT: got %v, want ErrMalformedEAT or ErrInvalidClaims", err)
			}
		})
	}
}

// TestUnmarshalEAT_MissingIssuer proves a payload without iss is
// rejected with ErrInvalidClaims.
func TestUnmarshalEAT_MissingIssuer(t *testing.T) {
	t.Parallel()

	claims := map[int64]any{
		ClaimCWTID: "00",
	}
	payload, err := canonical.CBOREncode(claims)
	if err != nil {
		t.Fatalf("CBOREncode: %v", err)
	}
	token, err := marshalCOSESign1(signature.AlgorithmEdDSA, "", claims, []byte{0x01})
	if err != nil {
		t.Fatalf("marshalCOSESign1: %v", err)
	}
	_ = payload

	_, err = UnmarshalEAT(token)
	if !errors.Is(err, ErrInvalidClaims) {
		t.Fatalf("UnmarshalEAT: got %v, want ErrInvalidClaims", err)
	}
}

// TestUnmarshalEAT_HashMismatch proves a cti that does not match the
// recomputed canonical hash is rejected with ErrEATHashMismatch.
func TestUnmarshalEAT_HashMismatch(t *testing.T) {
	t.Parallel()

	att := testAttestation(t)
	token, err := MarshalEAT(att)
	if err != nil {
		t.Fatalf("MarshalEAT: %v", err)
	}

	// Tamper: decode the token, flip the issuer, re-emit. The payload
	// still decodes, but cti no longer matches the recomputed hash.
	claims, sig, err := parseCOSESign1(token)
	if err != nil {
		t.Fatalf("parseCOSESign1: %v", err)
	}
	claims[ClaimIssuer] = "did:example:tampered"
	tamperedToken, err := marshalCOSESign1(att.Algorithm, att.SigningKeyID, claims, sig)
	if err != nil {
		t.Fatalf("marshalCOSESign1: %v", err)
	}

	_, err = UnmarshalEAT(tamperedToken)
	if !errors.Is(err, ErrEATHashMismatch) {
		t.Fatalf("UnmarshalEAT(tampered): got %v, want ErrEATHashMismatch", err)
	}
}

// TestUnmarshalEAT_EmptyPayload proves an empty payload errors
// instead of panicking.
func TestUnmarshalEAT_EmptyPayload(t *testing.T) {
	t.Parallel()

	token, err := marshalCOSESign1(signature.AlgorithmEdDSA, "", map[int64]any{}, []byte{0x01})
	if err != nil {
		t.Fatalf("marshalCOSESign1: %v", err)
	}
	_, err = UnmarshalEAT(token)
	if err == nil {
		t.Fatal("UnmarshalEAT(empty payload): got nil error, want an error")
	}
}

// TestEAT_NilSignatureRoundTrip asserts an attestation with a nil
// signature marshals and unmarshals with an empty signature slot.
func TestEAT_NilSignatureRoundTrip(t *testing.T) {
	t.Parallel()

	att := testAttestation(t)
	att.Signature = nil

	token, err := MarshalEAT(att)
	if err != nil {
		t.Fatalf("MarshalEAT: %v", err)
	}
	got, err := UnmarshalEAT(token)
	if err != nil {
		t.Fatalf("UnmarshalEAT: %v", err)
	}
	if len(got.Signature) != 0 {
		t.Fatalf("Signature: got %x, want empty", got.Signature)
	}
}

// TestEAT_EmptyEvidenceRoundTrip asserts an attestation with an empty
// evidence slice round-trips.
func TestEAT_EmptyEvidenceRoundTrip(t *testing.T) {
	t.Parallel()

	att := testAttestation(t)
	att.Evidence = nil

	token, err := MarshalEAT(att)
	if err != nil {
		t.Fatalf("MarshalEAT: %v", err)
	}
	got, err := UnmarshalEAT(token)
	if err != nil {
		t.Fatalf("UnmarshalEAT: %v", err)
	}
	if len(got.Evidence) != 0 {
		t.Fatalf("Evidence: got %d entries, want 0", len(got.Evidence))
	}
}

// TestEAT_UnknownLabelsIgnored asserts a payload with unknown extra
// labels is handled without panic and deterministically ignored.
func TestEAT_UnknownLabelsIgnored(t *testing.T) {
	t.Parallel()

	att := testAttestation(t)
	claims, err := eatClaims(att)
	if err != nil {
		t.Fatalf("eatClaims: %v", err)
	}
	claims[int64(-99999)] = "unknown"
	claims[int64(99)] = []byte("extra")

	token, err := marshalCOSESign1(att.Algorithm, att.SigningKeyID, claims, att.Signature)
	if err != nil {
		t.Fatalf("marshalCOSESign1: %v", err)
	}
	got, err := UnmarshalEAT(token)
	if err != nil {
		t.Fatalf("UnmarshalEAT: %v", err)
	}
	if got.Issuer != att.Issuer {
		t.Fatalf("Issuer: got %q, want %q", got.Issuer, att.Issuer)
	}
}

// TestEAT_CtiIsCanonicalHash asserts cti equals hex(CanonicalHash)
// of the attestation.
func TestEAT_CtiIsCanonicalHash(t *testing.T) {
	t.Parallel()

	att := testAttestation(t)
	token, err := MarshalEAT(att)
	if err != nil {
		t.Fatalf("MarshalEAT: %v", err)
	}
	claims, _, err := parseCOSESign1(token)
	if err != nil {
		t.Fatalf("parseCOSESign1: %v", err)
	}
	h, err := CanonicalHash(att)
	if err != nil {
		t.Fatalf("CanonicalHash: %v", err)
	}
	want := hex.EncodeToString(h[:])
	if got, _ := claims[ClaimCWTID].(string); got != want {
		t.Fatalf("cti: got %q, want %q", got, want)
	}
}

// hexDecode decodes a hex fixture string, failing the test on
// invalid hex.
func hexDecode(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("hexDecode(%q): %v", s, err)
	}
	return b
}
