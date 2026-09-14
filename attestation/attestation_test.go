package attestation

import (
	"bytes"
	"crypto/subtle"
	"encoding/json"
	"reflect"
	"sort"
	"testing"
	"time"

	"github.com/bperin/trust/authority"
	"github.com/bperin/trust/canonical"
	"github.com/bperin/trust/claim"
	"github.com/bperin/trust/evidence"
	"github.com/bperin/trust/signature"
)

// Fixed times — deterministic across runs.
var (
	attIssuedAt  = time.Date(2025, 6, 1, 12, 0, 0, 0, time.UTC)
	attNotBefore = time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	attNotAfter  = attNotBefore.AddDate(1, 0, 0)
)

// testClaim returns a structurally valid claim. Its Issuer and
// Validity deliberately differ from the attestation's own so tests
// prove the named claim field is committed to the canonical hash.
func testClaim() claim.Claim {
	return claim.Claim{
		Issuer:  "did:example:claim-issuer",
		Subject: "did:example:subject",
		Type:    claim.ClaimType{Namespace: "acme", Name: "role"},
		Value:   "admin",
		Validity: authority.Validity{
			NotBefore: attNotBefore,
			NotAfter:  attNotBefore.Add(6 * time.Hour),
		},
	}
}

// testEvidence returns a structurally valid evidence reference whose
// identity is derived from id — distinct ids yield distinct canonical
// hashes.
func testEvidence(id string) evidence.Evidence {
	h := make([]byte, evidence.ContentHashLen)
	for i := range h {
		h[i] = byte(i) ^ byte(len(id))
	}
	return evidence.Evidence{
		Identifier:  id,
		ContentHash: h,
		MediaType:   "application/pdf",
		Locator:     "ipfs://example/" + id,
		Provenance: evidence.Provenance{
			Source:    "did:example:evidence-source",
			Method:    "retrieved",
			Timestamp: attIssuedAt,
		},
	}
}

// sortEvidence orders evs strictly ascending by evidence.CanonicalHash
// — the canonical form Validate requires. It is the test-side
// normalizer; production code never sorts.
func sortEvidence(t *testing.T, evs []evidence.Evidence) []evidence.Evidence {
	t.Helper()
	type hashed struct {
		ev evidence.Evidence
		h  [32]byte
	}
	hs := make([]hashed, len(evs))
	for i, ev := range evs {
		h, err := evidence.CanonicalHash(&ev)
		if err != nil {
			t.Fatalf("evidence.CanonicalHash: %v", err)
		}
		hs[i] = hashed{ev, h}
	}
	sort.Slice(hs, func(i, j int) bool {
		return bytes.Compare(hs[i].h[:], hs[j].h[:]) < 0
	})
	out := make([]evidence.Evidence, len(hs))
	for i, h := range hs {
		out[i] = h.ev
	}
	return out
}

// testAttestation returns a fully populated, structurally valid,
// unsigned Attestation with two evidence references in canonical
// order.
func testAttestation(t *testing.T) *Attestation {
	t.Helper()
	return &Attestation{
		Issuer:            "did:example:attester",
		SigningKeyID:      "leaf-key-1",
		SigningKeyVersion: 1,
		AuthorityRef:      "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
		Capability:        authority.CapabilityAttest,
		Claim:             testClaim(),
		Evidence:          sortEvidence(t, []evidence.Evidence{testEvidence("ev-b"), testEvidence("ev-a")}),
		IssuedAt:          attIssuedAt,
		Validity: authority.Validity{
			NotBefore: attNotBefore,
			NotAfter:  attNotAfter,
		},
		Status:    authority.StatusActive,
		Algorithm: signature.AlgorithmEdDSA,
	}
}

// hashEqual reports whether two digests are equal in constant time.
func hashEqual(a, b [32]byte) bool {
	return subtle.ConstantTimeCompare(a[:], b[:]) == 1
}

// TestAttestation_RoundTrip marshals a fully populated Attestation via
// encoding/json and unmarshals it into a fresh value, asserting deep
// equality. The named Claim field — whose Issuer and Validity differ
// from the attestation's own — must survive: anonymous embedding would
// drop it on the colliding "issuer"/"validity" tags.
func TestAttestation_RoundTrip(t *testing.T) {
	t.Parallel()

	att := testAttestation(t)
	att.Signature = []byte{0xde, 0xad, 0xbe, 0xef}
	if att.Claim.Issuer == att.Issuer {
		t.Fatal("test setup: claim issuer must differ from attestation issuer")
	}

	raw, err := json.Marshal(att)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got Attestation
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !reflect.DeepEqual(*att, got) {
		t.Fatalf("round-trip mismatch:\n got %+v\nwant %+v", got, *att)
	}
	// The claim's own issuer and validity must be present under the
	// "claim" member — not shadowed by the attestation's fields.
	var probe map[string]json.RawMessage
	if err := json.Unmarshal(raw, &probe); err != nil {
		t.Fatalf("probe unmarshal: %v", err)
	}
	if _, ok := probe["claim"]; !ok {
		t.Fatal("round-trip JSON has no \"claim\" member")
	}
}

// TestCanonicalEncoding_ReturnsJSON asserts the attestation declares
// canonical.EncodingJSON (JCS per [RFC 8785]) as its canonical
// encoding.
func TestCanonicalEncoding_ReturnsJSON(t *testing.T) {
	t.Parallel()

	att := testAttestation(t)
	if got := att.CanonicalEncoding(); got != canonical.EncodingJSON {
		t.Fatalf("CanonicalEncoding(): got %v, want canonical.EncodingJSON", got)
	}
}

// TestValidate_Valid asserts a well-formed attestation passes Validate
// under each of the four known lifecycle statuses.
func TestValidate_Valid(t *testing.T) {
	t.Parallel()

	statuses := []struct {
		name   string
		status authority.Status
	}{
		{"active", authority.StatusActive},
		{"revoked", authority.StatusRevoked},
		{"superseded", authority.StatusSuperseded},
		{"expired", authority.StatusExpired},
	}
	for _, tc := range statuses {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			att := testAttestation(t)
			att.Status = tc.status
			if err := Validate(att); err != nil {
				t.Fatalf("Validate: got %v, want nil", err)
			}
		})
	}
}

// TestCanonicalHash_FieldCoverage proves every field except Signature
// is committed to the canonical hash: mutating each one changes the
// digest, while mutating only Signature does not.
func TestCanonicalHash_FieldCoverage(t *testing.T) {
	t.Parallel()

	base := testAttestation(t)
	baseHash, err := CanonicalHash(base)
	if err != nil {
		t.Fatalf("CanonicalHash(base): %v", err)
	}

	mutations := []struct {
		name   string
		mutate func(a *Attestation)
	}{
		{"Issuer", func(a *Attestation) { a.Issuer = "did:example:other" }},
		{"SigningKeyID", func(a *Attestation) { a.SigningKeyID = "leaf-key-2" }},
		{"SigningKeyVersion", func(a *Attestation) { a.SigningKeyVersion++ }},
		{"AuthorityRef", func(a *Attestation) {
			a.AuthorityRef = "0000000000000000000000000000000000000000000000000000000000000000"
		}},
		{"Capability", func(a *Attestation) { a.Capability = authority.CapabilitySign }},
		{"Claim.Issuer", func(a *Attestation) { a.Claim.Issuer = "did:example:other-claim-issuer" }},
		{"Claim.Subject", func(a *Attestation) { a.Claim.Subject = "did:example:other-subject" }},
		{"Claim.Validity", func(a *Attestation) {
			a.Claim.Validity.NotAfter = a.Claim.Validity.NotAfter.Add(time.Hour)
		}},
		{"Evidence entry", func(a *Attestation) { a.Evidence[0].Identifier = "ev-changed" }},
		{"IssuedAt", func(a *Attestation) { a.IssuedAt = a.IssuedAt.Add(time.Hour) }},
		{"Validity", func(a *Attestation) { a.Validity.NotAfter = a.Validity.NotAfter.Add(time.Hour) }},
		{"Status", func(a *Attestation) { a.Status = authority.StatusRevoked }},
		{"Algorithm", func(a *Attestation) { a.Algorithm = signature.AlgorithmES256 }},
	}
	for _, tc := range mutations {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			att := testAttestation(t)
			tc.mutate(att)
			got, err := CanonicalHash(att)
			if err != nil {
				t.Fatalf("CanonicalHash(mutated %s): %v", tc.name, err)
			}
			if hashEqual(got, baseHash) {
				t.Fatalf("mutating %s did not change digest %x — field not hashed",
					tc.name, got)
			}
		})
	}

	t.Run("Signature excluded", func(t *testing.T) {
		t.Parallel()
		att := testAttestation(t)
		att.Signature = []byte{0x01, 0x02, 0x03}
		got, err := CanonicalHash(att)
		if err != nil {
			t.Fatalf("CanonicalHash(signed): %v", err)
		}
		if !hashEqual(got, baseHash) {
			t.Fatalf("setting Signature changed digest: got %x, want %x", got, baseHash)
		}
		// The caller's value must not be mutated by hashing.
		if !bytes.Equal(att.Signature, []byte{0x01, 0x02, 0x03}) {
			t.Fatalf("CanonicalHash mutated caller Signature: got %x", att.Signature)
		}
	})
}
