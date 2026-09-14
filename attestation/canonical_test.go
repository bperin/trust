package attestation

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"math"
	"testing"

	"github.com/bperin/trust/canonical"
	"github.com/bperin/trust/evidence"
)

// TestCanonicalHash_Nil asserts the nil attestation returns
// ErrNilAttestation and a zero digest.
func TestCanonicalHash_Nil(t *testing.T) {
	t.Parallel()

	got, err := CanonicalHash(nil)
	if !errors.Is(err, ErrNilAttestation) {
		t.Fatalf("CanonicalHash(nil): got err %v, want %v", err, ErrNilAttestation)
	}
	if got != [32]byte{} {
		t.Fatalf("CanonicalHash(nil): got hash %x, want zero", got)
	}
}

// TestCanonicalHash_Deterministic asserts two independently constructed
// identical attestations produce identical digests.
func TestCanonicalHash_Deterministic(t *testing.T) {
	t.Parallel()

	a := testAttestation(t)
	b := testAttestation(t)

	ha, err := CanonicalHash(a)
	if err != nil {
		t.Fatalf("CanonicalHash(a): %v", err)
	}
	hb, err := CanonicalHash(b)
	if err != nil {
		t.Fatalf("CanonicalHash(b): %v", err)
	}
	if subtle.ConstantTimeCompare(ha[:], hb[:]) != 1 {
		t.Fatalf("determinism: got %x and %x for identical attestations", ha, hb)
	}
}

// TestCanonicalHash_ConstructionOrderIndependent asserts two
// attestations whose evidence slices were appended in different orders
// and then canonically sorted produce identical digests — the identity
// depends on logical content, not construction order.
func TestCanonicalHash_ConstructionOrderIndependent(t *testing.T) {
	t.Parallel()

	a := testAttestation(t)
	a.Evidence = sortEvidence(t, []evidence.Evidence{testEvidence("ev-a"), testEvidence("ev-b")})

	b := testAttestation(t)
	b.Evidence = sortEvidence(t, []evidence.Evidence{testEvidence("ev-b"), testEvidence("ev-a")})

	ha, err := CanonicalHash(a)
	if err != nil {
		t.Fatalf("CanonicalHash(a): %v", err)
	}
	hb, err := CanonicalHash(b)
	if err != nil {
		t.Fatalf("CanonicalHash(b): %v", err)
	}
	if subtle.ConstantTimeCompare(ha[:], hb[:]) != 1 {
		t.Fatalf("construction order: got %x and %x for identical attestations", ha, hb)
	}
}

// TestCanonicalHash_CrossEncoding asserts an attestation built by Go
// construction and an identical attestation recovered from a JSON
// round-trip produce the same canonical hash.
func TestCanonicalHash_CrossEncoding(t *testing.T) {
	t.Parallel()

	a := testAttestation(t)
	raw, err := json.Marshal(a)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var b Attestation
	if err := json.Unmarshal(raw, &b); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	ha, err := CanonicalHash(a)
	if err != nil {
		t.Fatalf("CanonicalHash(a): %v", err)
	}
	hb, err := CanonicalHash(&b)
	if err != nil {
		t.Fatalf("CanonicalHash(b): %v", err)
	}
	if subtle.ConstantTimeCompare(ha[:], hb[:]) != 1 {
		t.Fatalf("cross-encoding: got %x and %x for identical attestations", ha, hb)
	}
}

// TestCanonicalHash_NonCanonicalizableClaim asserts a claim value that
// JCS cannot canonicalize surfaces the canonical package's error with a
// zero digest.
func TestCanonicalHash_NonCanonicalizableClaim(t *testing.T) {
	t.Parallel()

	zero := [32]byte{}
	cases := []struct {
		name    string
		value   any
		wantErr error // nil means any non-nil error is acceptable
	}{
		// NaN and ±Inf fail in encoding/json before JCS sees them —
		// the marshal error propagates wrapped.
		{"NaN", math.NaN(), nil},
		{"+Inf", math.Inf(1), nil},
		{"-Inf", math.Inf(-1), nil},
		// A number literal that parses to +Inf reaches the JCS layer
		// and is rejected as non-finite per [RFC 8785] §3.2.2.3.
		{"overflow literal", json.Number("1e999"), canonical.ErrNonFiniteNumber},
		// 2^53+1 is not exactly representable as an IEEE 754 double;
		// the integer literal is rejected rather than rounded (A05).
		{"lossy integer", int64(1)<<53 + 1, canonical.ErrLossyNumber},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			att := testAttestation(t)
			att.Claim.Value = tc.value
			got, err := CanonicalHash(att)
			if err == nil {
				t.Fatalf("CanonicalHash with %T claim value: got nil err, want non-nil", tc.value)
			}
			if tc.wantErr != nil && !errors.Is(err, tc.wantErr) {
				t.Fatalf("CanonicalHash with %T claim value: got err %v, want wrapping %v",
					tc.value, err, tc.wantErr)
			}
			if subtle.ConstantTimeCompare(got[:], zero[:]) != 1 {
				t.Fatalf("CanonicalHash with %T claim value: got digest %x, want zero on error",
					tc.value, got)
			}
		})
	}
}

// TestCanonicalHash_DoesNotMutateCaller asserts the signature is zeroed
// on a shallow copy — the caller's attestation keeps its Signature.
func TestCanonicalHash_DoesNotMutateCaller(t *testing.T) {
	t.Parallel()

	att := testAttestation(t)
	att.Signature = []byte{0xaa, 0xbb, 0xcc}
	if _, err := CanonicalHash(att); err != nil {
		t.Fatalf("CanonicalHash: %v", err)
	}
	if subtle.ConstantTimeCompare(att.Signature, []byte{0xaa, 0xbb, 0xcc}) != 1 {
		t.Fatalf("CanonicalHash mutated caller Signature: got %x", att.Signature)
	}
}
