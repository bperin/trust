package claim

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"math"
	"testing"

	"github.com/bperin/trust/canonical"
)

func TestCanonicalHash_Nil(t *testing.T) {
	t.Parallel()

	got, err := CanonicalHash(nil)
	if !errors.Is(err, ErrNilClaim) {
		t.Fatalf("CanonicalHash(nil): got err %v, want %v", err, ErrNilClaim)
	}
	if got != [32]byte{} {
		t.Fatalf("CanonicalHash(nil): got hash %x, want zero", got)
	}
}

func TestCanonicalHash_CrossConstruction(t *testing.T) {
	t.Parallel()

	// A claim built by Go construction and an identical claim built by
	// JSON round-trip must yield the same canonical hash — the digest
	// depends on logical content, not on how the struct was built.
	a := testClaim()

	raw, err := json.Marshal(a)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var b Claim
	if err := json.Unmarshal(raw, &b); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	ha, err := CanonicalHash(a)
	if err != nil {
		t.Fatalf("hash a: %v", err)
	}
	hb, err := CanonicalHash(&b)
	if err != nil {
		t.Fatalf("hash b: %v", err)
	}
	if subtle.ConstantTimeCompare(ha[:], hb[:]) != 1 {
		t.Fatalf("cross-construction: got %x and %x for identical claims", ha, hb)
	}
}

func TestCanonicalHash_NonCanonicalizableValue(t *testing.T) {
	t.Parallel()

	zero := [32]byte{}
	cases := []struct {
		name    string
		value   any
		wantErr error // nil means any non-nil error is acceptable
	}{
		// NaN and +Inf fail in encoding/json before JCS sees them —
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
		// A channel is not marshalable — encoding/json error propagates.
		{"channel", make(chan int), nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			c := testClaim()
			c.Value = tc.value
			got, err := CanonicalHash(c)
			if err == nil {
				t.Fatalf("CanonicalHash with %T value: got nil err, want non-nil", tc.value)
			}
			if tc.wantErr != nil && !errors.Is(err, tc.wantErr) {
				t.Fatalf("CanonicalHash with %T value: got err %v, want wrapping %v",
					tc.value, err, tc.wantErr)
			}
			if subtle.ConstantTimeCompare(got[:], zero[:]) != 1 {
				t.Fatalf("CanonicalHash with %T value: got digest %x, want zero on error",
					tc.value, got)
			}
		})
	}
}
