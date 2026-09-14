package evidence

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"math"
	"testing"
	"time"

	"github.com/bperin/trust/canonical"
)

func TestCanonicalHash_Nil(t *testing.T) {
	t.Parallel()

	digest, err := CanonicalHash(nil)
	if !errors.Is(err, ErrNilEvidence) {
		t.Fatalf("CanonicalHash(nil): got err %v, want %v", err, ErrNilEvidence)
	}
	if digest != [32]byte{} {
		t.Fatalf("CanonicalHash(nil): got digest %x, want zero [32]byte", digest)
	}
}

// TestCanonicalHash_CrossConstruction repeats the determinism check with
// two fully independent construction paths, including Metadata maps
// populated in opposite key order.
func TestCanonicalHash_CrossConstruction(t *testing.T) {
	t.Parallel()

	a := &Evidence{
		Identifier:  "urn:example:evidence:x",
		ContentHash: testContentHash(),
		MediaType:   "application/json",
		Locator:     "ipfs://QmX",
		Provenance: Provenance{
			Source:    "system-a",
			Method:    "generated",
			Timestamp: time.Date(2025, 6, 15, 0, 0, 0, 0, time.UTC),
		},
		Metadata: map[string]any{"a": "1", "b": "2", "c": "3"},
	}

	b := &Evidence{
		Identifier:  "urn:example:evidence:x",
		ContentHash: testContentHash(),
		MediaType:   "application/json",
		Locator:     "ipfs://QmX",
		Provenance: Provenance{
			Source:    "system-a",
			Method:    "generated",
			Timestamp: time.Date(2025, 6, 15, 0, 0, 0, 0, time.UTC),
		},
		Metadata: map[string]any{"c": "3", "b": "2", "a": "1"},
	}

	ha, err := CanonicalHash(a)
	if err != nil {
		t.Fatalf("hash a: %v", err)
	}
	hb, err := CanonicalHash(b)
	if err != nil {
		t.Fatalf("hash b: %v", err)
	}
	if subtle.ConstantTimeCompare(ha[:], hb[:]) != 1 {
		t.Fatalf("CanonicalHash differs across construction:\n got %x\nwant %x", hb, ha)
	}
}

// TestCanonicalHash_NonCanonicalizableMetadata proves a Metadata value
// that cannot be represented in the [RFC 8785] JSON data model is
// rejected and produces no digest. Rejection happens at two layers:
// encoding/json refuses NaN and Inf outright at marshal time, while a
// number literal that decodes to a non-finite double (e.g. "1e999") and
// an inexact integer literal (e.g. 2^53+1) are rejected by the
// canonicalizer with ErrNonFiniteNumber and ErrLossyNumber.
func TestCanonicalHash_NonCanonicalizableMetadata(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		value   any
		wantErr error // nil means any non-nil error is acceptable
	}{
		{"NaN", math.NaN(), nil},
		{"positive infinity", math.Inf(1), nil},
		{"negative infinity", math.Inf(-1), nil},
		{"literal 1e999 overflows to +Inf", json.Number("1e999"), canonical.ErrNonFiniteNumber},
		{"literal -1e999 overflows to -Inf", json.Number("-1e999"), canonical.ErrNonFiniteNumber},
		{"lossy integer 2^53+1", int64(1)<<53 + 1, canonical.ErrLossyNumber},
		{"lossy integer max int64", int64(math.MaxInt64), canonical.ErrLossyNumber},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ev := testEvidence()
			ev.Metadata = map[string]any{"bad": tc.value}
			digest, err := CanonicalHash(ev)
			if err == nil {
				t.Fatalf("CanonicalHash(Metadata %v): got nil error, want error", tc.value)
			}
			if tc.wantErr != nil && !errors.Is(err, tc.wantErr) {
				t.Fatalf("CanonicalHash(Metadata %v): got err %v, want errors.Is(_, %v)",
					tc.value, err, tc.wantErr)
			}
			if digest != [32]byte{} {
				t.Fatalf("CanonicalHash(Metadata %v): got digest %x, want zero [32]byte",
					tc.value, digest)
			}
		})
	}
}
