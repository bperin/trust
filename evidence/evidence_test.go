package evidence

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"reflect"
	"testing"
	"time"
)

// testContentHash returns a deterministic 32-byte digest for fixtures.
func testContentHash() []byte {
	h := make([]byte, ContentHashLen)
	for i := range h {
		h[i] = byte(i)
	}
	return h
}

// testEvidence returns a representative populated evidence — the
// canonical form.
func testEvidence() *Evidence {
	return &Evidence{
		Identifier:  "urn:example:evidence:1",
		ContentHash: testContentHash(),
		MediaType:   "application/pdf",
		Locator:     "https://example.com/docs/report-1.pdf",
		Provenance: Provenance{
			Source:    "did:example:issuer",
			Method:    "retrieved",
			Timestamp: time.Date(2025, 3, 1, 12, 0, 0, 0, time.UTC),
		},
		Metadata: map[string]any{
			"origin":  "archive",
			"version": float64(2),
		},
	}
}

func TestEvidence_RoundTrip(t *testing.T) {
	t.Parallel()

	ev := testEvidence()
	raw, err := json.Marshal(ev)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got Evidence
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !reflect.DeepEqual(&got, ev) {
		t.Fatalf("round-trip deep equality:\n got %+v\nwant %+v", &got, ev)
	}
	raw2, err := json.Marshal(&got)
	if err != nil {
		t.Fatalf("re-marshal: %v", err)
	}
	if string(raw2) != string(raw) {
		t.Fatalf("round-trip bytes:\n got %s\nwant %s", raw2, raw)
	}
}

func TestCanonicalHash_Deterministic(t *testing.T) {
	t.Parallel()

	// Same logical evidence built two ways: a single struct literal, and
	// field-by-field assignment with the Metadata map populated in a
	// different insertion order. JCS sorts map keys, so the canonical
	// bytes — and the hash — must be identical.
	a := testEvidence()

	b := &Evidence{}
	b.Locator = "https://example.com/docs/report-1.pdf"
	b.Identifier = "urn:example:evidence:1"
	b.MediaType = "application/pdf"
	b.ContentHash = testContentHash()
	b.Provenance = Provenance{
		Source:    "did:example:issuer",
		Method:    "retrieved",
		Timestamp: time.Date(2025, 3, 1, 12, 0, 0, 0, time.UTC),
	}
	b.Metadata = map[string]any{}
	b.Metadata["version"] = float64(2)
	b.Metadata["origin"] = "archive"

	ha, err := CanonicalHash(a)
	if err != nil {
		t.Fatalf("hash a: %v", err)
	}
	hb, err := CanonicalHash(b)
	if err != nil {
		t.Fatalf("hash b: %v", err)
	}
	if subtle.ConstantTimeCompare(ha[:], hb[:]) != 1 {
		t.Fatalf("CanonicalHash not deterministic across construction:\n got %x\nwant %x", hb, ha)
	}
}

// TestCanonicalHash_Completeness proves every field of Evidence is part
// of the canonical identity: mutating any single field changes the hash.
// In particular, ContentHash — the stored external-material digest — is
// distinct from CanonicalHash, the computed struct identity that covers
// it.
func TestCanonicalHash_Completeness(t *testing.T) {
	t.Parallel()

	base, err := CanonicalHash(testEvidence())
	if err != nil {
		t.Fatalf("hash base: %v", err)
	}

	cases := []struct {
		name   string
		mutate func(*Evidence)
	}{
		{"identifier", func(e *Evidence) { e.Identifier = "urn:example:evidence:2" }},
		{"content hash byte", func(e *Evidence) { e.ContentHash[0] ^= 0xFF }},
		{"media type", func(e *Evidence) { e.MediaType = "text/plain" }},
		{"locator", func(e *Evidence) { e.Locator = "ipfs://QmOther" }},
		{"provenance source", func(e *Evidence) { e.Provenance.Source = "did:example:other" }},
		{"provenance method", func(e *Evidence) { e.Provenance.Method = "generated" }},
		{"provenance timestamp", func(e *Evidence) {
			e.Provenance.Timestamp = e.Provenance.Timestamp.Add(time.Second)
		}},
		{"metadata value", func(e *Evidence) { e.Metadata["version"] = float64(3) }},
		{"metadata key added", func(e *Evidence) { e.Metadata["extra"] = "x" }},
		{"metadata removed", func(e *Evidence) { e.Metadata = nil }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ev := testEvidence()
			tc.mutate(ev)
			got, err := CanonicalHash(ev)
			if err != nil {
				t.Fatalf("hash mutated: %v", err)
			}
			if subtle.ConstantTimeCompare(got[:], base[:]) == 1 {
				t.Fatalf("CanonicalHash unchanged after mutating %s: got %x, want different from %x",
					tc.name, got, base)
			}
		})
	}
}

// TestContentHash_LengthSemantics proves ValidateEvidence pins
// ContentHash to exactly ContentHashLen bytes: nil, empty, and any other
// length are rejected; exactly 32 is accepted.
func TestContentHash_LengthSemantics(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		hash    []byte
		wantErr error
	}{
		{"nil", nil, ErrNilContentHash},
		{"empty non-nil", []byte{}, ErrEmptyContentHash},
		{"16 bytes", make([]byte, 16), ErrContentHashLength},
		{"31 bytes", make([]byte, 31), ErrContentHashLength},
		{"32 bytes", make([]byte, ContentHashLen), nil},
		{"33 bytes", make([]byte, 33), ErrContentHashLength},
		{"64 bytes", make([]byte, 64), ErrContentHashLength},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ev := testEvidence()
			ev.ContentHash = tc.hash
			err := ValidateEvidence(ev)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("ValidateEvidence(len=%d): got err %v, want %v",
					len(tc.hash), err, tc.wantErr)
			}
		})
	}
}
