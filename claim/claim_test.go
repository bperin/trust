package claim

import (
	"bytes"
	"crypto/subtle"
	"encoding/json"
	"reflect"
	"testing"
	"time"

	"github.com/bperin/trust/authority"
)

// testClaim returns a representative populated claim in canonical form:
// sorted scope dimensions, non-zero validity, provenance, and a string
// value.
func testClaim() *Claim {
	return &Claim{
		Issuer:  "did:example:issuer",
		Subject: "did:example:subject",
		Type:    ClaimType{Namespace: "acme", Name: "role"},
		Value:   "admin",
		Scope: authority.Scope{
			Resources: []string{"doc:a", "doc:b"},
			Actions:   []string{"read", "write"},
		},
		Validity: authority.Validity{
			NotBefore: time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
			NotAfter:  time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		},
		Provenance: Provenance{
			Source:    "https://acme.example/claims/1",
			Method:    "verified-import",
			Timestamp: time.Date(2025, 1, 2, 0, 0, 0, 0, time.UTC),
		},
	}
}

// hashEqual compares two digests in constant time — digests are
// security-sensitive values.
func hashEqual(a, b [32]byte) bool {
	return subtle.ConstantTimeCompare(a[:], b[:]) == 1
}

func TestClaim_RoundTrip(t *testing.T) {
	t.Parallel()

	c := testClaim()
	raw, err := json.Marshal(c)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got Claim
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !reflect.DeepEqual(&got, c) {
		t.Fatalf("round-trip:\n got %+v\nwant %+v", &got, c)
	}
	// Re-marshal must be byte-identical.
	raw2, err := json.Marshal(&got)
	if err != nil {
		t.Fatalf("re-marshal: %v", err)
	}
	if !bytes.Equal(raw, raw2) {
		t.Fatalf("round-trip bytes:\n got %s\nwant %s", raw2, raw)
	}
}

func TestCanonicalHash_Deterministic(t *testing.T) {
	t.Parallel()

	// Two logically identical claims built independently — one by
	// struct literal, one field-by-field in a different order — must
	// yield the same canonical hash.
	a := testClaim()

	b := &Claim{}
	b.Provenance.Method = "verified-import"
	b.Provenance.Source = "https://acme.example/claims/1"
	b.Provenance.Timestamp = time.Date(2025, 1, 2, 0, 0, 0, 0, time.UTC)
	b.Validity.NotAfter = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	b.Validity.NotBefore = time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	b.Scope.Actions = []string{"read", "write"}
	b.Scope.Resources = []string{"doc:a", "doc:b"}
	b.Value = "admin"
	b.Type = ClaimType{Namespace: "acme", Name: "role"}
	b.Subject = "did:example:subject"
	b.Issuer = "did:example:issuer"

	ha, err := CanonicalHash(a)
	if err != nil {
		t.Fatalf("hash a: %v", err)
	}
	hb, err := CanonicalHash(b)
	if err != nil {
		t.Fatalf("hash b: %v", err)
	}
	if !hashEqual(ha, hb) {
		t.Fatalf("determinism: got %x and %x for identical claims", ha, hb)
	}
}

func TestCanonicalHash_Completeness(t *testing.T) {
	t.Parallel()

	base := testClaim()
	hBase, err := CanonicalHash(base)
	if err != nil {
		t.Fatalf("hash base: %v", err)
	}

	cases := []struct {
		name   string
		mutate func(*Claim)
	}{
		{"issuer", func(c *Claim) { c.Issuer = "did:example:other" }},
		{"subject", func(c *Claim) { c.Subject = "did:example:other" }},
		{"type namespace", func(c *Claim) { c.Type.Namespace = "other" }},
		{"type name", func(c *Claim) { c.Type.Name = "other" }},
		{"value", func(c *Claim) { c.Value = "user" }},
		{"scope dimension", func(c *Claim) { c.Scope.Resources = []string{"doc:a", "doc:c"} }},
		{"validity notBefore", func(c *Claim) {
			c.Validity.NotBefore = time.Date(2025, 2, 1, 0, 0, 0, 0, time.UTC)
		}},
		{"provenance source", func(c *Claim) { c.Provenance.Source = "other" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			c := testClaim()
			tc.mutate(c)
			got, err := CanonicalHash(c)
			if err != nil {
				t.Fatalf("hash: %v", err)
			}
			if hashEqual(got, hBase) {
				t.Fatalf("mutating %s did not change hash: got %x, want different from %x",
					tc.name, got, hBase)
			}
		})
	}
}

func TestClaimType_Equality(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name  string
		a, b  ClaimType
		equal bool
	}{
		{"same namespace and name", ClaimType{"acme", "role"}, ClaimType{"acme", "role"}, true},
		{"differing namespace", ClaimType{"acme", "role"}, ClaimType{"other", "role"}, false},
		{"differing name", ClaimType{"acme", "role"}, ClaimType{"acme", "team"}, false},
		{"both differing", ClaimType{"acme", "role"}, ClaimType{"other", "team"}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := tc.a == tc.b; got != tc.equal {
				t.Fatalf("equality: got %v, want %v (%v vs %v)", got, tc.equal, tc.a, tc.b)
			}
		})
	}
}

func TestClaimType_ConsumerRoundTrip(t *testing.T) {
	t.Parallel()

	custom := ClaimType{Namespace: "acme", Name: "role"}
	raw, err := json.Marshal(custom)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if string(raw) != `{"namespace":"acme","name":"role"}` {
		t.Fatalf("marshal: got %s, want %s", raw, `{"namespace":"acme","name":"role"}`)
	}
	var got ClaimType
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got != custom {
		t.Fatalf("round-trip: got %+v, want %+v", got, custom)
	}
}

func TestScope_ZeroValueSerializesToEmptyObject(t *testing.T) {
	t.Parallel()

	c := testClaim()
	c.Scope = authority.Scope{}
	raw, err := json.Marshal(c)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if !bytes.Contains(raw, []byte(`"scope":{}`)) {
		t.Fatalf("zero scope: got %s, want JSON containing %s", raw, `"scope":{}`)
	}
}

func TestScope_WithDimensionsRoundTrips(t *testing.T) {
	t.Parallel()

	c := testClaim()
	raw, err := json.Marshal(c)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got Claim
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !reflect.DeepEqual(got.Scope, c.Scope) {
		t.Fatalf("scope round-trip: got %+v, want %+v", got.Scope, c.Scope)
	}
}

func TestValidity_RoundTrip(t *testing.T) {
	t.Parallel()

	c := testClaim()
	raw, err := json.Marshal(c)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got Claim
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.Validity != c.Validity {
		t.Fatalf("validity round-trip: got %+v, want %+v", got.Validity, c.Validity)
	}
}

func TestValue_TypesCanonicalize(t *testing.T) {
	t.Parallel()

	zero := [32]byte{}
	cases := []struct {
		name  string
		value any
	}{
		{"string", "hello"},
		{"int", 42},
		{"float64", 3.14},
		{"bool", true},
		{"array", []any{"a", 1, true}},
		{"object", map[string]any{"k": "v", "n": 1.5}},
		{"time.Time (RFC 3339)", time.Date(2025, 6, 15, 12, 30, 0, 0, time.UTC)},
		{"[]byte (base64)", []byte{0x01, 0x02, 0x03}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			c := testClaim()
			c.Value = tc.value
			got, err := CanonicalHash(c)
			if err != nil {
				t.Fatalf("CanonicalHash with %T value: %v", tc.value, err)
			}
			if hashEqual(got, zero) {
				t.Fatalf("CanonicalHash with %T value: got zero digest", tc.value)
			}
		})
	}
}
