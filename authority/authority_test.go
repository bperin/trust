package authority

import (
	"bytes"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/bperin/trust/signature"
)

// testAuthority returns a representative populated root authority with
// sorted capabilities and scope — the canonical form.
func testAuthority() *Authority {
	return &Authority{
		Subject: "did:example:alice",
		Capabilities: []Capability{
			CapabilityAttest,
			CapabilitySign,
		},
		Scope: Scope{
			Resources:     []string{"doc:a", "doc:b"},
			Actions:       []string{"read", "write"},
			Organizations: []string{"org:1"},
			Geography:     []string{"US"},
			Channels:      []string{"api"},
			Subjects:      []string{"did:example:bob"},
			TimeWindow: &TimeWindow{
				Start: time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
				End:   time.Date(2025, 12, 31, 23, 59, 59, 0, time.UTC),
			},
			Quantity: &Quantity{Unit: "operations", Limit: 100},
			Monetary: &Monetary{Currency: "USD", Limit: 1000.50},
		},
		Validity: Validity{
			NotBefore: time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
			NotAfter:  time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		},
		DelegationConstraints: DelegationConstraints{MaxDepth: intPtr(2)},
		Status:                StatusActive,
		Proof: Proof{
			Algorithm: signature.AlgorithmEdDSA,
			KeyID:     "key-1",
			Signature: []byte{0x01, 0x02, 0x03},
		},
	}
}

func intPtr(v int) *int { return &v }

func TestCapability_Equality(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name  string
		a, b  Capability
		equal bool
	}{
		{"same namespace and name", Capability{"trust", "attest"}, Capability{"trust", "attest"}, true},
		{"differing namespace", Capability{"trust", "attest"}, Capability{"other", "attest"}, false},
		{"differing name", Capability{"trust", "attest"}, Capability{"trust", "sign"}, false},
		{"both differing", Capability{"trust", "attest"}, Capability{"other", "sign"}, false},
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

func TestPredefinedCapabilities(t *testing.T) {
	t.Parallel()

	caps := []Capability{
		CapabilityAttest,
		CapabilityDelegate,
		CapabilityRevoke,
		CapabilitySign,
	}
	seen := make(map[string]bool, len(caps))
	for _, c := range caps {
		if c.Namespace != "trust" {
			t.Errorf("predefined capability %v: namespace got %q, want %q", c, c.Namespace, "trust")
		}
		if c.Name == "" {
			t.Errorf("predefined capability %v: empty name", c)
		}
		if seen[c.Name] {
			t.Errorf("predefined capability %v: duplicate name %q", c, c.Name)
		}
		seen[c.Name] = true
	}
}

func TestCapability_ConsumerRoundTrip(t *testing.T) {
	t.Parallel()

	custom := Capability{Namespace: "acme", Name: "launch-rockets"}
	raw, err := json.Marshal(custom)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got Capability
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got != custom {
		t.Fatalf("round-trip: got %+v, want %+v", got, custom)
	}
}

func TestValidateCapabilities(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		caps    []Capability
		wantErr error
	}{
		{"nil slice", nil, nil},
		{"empty slice", []Capability{}, nil},
		{"single capability", []Capability{CapabilitySign}, nil},
		{
			"sorted distinct",
			[]Capability{CapabilityAttest, CapabilityDelegate, CapabilitySign},
			nil,
		},
		{
			"sorted across namespaces",
			[]Capability{{"acme", "z"}, {"trust", "attest"}},
			nil,
		},
		{
			"unsorted",
			[]Capability{CapabilitySign, CapabilityAttest},
			ErrUnsortedCapabilities,
		},
		{
			"unsorted across namespaces",
			[]Capability{{"trust", "attest"}, {"acme", "a"}},
			ErrUnsortedCapabilities,
		},
		{
			"duplicate pair",
			[]Capability{CapabilityAttest, CapabilityAttest},
			ErrUnsortedCapabilities,
		},
		{
			"empty namespace",
			[]Capability{{Namespace: "", Name: "x"}},
			ErrEmptyCapabilityNamespace,
		},
		{
			"empty name",
			[]Capability{{Namespace: "trust", Name: ""}},
			ErrEmptyCapabilityName,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := ValidateCapabilities(tc.caps)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("ValidateCapabilities(%v): got err %v, want %v", tc.caps, err, tc.wantErr)
			}
		})
	}
}

func TestScope_ZeroValueMarshal(t *testing.T) {
	t.Parallel()

	raw, err := json.Marshal(Scope{})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if string(raw) != "{}" {
		t.Fatalf("zero scope marshal: got %s, want {}", raw)
	}
}

func TestScope_RoundTrip(t *testing.T) {
	t.Parallel()

	scope := Scope{
		Resources:     []string{"doc:a", "doc:b"},
		Subjects:      []string{"did:example:bob"},
		Actions:       []string{"read", "write"},
		Organizations: []string{"org:1", "org:2"},
		Geography:     []string{"EU", "US"},
		Channels:      []string{"api", "web"},
		TimeWindow: &TimeWindow{
			Start: time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
			End:   time.Date(2025, 6, 30, 0, 0, 0, 0, time.UTC),
		},
		Quantity: &Quantity{Unit: "ops", Limit: 42},
		Monetary: &Monetary{Currency: "EUR", Limit: 99.95},
	}
	raw, err := json.Marshal(scope)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got Scope
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	raw2, err := json.Marshal(got)
	if err != nil {
		t.Fatalf("re-marshal: %v", err)
	}
	if !bytes.Equal(raw, raw2) {
		t.Fatalf("round-trip bytes: got %s, want %s", raw2, raw)
	}
}

func TestValidateScope(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		scope   Scope
		wantErr error
	}{
		{"zero scope", Scope{}, nil},
		{"sorted dimensions", Scope{
			Resources: []string{"a", "b"},
			Actions:   []string{"read", "write"},
		}, nil},
		{"single element", Scope{Resources: []string{"a"}}, nil},
		{"unsorted resources", Scope{Resources: []string{"b", "a"}}, ErrUnsortedScope},
		{"unsorted subjects", Scope{Subjects: []string{"b", "a"}}, ErrUnsortedScope},
		{"unsorted actions", Scope{Actions: []string{"write", "read"}}, ErrUnsortedScope},
		{"unsorted organizations", Scope{Organizations: []string{"z", "a"}}, ErrUnsortedScope},
		{"unsorted geography", Scope{Geography: []string{"US", "EU"}}, ErrUnsortedScope},
		{"unsorted channels", Scope{Channels: []string{"web", "api"}}, ErrUnsortedScope},
		{"duplicate values", Scope{Resources: []string{"a", "a"}}, ErrUnsortedScope},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := ValidateScope(tc.scope)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("ValidateScope(%+v): got err %v, want %v", tc.scope, err, tc.wantErr)
			}
		})
	}
}

func TestStatus_JSON(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name   string
		status Status
		want   string
	}{
		{"active", StatusActive, "1"},
		{"revoked", StatusRevoked, "2"},
		{"superseded", StatusSuperseded, "3"},
		{"expired", StatusExpired, "4"},
	}
	seen := make(map[string]bool, len(cases))
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			raw, err := json.Marshal(tc.status)
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			if string(raw) != tc.want {
				t.Fatalf("marshal: got %s, want %s", raw, tc.want)
			}
			var got Status
			if err := json.Unmarshal(raw, &got); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			if got != tc.status {
				t.Fatalf("round-trip: got %d, want %d", got, tc.status)
			}
		})
		if seen[tc.want] {
			t.Fatalf("status %v marshals to %s already used by another constant", tc.status, tc.want)
		}
		seen[tc.want] = true
	}
}

func TestAuthority_MarshalRoundTrip(t *testing.T) {
	t.Parallel()

	auth := testAuthority()
	raw, err := json.Marshal(auth)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got Authority
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	raw2, err := json.Marshal(&got)
	if err != nil {
		t.Fatalf("re-marshal: %v", err)
	}
	if !bytes.Equal(raw, raw2) {
		t.Fatalf("round-trip bytes:\n got %s\nwant %s", raw2, raw)
	}
}

func TestValidate(t *testing.T) {
	t.Parallel()

	good := testAuthority()

	badSubject := testAuthority()
	badSubject.Subject = ""

	badStatus := testAuthority()
	badStatus.Status = Status(99)

	zeroStatus := testAuthority()
	zeroStatus.Status = Status(0)

	badCaps := testAuthority()
	badCaps.Capabilities = []Capability{CapabilitySign, CapabilityAttest}

	badScope := testAuthority()
	badScope.Scope.Resources = []string{"b", "a"}

	cases := []struct {
		name    string
		auth    *Authority
		wantErr error
	}{
		{"nil authority", nil, ErrNilAuthority},
		{"valid authority", good, nil},
		{"empty subject", badSubject, ErrEmptySubject},
		{"unknown status", badStatus, ErrUnknownStatus},
		{"zero status", zeroStatus, ErrUnknownStatus},
		{"unsorted capabilities", badCaps, ErrUnsortedCapabilities},
		{"unsorted scope", badScope, ErrUnsortedScope},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := Validate(tc.auth)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("Validate: got err %v, want %v", err, tc.wantErr)
			}
		})
	}
}

func TestCanonicalHash_StatusDistinction(t *testing.T) {
	t.Parallel()

	active := testAuthority()
	active.Status = StatusActive

	revoked := testAuthority()
	revoked.Status = StatusRevoked

	hActive, err := CanonicalHash(active)
	if err != nil {
		t.Fatalf("hash active: %v", err)
	}
	hRevoked, err := CanonicalHash(revoked)
	if err != nil {
		t.Fatalf("hash revoked: %v", err)
	}
	if hActive == hRevoked {
		t.Fatal("CanonicalHash: revoked authority produced same hash as active")
	}
}
