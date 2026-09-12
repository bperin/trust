package authority

import (
	"crypto"
	"crypto/elliptic"
	"fmt"
	"os"
	"slices"
	"testing"
	"time"

	"github.com/bperin/trust/crypto/ecdsa"
	"github.com/bperin/trust/crypto/ed25519"
	"github.com/bperin/trust/crypto/rsa"
	"github.com/bperin/trust/crypto/secp256k1"
	"github.com/bperin/trust/signature"
)

// keypair is a generated trust keypair for one algorithm.
type keypair struct {
	priv crypto.PrivateKey
	pub  crypto.PublicKey
}

// genPair generates a fresh trust keypair for one registered
// algorithm.
func genPair(alg signature.Algorithm) (keypair, error) {
	switch alg {
	case signature.AlgorithmEdDSA:
		priv, pub, err := ed25519.GenerateKey()
		return keypair{priv, pub}, err
	case signature.AlgorithmES256K:
		priv, pub, err := secp256k1.GenerateKey()
		return keypair{priv, pub}, err
	case signature.AlgorithmES256:
		priv, pub, err := ecdsa.GenerateKey(elliptic.P256(), crypto.SHA256)
		return keypair{priv, pub}, err
	case signature.AlgorithmES384:
		priv, pub, err := ecdsa.GenerateKey(elliptic.P384(), crypto.SHA384)
		return keypair{priv, pub}, err
	case signature.AlgorithmPS256:
		priv, pub, err := rsa.GeneratePSSKey(2048, crypto.SHA256)
		return keypair{priv, pub}, err
	case signature.AlgorithmRS256:
		priv, pub, err := rsa.GeneratePKCS1Key(2048, crypto.SHA256)
		return keypair{priv, pub}, err
	default:
		return keypair{}, fmt.Errorf("untested algorithm %v", alg)
	}
}

// algorithmCases covers all six registered signature algorithms:
// ed25519 (default), secp256k1, ecdsa-p256, ecdsa-p384, rsa-pss, and
// rsa-pkcs1v15.
var algorithmCases = []struct {
	name string
	alg  signature.Algorithm
}{
	{"ed25519", signature.AlgorithmEdDSA},
	{"secp256k1", signature.AlgorithmES256K},
	{"ecdsa-p256", signature.AlgorithmES256},
	{"ecdsa-p384", signature.AlgorithmES384},
	{"rsa-pss", signature.AlgorithmPS256},
	{"rsa-pkcs1v15", signature.AlgorithmRS256},
}

// keyPool holds four pre-generated keypairs per algorithm (root +
// three chain keys) so RSA key generation cost is paid once in
// TestMain rather than per test. Keys are shared read-only across
// tests; every chain gets its own link values.
var keyPool map[signature.Algorithm][]keypair

func TestMain(m *testing.M) {
	keyPool = make(map[signature.Algorithm][]keypair, len(algorithmCases))
	for _, tc := range algorithmCases {
		for i := 0; i < 4; i++ {
			kp, err := genPair(tc.alg)
			if err != nil {
				panic(fmt.Sprintf("genPair(%s): %v", tc.name, err))
			}
			keyPool[tc.alg] = append(keyPool[tc.alg], kp)
		}
	}
	os.Exit(m.Run())
}

func u64(v uint64) *uint64 { return &v }
func u(v uint) *uint       { return &v }

// Fixed validity windows — deterministic across runs.
var (
	winStart   = time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	winEnd     = winStart.AddDate(1, 0, 0)
	winNarrow0 = winStart.AddDate(0, 1, 0)
	winNarrow1 = winEnd.AddDate(0, -1, 0)
	winLeaf0   = winStart.AddDate(0, 3, 0)
	winLeaf1   = winEnd.AddDate(0, -3, 0)
)

// chainSpec describes one link's delegated bounds. Every field is
// signed into the link payload.
type chainSpec struct {
	caps      []string
	resources []string
	orgs      []string
	geos      []string
	channels  []string
	window    *TimeWindow
	quantity  *uint64
	monetary  *Monetary
	depth     *uint
	version   uint64
}

// link builds an unsigned DelegationLink bound to pub.
func (s chainSpec) link(pub crypto.PublicKey, id string) DelegationLink {
	return DelegationLink{
		KeyID:             id,
		PublicKey:         pub,
		Capabilities:      Capabilities(s.caps),
		ResourceScope:     s.resources,
		OrganizationScope: s.orgs,
		GeographicScope:   s.geos,
		TemporalScope:     s.window,
		ChannelScope:      s.channels,
		QuantityLimit:     s.quantity,
		MonetaryLimit:     s.monetary,
		DelegationDepth:   s.depth,
		Status:            StatusActive,
		KeyVersion:        s.version,
	}
}

// baseSpecs returns a valid three-level chain specification that
// strictly narrows at every level: root-issued link → intermediate
// → leaf.
func baseSpecs() []chainSpec {
	return []chainSpec{
		{
			caps:      []string{"product.attest", "inventory.attest", "delegate"},
			resources: []string{"res-a", "res-b", "res-c"},
			orgs:      []string{"org-1", "org-2"},
			geos:      []string{"US", "EU"},
			channels:  []string{"online", "retail"},
			window:    &TimeWindow{NotBefore: winStart, NotAfter: winEnd},
			quantity:  u64(1000),
			monetary:  &Monetary{Amount: 10000, Currency: "USD"},
			depth:     u(5),
			version:   1,
		},
		{
			caps:      []string{"product.attest", "delegate"},
			resources: []string{"res-a", "res-b"},
			orgs:      []string{"org-1"},
			geos:      []string{"US"},
			channels:  []string{"online"},
			window:    &TimeWindow{NotBefore: winNarrow0, NotAfter: winNarrow1},
			quantity:  u64(500),
			monetary:  &Monetary{Amount: 5000, Currency: "USD"},
			depth:     u(2),
			version:   2,
		},
		{
			caps:      []string{"product.attest"},
			resources: []string{"res-a"},
			orgs:      []string{"org-1"},
			geos:      []string{"US"},
			channels:  []string{"online"},
			window:    &TimeWindow{NotBefore: winLeaf0, NotAfter: winLeaf1},
			quantity:  u64(100),
			monetary:  &Monetary{Amount: 1000, Currency: "USD"},
			depth:     u(1),
			version:   3,
		},
	}
}

// buildSignedChain signs a chain of links for specs under alg. Link
// i is signed by pool key i (key 0 is the root anchor); each link
// delegates to pool key i+1.
func buildSignedChain(t *testing.T, alg signature.Algorithm, specs []chainSpec) (DelegationChain, crypto.PublicKey) {
	t.Helper()
	pool := keyPool[alg]
	if len(specs)+1 > len(pool) {
		t.Fatalf("key pool too small: need %d keys, have %d", len(specs)+1, len(pool))
	}
	links := make([]DelegationLink, len(specs))
	for i, spec := range specs {
		links[i] = spec.link(pool[i+1].pub, fmt.Sprintf("key-%d", i+1))
		if i > 0 {
			h, err := CanonicalHash(&links[i-1])
			if err != nil {
				t.Fatalf("CanonicalHash link %d: %v", i-1, err)
			}
			links[i].ParentAuthorityRef = h
		}
		if err := SignLink(&links[i], pool[i].priv); err != nil {
			t.Fatalf("SignLink link %d: %v", i, err)
		}
	}
	chain, err := BuildChain(links...)
	if err != nil {
		t.Fatalf("BuildChain: %v", err)
	}
	return chain, pool[0].pub
}

// assertScopeEqual compares two scopes field by field.
func assertScopeEqual(t *testing.T, got, want Scope) {
	t.Helper()
	if !slices.Equal(got.Resources, want.Resources) {
		t.Errorf("scope.Resources = %v, want %v", got.Resources, want.Resources)
	}
	if !slices.Equal(got.Actions, want.Actions) {
		t.Errorf("scope.Actions = %v, want %v", got.Actions, want.Actions)
	}
	if !slices.Equal(got.Organizations, want.Organizations) {
		t.Errorf("scope.Organizations = %v, want %v", got.Organizations, want.Organizations)
	}
	if !slices.Equal(got.Geographies, want.Geographies) {
		t.Errorf("scope.Geographies = %v, want %v", got.Geographies, want.Geographies)
	}
	if !slices.Equal(got.Channels, want.Channels) {
		t.Errorf("scope.Channels = %v, want %v", got.Channels, want.Channels)
	}
	if (got.TimeWindow == nil) != (want.TimeWindow == nil) {
		t.Fatalf("scope.TimeWindow = %v, want %v", got.TimeWindow, want.TimeWindow)
	}
	if got.TimeWindow != nil && *got.TimeWindow != *want.TimeWindow {
		t.Errorf("scope.TimeWindow = %v, want %v", *got.TimeWindow, *want.TimeWindow)
	}
	if (got.QuantityLimit == nil) != (want.QuantityLimit == nil) ||
		(got.QuantityLimit != nil && *got.QuantityLimit != *want.QuantityLimit) {
		t.Errorf("scope.QuantityLimit = %v, want %v", got.QuantityLimit, want.QuantityLimit)
	}
	if (got.MonetaryLimit == nil) != (want.MonetaryLimit == nil) ||
		(got.MonetaryLimit != nil && *got.MonetaryLimit != *want.MonetaryLimit) {
		t.Errorf("scope.MonetaryLimit = %v, want %v", got.MonetaryLimit, want.MonetaryLimit)
	}
	if (got.DelegationDepth == nil) != (want.DelegationDepth == nil) ||
		(got.DelegationDepth != nil && *got.DelegationDepth != *want.DelegationDepth) {
		t.Errorf("scope.DelegationDepth = %v, want %v", got.DelegationDepth, want.DelegationDepth)
	}
}
