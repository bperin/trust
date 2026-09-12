package proof

import (
	"crypto"
	"crypto/elliptic"
	"crypto/subtle"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/bperin/trust/attestation"
	"github.com/bperin/trust/authority"
	"github.com/bperin/trust/credential"
	"github.com/bperin/trust/crypto/ecdsa"
	"github.com/bperin/trust/crypto/ed25519"
	"github.com/bperin/trust/crypto/rsa"
	"github.com/bperin/trust/crypto/secp256k1"
	"github.com/bperin/trust/evidence"
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

// keyPool holds five pre-generated keypairs per algorithm (root,
// intermediate, delegator, leaf, spare) so RSA key generation cost is
// paid once in TestMain rather than per test. Keys are shared
// read-only across tests; every chain gets its own link values.
var keyPool map[signature.Algorithm][]keypair

func TestMain(m *testing.M) {
	keyPool = make(map[signature.Algorithm][]keypair, len(algorithmCases))
	for _, tc := range algorithmCases {
		for i := 0; i < 5; i++ {
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
	window    *authority.TimeWindow
	quantity  *uint64
	monetary  *authority.Monetary
	depth     *uint
	version   uint64
}

// link builds an unsigned DelegationLink bound to pub.
func (s chainSpec) link(pub crypto.PublicKey, id string) authority.DelegationLink {
	return authority.DelegationLink{
		KeyID:             id,
		PublicKey:         pub,
		Capabilities:      authority.Capabilities(s.caps),
		ResourceScope:     s.resources,
		OrganizationScope: s.orgs,
		GeographicScope:   s.geos,
		TemporalScope:     s.window,
		ChannelScope:      s.channels,
		QuantityLimit:     s.quantity,
		MonetaryLimit:     s.monetary,
		DelegationDepth:   s.depth,
		Status:            authority.StatusActive,
		KeyVersion:        s.version,
	}
}

// baseSpecs returns a valid three-level chain specification that
// strictly narrows at every level: root-issued link -> intermediate
// -> leaf. The intersected scope has Actions = ["product.attest"].
func baseSpecs() []chainSpec {
	return []chainSpec{
		{
			caps:      []string{"product.attest", "inventory.attest", "delegate"},
			resources: []string{"res-a", "res-b", "res-c"},
			orgs:      []string{"org-1", "org-2"},
			geos:      []string{"US", "EU"},
			channels:  []string{"online", "retail"},
			window:    &authority.TimeWindow{NotBefore: winStart, NotAfter: winEnd},
			quantity:  u64(1000),
			monetary:  &authority.Monetary{Amount: 10000, Currency: "USD"},
			depth:     u(5),
			version:   1,
		},
		{
			caps:      []string{"product.attest", "delegate"},
			resources: []string{"res-a", "res-b"},
			orgs:      []string{"org-1"},
			geos:      []string{"US"},
			channels:  []string{"online"},
			window:    &authority.TimeWindow{NotBefore: winNarrow0, NotAfter: winNarrow1},
			quantity:  u64(500),
			monetary:  &authority.Monetary{Amount: 5000, Currency: "USD"},
			depth:     u(2),
			version:   2,
		},
		{
			caps:      []string{"product.attest"},
			resources: []string{"res-a"},
			orgs:      []string{"org-1"},
			geos:      []string{"US"},
			channels:  []string{"online"},
			window:    &authority.TimeWindow{NotBefore: winLeaf0, NotAfter: winLeaf1},
			quantity:  u64(100),
			monetary:  &authority.Monetary{Amount: 1000, Currency: "USD"},
			depth:     u(1),
			version:   3,
		},
	}
}

// buildSignedChain signs a chain of links for specs under alg. Link
// i is signed by pool key i (key 0 is the root anchor); each link
// delegates to pool key i+1. Returns the chain and the root public
// key.
func buildSignedChain(t *testing.T, alg signature.Algorithm, specs []chainSpec) (authority.DelegationChain, crypto.PublicKey) {
	t.Helper()
	pool := keyPool[alg]
	if len(specs)+1 > len(pool) {
		t.Fatalf("key pool too small: need %d keys, have %d", len(specs)+1, len(pool))
	}
	links := make([]authority.DelegationLink, len(specs))
	for i, spec := range specs {
		links[i] = spec.link(pool[i+1].pub, fmt.Sprintf("key-%d", i+1))
		if i > 0 {
			h, err := authority.CanonicalHash(&links[i-1])
			if err != nil {
				t.Fatalf("CanonicalHash link %d: %v", i-1, err)
			}
			links[i].ParentAuthorityRef = h
		}
		if err := authority.SignLink(&links[i], pool[i].priv); err != nil {
			t.Fatalf("SignLink link %d: %v", i, err)
		}
	}
	chain, err := authority.BuildChain(links...)
	if err != nil {
		t.Fatalf("BuildChain: %v", err)
	}
	return chain, pool[0].pub
}

// leafPrivateKey returns the leaf signing key's private key for a
// chain built from specs under alg. The leaf is pool key len(specs).
func leafPrivateKey(t *testing.T, alg signature.Algorithm, specs []chainSpec) crypto.PrivateKey {
	t.Helper()
	pool := keyPool[alg]
	idx := len(specs)
	if idx >= len(pool) {
		t.Fatalf("key pool too small: need key %d, have %d", idx, len(pool))
	}
	return pool[idx].priv
}

// wrongRootPub returns a public key of the same algorithm that is
// not the root key, for the wrong-root-key negative test.
func wrongRootPub(t *testing.T, alg signature.Algorithm) crypto.PublicKey {
	t.Helper()
	pool := keyPool[alg]
	if len(pool) < 5 {
		t.Fatalf("key pool too small: need 5 keys, have %d", len(pool))
	}
	return pool[4].pub
}

// buildClaim returns a VersionedClaim whose Schema carries the
// capability the attestation authorizes. The capability must be
// covered by the intersected scope's Actions for VerifyProof to
// pass.
func buildClaim(capability string) *credential.VersionedClaim {
	return &credential.VersionedClaim{
		Version:   1,
		Schema:    capability,
		Subject:   "did:example:subject",
		Resource:  "res-a",
		Issuer:    "did:example:claimer",
		IssuedAt:  winStart,
		NotBefore: winStart,
		NotAfter:  winEnd,
		Payload:   map[string]interface{}{"product": "widget", "qty": float64(42)},
		Evidence: []evidence.EvidenceRef{
			{
				Type:        "pdf",
				URI:         "ipfs://QmEvidenceHash",
				ContentHash: evidence.HashContent([]byte("evidence-bytes")),
			},
		},
	}
}

// buildAttestation returns a valid signed Attestation bound to the
// leaf link of chain, signed with leafPriv. The AuthorityRef is the
// canonical hash of the leaf link; the DelegationChainHash is the
// same (carried for context, not verified by VerifyAttestation).
func buildAttestation(t *testing.T, chain authority.DelegationChain, leafPriv crypto.PrivateKey, capability string) attestation.Attestation {
	t.Helper()
	claim := buildClaim(capability)

	leafLink := chain[len(chain)-1]
	authRef, err := authority.CanonicalHash(&leafLink)
	if err != nil {
		t.Fatalf("CanonicalHash leaf link: %v", err)
	}

	att := attestation.Attestation{
		Claim:               claim,
		Issuer:              "did:example:attester",
		SigningKeyID:        "leaf-key-1",
		SigningKeyVersion:   leafLink.KeyVersion,
		AuthorityRef:        authRef,
		DelegationChainHash: authRef,
		Evidence:            claim.Evidence,
		IssuedAt:            winStart,
		NotBefore:           winStart,
		NotAfter:            winEnd,
		Status:              "active",
	}
	if err := attestation.SignAttestation(&att, leafPriv); err != nil {
		t.Fatalf("SignAttestation: %v", err)
	}
	return att
}

// buildProof assembles a full proof: builds a chain, signs an
// attestation with the leaf key, and calls BuildProof. Returns the
// proof and the root public key.
func buildProof(t *testing.T, alg signature.Algorithm, specs []chainSpec, capability string) (Proof, crypto.PublicKey) {
	t.Helper()
	chain, rootPub := buildSignedChain(t, alg, specs)
	leafPriv := leafPrivateKey(t, alg, specs)
	att := buildAttestation(t, chain, leafPriv, capability)
	p, err := BuildProof(att, chain)
	if err != nil {
		t.Fatalf("BuildProof: %v", err)
	}
	return p, rootPub
}

// wantScope is the expected intersected scope for baseSpecs.
func wantScope() authority.Scope {
	return authority.Scope{
		Resources:       []string{"res-a"},
		Actions:         []string{"product.attest"},
		Organizations:   []string{"org-1"},
		Geographies:     []string{"US"},
		Channels:        []string{"online"},
		TimeWindow:      &authority.TimeWindow{NotBefore: winLeaf0, NotAfter: winLeaf1},
		QuantityLimit:   u64(100),
		MonetaryLimit:   &authority.Monetary{Amount: 1000, Currency: "USD"},
		DelegationDepth: u(1),
	}
}

// assertScopeEqual compares two scopes field by field.
func assertScopeEqual(t *testing.T, got, want authority.Scope) {
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

// TestProofRoundTrip builds a 3-level delegation chain, signs an
// attestation with the leaf key, builds a proof, and verifies it
// with only the root public key — succeeds and returns the
// intersected scope — under every registered algorithm.
func TestProofRoundTrip(t *testing.T) {
	t.Parallel()
	for _, tc := range algorithmCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			p, rootPub := buildProof(t, tc.alg, baseSpecs(), "product.attest")

			scope, err := VerifyProof(p, rootPub)
			if err != nil {
				t.Fatalf("VerifyProof: got error %v, want nil", err)
			}
			assertScopeEqual(t, scope, wantScope())

			// The proof's SigningKeyVersion must match the leaf
			// link's KeyVersion (3 in baseSpecs).
			if p.SigningKeyVersion != 3 {
				t.Errorf("SigningKeyVersion = %d, want 3", p.SigningKeyVersion)
			}

			// The cached IntersectedScope is advisory — VerifyProof
			// re-computes it. Confirm the cached value is the zero
			// scope (BuildProof does not compute it) and the
			// returned scope is the correct intersection.
			if len(p.IntersectedScope.Actions) != 0 {
				t.Errorf("cached IntersectedScope.Actions = %v, want empty (advisory)", p.IntersectedScope.Actions)
			}
		})
	}
}

// TestProofScopeViolation rejects a proof whose delegation chain has
// a child link exceeding its parent's scope — VerifyProof fails with
// ErrScopeViolation.
func TestProofScopeViolation(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name   string
		mutate func(specs []chainSpec)
	}{
		{"resource outside parent", func(s []chainSpec) {
			s[1].resources = []string{"res-a", "res-x"}
		}},
		{"organization outside parent", func(s []chainSpec) {
			s[1].orgs = []string{"org-9"}
		}},
		{"geography outside parent", func(s []chainSpec) {
			s[1].geos = []string{"US", "APAC"}
		}},
		{"channel outside parent", func(s []chainSpec) {
			s[1].channels = []string{"online", "phone"}
		}},
		{"quantity exceeds parent", func(s []chainSpec) {
			s[1].quantity = u64(2000)
		}},
		{"monetary amount exceeds parent", func(s []chainSpec) {
			s[1].monetary = &authority.Monetary{Amount: 20000, Currency: "USD"}
		}},
	}
	for _, vc := range cases {
		for _, tc := range algorithmCases {
			t.Run(vc.name+"/"+tc.name, func(t *testing.T) {
				t.Parallel()
				specs := baseSpecs()
				vc.mutate(specs)
				p, rootPub := buildProof(t, tc.alg, specs, "product.attest")
				_, err := VerifyProof(p, rootPub)
				if !errors.Is(err, ErrScopeViolation) {
					t.Fatalf("VerifyProof: got error %v, want errors.Is(_, ErrScopeViolation)", err)
				}
			})
		}
	}
}

// TestProofBrokenDelegationChain rejects a proof whose delegation
// chain has a tampered parent signature on a non-root link —
// VerifyProof fails with ErrBrokenDelegationChain.
func TestProofBrokenDelegationChain(t *testing.T) {
	t.Parallel()
	for _, tc := range algorithmCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			p, rootPub := buildProof(t, tc.alg, baseSpecs(), "product.attest")

			// Tamper link 1's parent signature (not the root link).
			// The root key pre-check on link 0 passes; VerifyChain
			// then fails at link 1 with ErrBrokenSignature, which
			// VerifyProof wraps as ErrBrokenDelegationChain.
			sig := make([]byte, len(p.DelegationChain[1].ParentSignature))
			copy(sig, p.DelegationChain[1].ParentSignature)
			sig[len(sig)-1] ^= 0x01
			p.DelegationChain[1].ParentSignature = sig

			_, err := VerifyProof(p, rootPub)
			if !errors.Is(err, ErrBrokenDelegationChain) {
				t.Fatalf("VerifyProof: got error %v, want errors.Is(_, ErrBrokenDelegationChain)", err)
			}
		})
	}
}

// TestProofKeyVersionNonMonotonic rejects a proof whose delegation
// chain has a decreasing key version — VerifyProof fails with
// ErrKeyVersionNonMonotonic.
func TestProofKeyVersionNonMonotonic(t *testing.T) {
	t.Parallel()
	for _, tc := range algorithmCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			specs := baseSpecs()
			specs[2].version = 1 // below link 1's version 2
			p, rootPub := buildProof(t, tc.alg, specs, "product.attest")
			_, err := VerifyProof(p, rootPub)
			if !errors.Is(err, ErrKeyVersionNonMonotonic) {
				t.Fatalf("VerifyProof: got error %v, want errors.Is(_, ErrKeyVersionNonMonotonic)", err)
			}
		})
	}
}

// TestProofTamperedAttestation rejects a proof whose attestation has
// been modified after signing — VerifyProof fails with
// ErrTamperedAttestation.
func TestProofTamperedAttestation(t *testing.T) {
	t.Parallel()
	for _, tc := range algorithmCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			p, rootPub := buildProof(t, tc.alg, baseSpecs(), "product.attest")

			// Tamper with the issuer after signing. This changes
			// the canonical hash, so the stored signature no longer
			// matches.
			p.Attestation.Issuer = "did:example:attacker"

			_, err := VerifyProof(p, rootPub)
			if !errors.Is(err, ErrTamperedAttestation) {
				t.Fatalf("VerifyProof: got error %v, want errors.Is(_, ErrTamperedAttestation)", err)
			}
		})
	}
}

// TestProofWrongRootKey rejects a proof verified with the wrong root
// public key — VerifyProof fails with ErrWrongRootKey.
func TestProofWrongRootKey(t *testing.T) {
	t.Parallel()
	for _, tc := range algorithmCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			p, _ := buildProof(t, tc.alg, baseSpecs(), "product.attest")
			wrongPub := wrongRootPub(t, tc.alg)

			_, err := VerifyProof(p, wrongPub)
			if !errors.Is(err, ErrWrongRootKey) {
				t.Fatalf("VerifyProof: got error %v, want errors.Is(_, ErrWrongRootKey)", err)
			}
		})
	}
}

// TestProofNilRootKey rejects a proof verified with a nil root public
// key — VerifyProof fails with ErrWrongRootKey.
func TestProofNilRootKey(t *testing.T) {
	t.Parallel()
	for _, tc := range algorithmCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			p, _ := buildProof(t, tc.alg, baseSpecs(), "product.attest")
			_, err := VerifyProof(p, nil)
			if !errors.Is(err, ErrWrongRootKey) {
				t.Fatalf("VerifyProof nil root: got error %v, want errors.Is(_, ErrWrongRootKey)", err)
			}
		})
	}
}

// TestProofCapabilityNotCovered rejects a proof whose attestation
// claim capability is not in the intersected scope's Actions —
// VerifyProof fails with ErrCapabilityNotCovered.
func TestProofCapabilityNotCovered(t *testing.T) {
	t.Parallel()
	for _, tc := range algorithmCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			// The intersected scope has Actions = ["product.attest"].
			// The claim declares "inventory.attest", which is not
			// covered.
			p, rootPub := buildProof(t, tc.alg, baseSpecs(), "inventory.attest")
			_, err := VerifyProof(p, rootPub)
			if !errors.Is(err, ErrCapabilityNotCovered) {
				t.Fatalf("VerifyProof: got error %v, want errors.Is(_, ErrCapabilityNotCovered)", err)
			}
		})
	}
}

// TestProofEmptyChain rejects a proof built from an empty chain —
// BuildProof fails with ErrBrokenDelegationChain.
func TestProofEmptyChain(t *testing.T) {
	t.Parallel()
	_, err := BuildProof(attestation.Attestation{}, authority.DelegationChain{})
	if !errors.Is(err, ErrBrokenDelegationChain) {
		t.Fatalf("BuildProof empty chain: got error %v, want errors.Is(_, ErrBrokenDelegationChain)", err)
	}
}

// TestProofVerifyEmptyChain rejects VerifyProof on an empty chain —
// fails with ErrBrokenDelegationChain.
func TestProofVerifyEmptyChain(t *testing.T) {
	t.Parallel()
	// Build a valid attestation using a real chain, then construct
	// a proof with an empty chain manually (BuildProof rejects
	// empty chains, so we bypass it).
	chain, rootPub := buildSignedChain(t, signature.AlgorithmEdDSA, baseSpecs())
	leafPriv := leafPrivateKey(t, signature.AlgorithmEdDSA, baseSpecs())
	att := buildAttestation(t, chain, leafPriv, "product.attest")
	empty := Proof{Attestation: att}
	_, err := VerifyProof(empty, rootPub)
	if !errors.Is(err, ErrBrokenDelegationChain) {
		t.Fatalf("VerifyProof empty chain: got error %v, want errors.Is(_, ErrBrokenDelegationChain)", err)
	}
}

// TestProofSigningKeyVersionMismatch rejects a proof whose
// SigningKeyVersion does not match the leaf link's KeyVersion.
func TestProofSigningKeyVersionMismatch(t *testing.T) {
	t.Parallel()
	for _, tc := range algorithmCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			p, rootPub := buildProof(t, tc.alg, baseSpecs(), "product.attest")
			p.SigningKeyVersion = 999 // does not match leaf version 3
			_, err := VerifyProof(p, rootPub)
			if err == nil {
				t.Fatalf("VerifyProof: got nil error, want signing key version mismatch error")
			}
			if errors.Is(err, ErrScopeViolation) || errors.Is(err, ErrBrokenDelegationChain) ||
				errors.Is(err, ErrTamperedAttestation) || errors.Is(err, ErrWrongRootKey) ||
				errors.Is(err, ErrCapabilityNotCovered) || errors.Is(err, ErrKeyVersionNonMonotonic) {
				t.Fatalf("VerifyProof: got sentinel error %v, want non-sentinel version mismatch error", err)
			}
		})
	}
}

// TestProofCachedScopeNotTrusted confirms the cached IntersectedScope
// is advisory — setting it to a wrong value does not affect
// verification. VerifyProof re-intersects the chain and returns the
// correct scope.
func TestProofCachedScopeNotTrusted(t *testing.T) {
	t.Parallel()
	for _, tc := range algorithmCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			p, rootPub := buildProof(t, tc.alg, baseSpecs(), "product.attest")

			// Poison the cached scope with a capability the claim
			// does not hold. VerifyProof must ignore it.
			p.IntersectedScope = authority.Scope{
				Actions: []string{"inventory.attest"},
			}

			scope, err := VerifyProof(p, rootPub)
			if err != nil {
				t.Fatalf("VerifyProof: got error %v, want nil", err)
			}
			if !slices.Equal(scope.Actions, []string{"product.attest"}) {
				t.Errorf("scope.Actions = %v, want [product.attest] (re-intersected, not cached)", scope.Actions)
			}
		})
	}
}

// TestProofRootOrgHashIsContext confirms RootOrganizationHash is
// carried as context and does not gate verification.
func TestProofRootOrgHashIsContext(t *testing.T) {
	t.Parallel()
	for _, tc := range algorithmCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			p, rootPub := buildProof(t, tc.alg, baseSpecs(), "product.attest")
			p.RootOrganizationHash = [32]byte{0xde, 0xad, 0xbe, 0xef}
			if _, err := VerifyProof(p, rootPub); err != nil {
				t.Fatalf("VerifyProof with non-zero RootOrganizationHash: got error %v, want nil", err)
			}
		})
	}
}

// TestProofPurity verifies the proof package source files contain no
// I/O, network, or database imports or calls. VerifyProof is a pure
// function — no I/O, no network, no global state. Forbidden patterns
// are constructed from concatenation so the test file itself does not
// contain the literal forbidden strings.
func TestProofPurity(t *testing.T) {
	t.Parallel()
	// Check non-test source files only.
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatalf("glob: %v", err)
	}
	// Build forbidden patterns from parts so the literal strings
	// do not appear in this test file (which is itself in the
	// package directory).
	forbidden := []string{
		"ne" + "t" + "/",
		"ht" + "tp",
		"os" + ".O" + "pen",
		"sq" + "l",
	}
	for _, file := range files {
		if strings.HasSuffix(file, "_test.go") {
			continue
		}
		data, err := os.ReadFile(file)
		if err != nil {
			t.Fatalf("read %s: %v", file, err)
		}
		src := string(data)
		for _, pat := range forbidden {
			if strings.Contains(src, pat) {
				t.Errorf("file %s contains forbidden pattern %q — VerifyProof must be pure (no I/O, no network, no database)", file, pat)
			}
		}
	}
}

// TestNoAuthChainImports verifies the dependency rule: the proof
// package must not import the auth or chain modules. trust must never
// depend on auth or chain.
func TestNoAuthChainImports(t *testing.T) {
	t.Parallel()
	// Check non-test source files only. The test file itself
	// contains the import-path strings as part of its assertions.
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatalf("glob: %v", err)
	}
	for _, file := range files {
		if strings.HasSuffix(file, "_test.go") {
			continue
		}
		data, err := os.ReadFile(file)
		if err != nil {
			t.Fatalf("read %s: %v", file, err)
		}
		if strings.Contains(string(data), "github.com/bperin/auth") {
			t.Errorf("file %s imports github.com/bperin/auth (dependency rule violation)", file)
		}
		if strings.Contains(string(data), "github.com/bperin/chain") {
			t.Errorf("file %s imports github.com/bperin/chain (dependency rule violation)", file)
		}
	}
}

// hashEqual reports whether two digests are equal in constant time.
func hashEqual(a, b [32]byte) bool {
	return subtle.ConstantTimeCompare(a[:], b[:]) == 1
}

// TestProofAttestationBinding confirms the attestation in the proof
// is signed by the leaf key derived from the chain, and the
// AuthorityRef matches the leaf link's canonical hash.
func TestProofAttestationBinding(t *testing.T) {
	t.Parallel()
	for _, tc := range algorithmCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			chain, _ := buildSignedChain(t, tc.alg, baseSpecs())
			leafPriv := leafPrivateKey(t, tc.alg, baseSpecs())
			att := buildAttestation(t, chain, leafPriv, "product.attest")
			p, err := BuildProof(att, chain)
			if err != nil {
				t.Fatalf("BuildProof: %v", err)
			}

			// The attestation's AuthorityRef must be the canonical
			// hash of the leaf link.
			leafLink := chain[len(chain)-1]
			wantRef, err := authority.CanonicalHash(&leafLink)
			if err != nil {
				t.Fatalf("CanonicalHash: %v", err)
			}
			if !hashEqual(p.Attestation.AuthorityRef, wantRef) {
				t.Errorf("AuthorityRef = %x, want %x (leaf link canonical hash)",
					p.Attestation.AuthorityRef, wantRef)
			}

			// The attestation's Algorithm must match the chain's
			// algorithm.
			if p.Attestation.Algorithm != tc.alg {
				t.Errorf("Algorithm = %v, want %v", p.Attestation.Algorithm, tc.alg)
			}
		})
	}
}
