package authority

import (
	"bytes"
	"crypto"
	stded25519 "crypto/ed25519"
	"crypto/elliptic"
	"crypto/subtle"
	"encoding/hex"
	"errors"
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

// TestChainRoundTrip builds, signs, and verifies a three-level
// delegation chain under every registered algorithm, and asserts the
// returned scope is the fully intersected leaf bound.
func TestChainRoundTrip(t *testing.T) {
	want := Scope{
		Resources:       []string{"res-a"},
		Actions:         []string{"product.attest"},
		Organizations:   []string{"org-1"},
		Geographies:     []string{"US"},
		Channels:        []string{"online"},
		TimeWindow:      &TimeWindow{NotBefore: winLeaf0, NotAfter: winLeaf1},
		QuantityLimit:   u64(100),
		MonetaryLimit:   &Monetary{Amount: 1000, Currency: "USD"},
		DelegationDepth: u(1), // min(5-2, 2-1, 1-0)
	}
	for _, tc := range algorithmCases {
		t.Run(tc.name, func(t *testing.T) {
			chain, rootPub := buildSignedChain(t, tc.alg, baseSpecs())
			if len(chain) != 3 {
				t.Fatalf("chain length = %d, want 3", len(chain))
			}
			for i, l := range chain {
				if len(l.ParentSignature) == 0 {
					t.Fatalf("link %d has no parent signature", i)
				}
				if l.Algorithm != tc.alg {
					t.Fatalf("link %d Algorithm = %v, want %v", i, l.Algorithm, tc.alg)
				}
			}
			scope, err := VerifyChain(chain, rootPub)
			if err != nil {
				t.Fatalf("VerifyChain: %v", err)
			}
			assertScopeEqual(t, scope, want)
		})
	}
}

// TestScopeIntersection exercises each scope dimension: a child
// within the parent's bound verifies; a child exceeding it fails
// with ErrScopeViolation.
func TestScopeIntersection(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(specs []chainSpec)
		want   error
	}{
		{"resource outside parent", func(s []chainSpec) {
			s[1].resources = []string{"res-a", "res-x"}
		}, ErrScopeViolation},
		{"organization outside parent", func(s []chainSpec) {
			s[1].orgs = []string{"org-9"}
		}, ErrScopeViolation},
		{"geography outside parent", func(s []chainSpec) {
			s[1].geos = []string{"US", "APAC"}
		}, ErrScopeViolation},
		{"channel outside parent", func(s []chainSpec) {
			s[1].channels = []string{"online", "phone"}
		}, ErrScopeViolation},
		{"quantity exceeds parent", func(s []chainSpec) {
			s[1].quantity = u64(2000)
		}, ErrScopeViolation},
		{"monetary amount exceeds parent", func(s []chainSpec) {
			s[1].monetary = &Monetary{Amount: 20000, Currency: "USD"}
		}, ErrScopeViolation},
		{"monetary currency outside parent", func(s []chainSpec) {
			s[1].monetary = &Monetary{Amount: 100, Currency: "EUR"}
		}, ErrScopeViolation},
		{"window precedes parent", func(s []chainSpec) {
			s[1].window = &TimeWindow{NotBefore: winStart.AddDate(0, 0, -1), NotAfter: winNarrow1}
		}, ErrScopeViolation},
		{"window exceeds parent", func(s []chainSpec) {
			s[2].window = &TimeWindow{NotBefore: winLeaf0, NotAfter: winEnd.AddDate(0, 0, 1)}
		}, ErrScopeViolation},
	}
	for _, vc := range cases {
		for _, tc := range algorithmCases {
			t.Run(vc.name+"/"+tc.name, func(t *testing.T) {
				specs := baseSpecs()
				vc.mutate(specs)
				chain, rootPub := buildSignedChain(t, tc.alg, specs)
				_, err := VerifyChain(chain, rootPub)
				if !errors.Is(err, vc.want) {
					t.Fatalf("VerifyChain: err = %v, want %v", err, vc.want)
				}
			})
		}
	}
}

// TestScopeWithinParent confirms a child strictly inside every
// parent dimension verifies and inherits bounds it does not narrow.
func TestScopeWithinParent(t *testing.T) {
	for _, tc := range algorithmCases {
		t.Run(tc.name, func(t *testing.T) {
			specs := baseSpecs()
			// Leaf narrows nothing: it inherits the effective scope.
			specs[2] = chainSpec{version: 3}
			chain, rootPub := buildSignedChain(t, tc.alg, specs)
			scope, err := VerifyChain(chain, rootPub)
			if err != nil {
				t.Fatalf("VerifyChain: %v", err)
			}
			assertScopeEqual(t, scope, Scope{
				Resources:       []string{"res-a", "res-b"},
				Actions:         []string{"product.attest", "delegate"},
				Organizations:   []string{"org-1"},
				Geographies:     []string{"US"},
				Channels:        []string{"online"},
				TimeWindow:      &TimeWindow{NotBefore: winNarrow0, NotAfter: winNarrow1},
				QuantityLimit:   u64(500),
				MonetaryLimit:   &Monetary{Amount: 5000, Currency: "USD"},
				DelegationDepth: u(1), // min(5-2, 2-1)
			})
		})
	}
}

// TestCapabilityNotCovered rejects a leaf that declares a capability
// outside its parent's effective set.
func TestCapabilityNotCovered(t *testing.T) {
	for _, tc := range algorithmCases {
		t.Run(tc.name, func(t *testing.T) {
			specs := baseSpecs()
			specs[2].caps = []string{"product.attest", "admin"}
			chain, rootPub := buildSignedChain(t, tc.alg, specs)
			_, err := VerifyChain(chain, rootPub)
			if !errors.Is(err, ErrCapabilityNotCovered) {
				t.Fatalf("VerifyChain: err = %v, want ErrCapabilityNotCovered", err)
			}
		})
	}
}

// TestBrokenSignature covers three ways the signature layer fails:
// a tampered signature byte, a missing signature, and verification
// against the wrong root key.
func TestBrokenSignature(t *testing.T) {
	for _, tc := range algorithmCases {
		t.Run(tc.name+"/tampered", func(t *testing.T) {
			chain, rootPub := buildSignedChain(t, tc.alg, baseSpecs())
			sig := make([]byte, len(chain[1].ParentSignature))
			copy(sig, chain[1].ParentSignature)
			sig[len(sig)-1] ^= 0x01
			chain[1].ParentSignature = sig
			_, err := VerifyChain(chain, rootPub)
			if !errors.Is(err, ErrBrokenSignature) {
				t.Fatalf("VerifyChain: err = %v, want ErrBrokenSignature", err)
			}
		})
		t.Run(tc.name+"/missing", func(t *testing.T) {
			chain, rootPub := buildSignedChain(t, tc.alg, baseSpecs())
			chain[2].ParentSignature = nil
			_, err := VerifyChain(chain, rootPub)
			if !errors.Is(err, ErrBrokenSignature) {
				t.Fatalf("VerifyChain: err = %v, want ErrBrokenSignature", err)
			}
		})
		t.Run(tc.name+"/wrong root", func(t *testing.T) {
			chain, _ := buildSignedChain(t, tc.alg, baseSpecs())
			other, err := genPair(tc.alg)
			if err != nil {
				t.Fatalf("genPair: %v", err)
			}
			_, err = VerifyChain(chain, other.pub)
			if !errors.Is(err, ErrBrokenSignature) {
				t.Fatalf("VerifyChain: err = %v, want ErrBrokenSignature", err)
			}
		})
	}
}

// TestKeyVersionNonMonotonic rejects a chain whose key versions
// decrease — the leaf is re-signed so only the version check fails.
func TestKeyVersionNonMonotonic(t *testing.T) {
	for _, tc := range algorithmCases {
		t.Run(tc.name, func(t *testing.T) {
			specs := baseSpecs()
			specs[2].version = 1 // below link 1's version 2
			chain, rootPub := buildSignedChain(t, tc.alg, specs)
			_, err := VerifyChain(chain, rootPub)
			if !errors.Is(err, ErrKeyVersionNonMonotonic) {
				t.Fatalf("VerifyChain: err = %v, want ErrKeyVersionNonMonotonic", err)
			}
		})
	}
}

// TestStaleKeyVersion covers VerifyOptions.LatestVersions: a chain
// version below the latest known fails when the option is set and
// passes when it is absent.
func TestStaleKeyVersion(t *testing.T) {
	for _, tc := range algorithmCases {
		t.Run(tc.name+"/stale rejected", func(t *testing.T) {
			chain, rootPub := buildSignedChain(t, tc.alg, baseSpecs())
			_, err := VerifyChain(chain, rootPub, VerifyOptions{
				LatestVersions: map[string]uint64{"key-2": 5},
			})
			if !errors.Is(err, ErrStaleKeyVersion) {
				t.Fatalf("VerifyChain: err = %v, want ErrStaleKeyVersion", err)
			}
		})
		t.Run(tc.name+"/skipped without option", func(t *testing.T) {
			chain, rootPub := buildSignedChain(t, tc.alg, baseSpecs())
			if _, err := VerifyChain(chain, rootPub); err != nil {
				t.Fatalf("VerifyChain: %v", err)
			}
		})
		t.Run(tc.name+"/at latest passes", func(t *testing.T) {
			chain, rootPub := buildSignedChain(t, tc.alg, baseSpecs())
			_, err := VerifyChain(chain, rootPub, VerifyOptions{
				LatestVersions: map[string]uint64{"key-2": 2},
			})
			if err != nil {
				t.Fatalf("VerifyChain: %v", err)
			}
		})
	}
}

// TestDepthExceeded rejects a chain longer than an intermediate
// link's declared delegation depth allows.
func TestDepthExceeded(t *testing.T) {
	for _, tc := range algorithmCases {
		t.Run(tc.name, func(t *testing.T) {
			specs := baseSpecs()
			specs[0].depth = u(1) // two links follow
			chain, rootPub := buildSignedChain(t, tc.alg, specs)
			_, err := VerifyChain(chain, rootPub)
			if !errors.Is(err, ErrDepthExceeded) {
				t.Fatalf("VerifyChain: err = %v, want ErrDepthExceeded", err)
			}
		})
	}
}

// TestChainBroken covers ordering failures: a link whose signed
// ParentAuthorityRef does not match the preceding link's canonical
// hash, a non-zero ref on the root link, and BuildChain called with
// links out of order.
func TestChainBroken(t *testing.T) {
	gen := func(t *testing.T) keypair {
		kp, err := genPair(signature.AlgorithmEdDSA)
		if err != nil {
			t.Fatalf("genPair: %v", err)
		}
		return kp
	}
	root := gen(t)
	k1 := gen(t)
	k2 := gen(t)

	newLink := func(k keypair, id string) DelegationLink {
		return baseSpecs()[0].link(k.pub, id)
	}

	t.Run("mismatched ref signed anyway", func(t *testing.T) {
		l0 := newLink(k1, "key-1")
		if err := SignLink(&l0, root.priv); err != nil {
			t.Fatalf("SignLink: %v", err)
		}
		l1 := newLink(k2, "key-2")
		l1.ParentAuthorityRef = [32]byte{0xde, 0xad} // not CanonicalHash(l0)
		if err := SignLink(&l1, k1.priv); err != nil {
			t.Fatalf("SignLink: %v", err)
		}
		_, err := VerifyChain(DelegationChain{l0, l1}, root.pub)
		if !errors.Is(err, ErrChainBroken) {
			t.Fatalf("VerifyChain: err = %v, want ErrChainBroken", err)
		}
	})

	t.Run("non-zero ref on root link", func(t *testing.T) {
		l0 := newLink(k1, "key-1")
		l0.ParentAuthorityRef = [32]byte{0x01}
		if err := SignLink(&l0, root.priv); err != nil {
			t.Fatalf("SignLink: %v", err)
		}
		_, err := VerifyChain(DelegationChain{l0}, root.pub)
		if !errors.Is(err, ErrChainBroken) {
			t.Fatalf("VerifyChain: err = %v, want ErrChainBroken", err)
		}
	})

	t.Run("BuildChain out of order", func(t *testing.T) {
		l0 := newLink(k1, "key-1")
		if err := SignLink(&l0, root.priv); err != nil {
			t.Fatalf("SignLink: %v", err)
		}
		l1 := newLink(k2, "key-2")
		h, err := CanonicalHash(&l0)
		if err != nil {
			t.Fatalf("CanonicalHash: %v", err)
		}
		l1.ParentAuthorityRef = h
		if err := SignLink(&l1, k1.priv); err != nil {
			t.Fatalf("SignLink: %v", err)
		}
		if _, err := BuildChain(l1, l0); !errors.Is(err, ErrChainBroken) {
			t.Fatalf("BuildChain reversed: err = %v, want ErrChainBroken", err)
		}
	})

	t.Run("BuildChain unsigned link", func(t *testing.T) {
		l0 := newLink(k1, "key-1")
		if _, err := BuildChain(l0); !errors.Is(err, ErrBrokenSignature) {
			t.Fatalf("BuildChain unsigned: err = %v, want ErrBrokenSignature", err)
		}
	})
}

// TestVerifyChainStructural covers the empty chain, nil root key,
// and single-link boundary cases.
func TestVerifyChainStructural(t *testing.T) {
	kp, err := genPair(signature.AlgorithmEdDSA)
	if err != nil {
		t.Fatalf("genPair: %v", err)
	}

	t.Run("empty chain", func(t *testing.T) {
		if _, err := VerifyChain(nil, kp.pub); !errors.Is(err, ErrEmptyChain) {
			t.Fatalf("VerifyChain: err = %v, want ErrEmptyChain", err)
		}
	})
	t.Run("nil root key", func(t *testing.T) {
		chain, _ := buildSignedChain(t, signature.AlgorithmEdDSA, baseSpecs())
		if _, err := VerifyChain(chain, nil); !errors.Is(err, ErrMissingRootKey) {
			t.Fatalf("VerifyChain: err = %v, want ErrMissingRootKey", err)
		}
	})
	t.Run("single link", func(t *testing.T) {
		chain, rootPub := buildSignedChain(t, signature.AlgorithmEdDSA, baseSpecs()[:1])
		if len(chain) != 1 {
			t.Fatalf("chain length = %d, want 1", len(chain))
		}
		scope, err := VerifyChain(chain, rootPub)
		if err != nil {
			t.Fatalf("VerifyChain: %v", err)
		}
		if *scope.DelegationDepth != 5 {
			t.Fatalf("scope.DelegationDepth = %d, want 5", *scope.DelegationDepth)
		}
	})
	t.Run("missing link public key", func(t *testing.T) {
		l := baseSpecs()[0].link(kp.pub, "key-1")
		l.PublicKey = nil
		if _, err := VerifyChain(DelegationChain{l}, kp.pub); !errors.Is(err, ErrMissingPublicKey) {
			t.Fatalf("VerifyChain: err = %v, want ErrMissingPublicKey", err)
		}
	})
}

// TestSignLinkNegative covers the SignLink error paths.
func TestSignLinkNegative(t *testing.T) {
	kp, err := genPair(signature.AlgorithmEdDSA)
	if err != nil {
		t.Fatalf("genPair: %v", err)
	}
	t.Run("nil link", func(t *testing.T) {
		if err := SignLink(nil, kp.priv); !errors.Is(err, ErrNilLink) {
			t.Fatalf("SignLink: err = %v, want ErrNilLink", err)
		}
	})
	t.Run("missing public key", func(t *testing.T) {
		l := &DelegationLink{KeyID: "key-1"}
		if err := SignLink(l, kp.priv); !errors.Is(err, ErrMissingPublicKey) {
			t.Fatalf("SignLink: err = %v, want ErrMissingPublicKey", err)
		}
	})
	t.Run("nil signer", func(t *testing.T) {
		l := &DelegationLink{KeyID: "key-1", PublicKey: kp.pub}
		if err := SignLink(l, nil); !errors.Is(err, ErrMissingSigner) {
			t.Fatalf("SignLink: err = %v, want ErrMissingSigner", err)
		}
	})
}

// TestSignVerifyKnownVectorEd25519 anchors the delegation round trip
// to a known Ed25519 key from the standard: the seed derives the
// RFC's public key, a signature over the RFC's empty message
// reproduces the RFC's signature bytes, and a link signed with the
// same key verifies as a one-link chain.
//
// Vector: [RFC 8032] §7.1 Test 1 (empty message).
func TestSignVerifyKnownVectorEd25519(t *testing.T) {
	seed, err := hex.DecodeString("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
	if err != nil {
		t.Fatalf("decode seed: %v", err)
	}
	wantPub, err := hex.DecodeString("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
	if err != nil {
		t.Fatalf("decode public key: %v", err)
	}
	wantSig, err := hex.DecodeString("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155" +
		"5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b")
	if err != nil {
		t.Fatalf("decode signature: %v", err)
	}

	priv, err := ed25519.NewPrivateKey(stded25519.NewKeyFromSeed(seed))
	if err != nil {
		t.Fatalf("ed25519.NewPrivateKey: %v", err)
	}
	pub := priv.Public()
	pubBytes := pub.Bytes()
	if subtle.ConstantTimeCompare(pubBytes[:], wantPub) != 1 {
		t.Fatalf("derived public key = %x, want %x", pubBytes, wantPub)
	}
	if sig := priv.Sign(nil); subtle.ConstantTimeCompare(sig, wantSig) != 1 {
		t.Fatalf("signature over empty message = %x, want %x", sig, wantSig)
	}

	link := baseSpecs()[0].link(pub, "key-1")
	if err := SignLink(&link, priv); err != nil {
		t.Fatalf("SignLink: %v", err)
	}
	if _, err := VerifyChain(DelegationChain{link}, pub); err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}
}

// TestCanonicalHashDeterministic proves the canonical hash is stable
// for a fixed signed link and changes when any field changes.
func TestCanonicalHashDeterministic(t *testing.T) {
	kp, err := genPair(signature.AlgorithmEdDSA)
	if err != nil {
		t.Fatalf("genPair: %v", err)
	}
	link := baseSpecs()[0].link(kp.pub, "key-1")
	if err := SignLink(&link, kp.priv); err != nil {
		t.Fatalf("SignLink: %v", err)
	}

	h1, err := CanonicalHash(&link)
	if err != nil {
		t.Fatalf("CanonicalHash: %v", err)
	}
	h2, err := CanonicalHash(&link)
	if err != nil {
		t.Fatalf("CanonicalHash: %v", err)
	}
	if subtle.ConstantTimeCompare(h1[:], h2[:]) != 1 {
		t.Fatalf("CanonicalHash not deterministic: %x != %x", h1, h2)
	}

	link.KeyID = "key-9"
	h3, err := CanonicalHash(&link)
	if err != nil {
		t.Fatalf("CanonicalHash: %v", err)
	}
	if subtle.ConstantTimeCompare(h1[:], h3[:]) == 1 {
		t.Fatal("CanonicalHash did not change after KeyID change")
	}
}

// TestCanonicalHashRegressionVector pins the canonical form of a
// fixed link under the RFC 8032 Test 1 Ed25519 key to a hard-coded
// digest. This is a self-consistency regression vector — the
// canonical projection (JCS per [RFC 8785], JWK key encoding per
// [RFC 7517], SHA-256 per [FIPS 180-4]) must never drift.
func TestCanonicalHashRegressionVector(t *testing.T) {
	seed, err := hex.DecodeString("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
	if err != nil {
		t.Fatalf("decode seed: %v", err)
	}
	priv, err := ed25519.NewPrivateKey(stded25519.NewKeyFromSeed(seed))
	if err != nil {
		t.Fatalf("ed25519.NewPrivateKey: %v", err)
	}
	link := baseSpecs()[0].link(priv.Public(), "key-1")
	if err := SignLink(&link, priv); err != nil {
		t.Fatalf("SignLink: %v", err)
	}
	h, err := CanonicalHash(&link)
	if err != nil {
		t.Fatalf("CanonicalHash: %v", err)
	}
	// Regression vector computed from this implementation's
	// canonical wire form; the Ed25519 signature over the link hash
	// is deterministic per [RFC 8032] §5.1, so the digest is stable.
	want, err := hex.DecodeString("86bf61f8e3eaafad19ae365360961ac7bdbc05e9f6fff4cac6fae9c4ea78609d")
	if err != nil {
		t.Fatalf("decode vector: %v", err)
	}
	if subtle.ConstantTimeCompare(h[:], want) != 1 {
		t.Fatalf("CanonicalHash = %x, want %x", h, want)
	}
}

// TestNoAuthChainImports verifies the dependency rule: the authority
// package must not import the auth or chain modules.
func TestNoAuthChainImports(t *testing.T) {
	for _, f := range []string{"doc.go", "authority.go", "verify.go"} {
		src, err := os.ReadFile(f)
		if err != nil {
			t.Fatalf("cannot read %s: %v", f, err)
		}
		if bytes.Contains(src, []byte("bperin/auth")) {
			t.Errorf("%s imports auth module (dependency rule violation)", f)
		}
		if bytes.Contains(src, []byte("bperin/chain")) {
			t.Errorf("%s imports chain module (dependency rule violation)", f)
		}
	}
}
