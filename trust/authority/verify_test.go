package authority

import (
	"bytes"
	stded25519 "crypto/ed25519"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"os"
	"testing"

	"github.com/bperin/trust/crypto/ed25519"
	"github.com/bperin/trust/signature"
)

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
	for _, f := range []string{"doc.go", "authority.go", "verify.go", "scope.go"} {
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
