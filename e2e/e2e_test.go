// Package e2e holds the end-to-end test harness for the trust library.
// TestE2E_TrustLifecycle is the canonical gate across every capability area.
package e2e

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"testing"
	"time"

	stded25519 "crypto/ed25519"

	"github.com/bperin/trust/attestation"
	"github.com/bperin/trust/authority"
	"github.com/bperin/trust/claim"
	"github.com/bperin/trust/crypto/ed25519"
	"github.com/bperin/trust/crypto/hkdf"
	"github.com/bperin/trust/crypto/secp256k1"
	"github.com/bperin/trust/delegation"
	"github.com/bperin/trust/evidence"
	"github.com/bperin/trust/identity/did"
	"github.com/bperin/trust/kms"
	"github.com/bperin/trust/merkle"
	"github.com/bperin/trust/signature"
)

// Fixed clock — deterministic across runs. The whole scenario lives
// inside this validity window.
var (
	base      = time.Date(2025, 6, 1, 12, 0, 0, 0, time.UTC)
	notBefore = base.AddDate(0, 0, -1)
	notAfter  = base.AddDate(1, 0, 0)
)

// deriveKey derives an Ed25519 keypair from parent key material along a
// scope path via HKDF-SHA-256, using the "/"-joined path as info.
func deriveKey(t *testing.T, parentSecret []byte, path ...string) (*ed25519.PrivateKey, *ed25519.PublicKey) {
	t.Helper()
	seed, err := hkdf.DeriveKey(parentSecret, []byte("trust/e2e/v1"), []byte(pathString(path)), 32)
	if err != nil {
		t.Fatalf("hkdf.DeriveKey(%q): %v", pathString(path), err)
	}
	priv, err := ed25519.NewPrivateKey(stded25519.NewKeyFromSeed(seed))
	if err != nil {
		t.Fatalf("ed25519.NewPrivateKey(%q): %v", pathString(path), err)
	}
	return priv, priv.Public()
}

func pathString(parts []string) string {
	out := ""
	for i, p := range parts {
		if i > 0 {
			out += "/"
		}
		out += p
	}
	return out
}

// ─── helpers ─────────────────────────────────────────────────────────

// mustAuthorityRef returns the hex canonical-hash reference of an authority.
func mustAuthorityRef(t *testing.T, a *authority.Authority) string {
	t.Helper()
	h := mustAuthorityHash(t, a)
	return hex.EncodeToString(h[:])
}

func newLocalSigner(t *testing.T, priv *ed25519.PrivateKey) *signature.LocalSigner {
	t.Helper()
	s, err := signature.NewLocalSigner(priv)
	if err != nil {
		t.Fatalf("signature.NewLocalSigner: %v", err)
	}
	return s
}

func mustAuthorityHash(t *testing.T, a *authority.Authority) [32]byte {
	t.Helper()
	h, err := authority.CanonicalHash(a)
	if err != nil {
		t.Fatalf("authority.CanonicalHash: %v", err)
	}
	return h
}

func mustAttestationHash(t *testing.T, a *attestation.Attestation) [32]byte {
	t.Helper()
	h, err := attestation.CanonicalHash(a)
	if err != nil {
		t.Fatalf("attestation.CanonicalHash: %v", err)
	}
	return h
}

func testEvidence(id string) evidence.Evidence {
	h := make([]byte, evidence.ContentHashLen)
	for i := range h {
		h[i] = byte(i) ^ byte(len(id))
	}
	return evidence.Evidence{
		Identifier:  id,
		ContentHash: h,
		MediaType:   "application/pdf",
		Locator:     "ipfs://e2e/" + id,
		Provenance: evidence.Provenance{
			Source:    "did:trust:org-a",
			Method:    "retrieved",
			Timestamp: base,
		},
	}
}

// sortedEvidence orders evs strictly ascending by evidence.CanonicalHash —
// the canonical form attestation.Validate requires.
func sortedEvidence(t *testing.T, evs []evidence.Evidence) []evidence.Evidence {
	t.Helper()
	type hashed struct {
		ev evidence.Evidence
		h  [32]byte
	}
	hs := make([]hashed, 0, len(evs))
	for _, ev := range evs {
		h, err := evidence.CanonicalHash(&ev)
		if err != nil {
			t.Fatalf("evidence.CanonicalHash: %v", err)
		}
		hs = append(hs, hashed{ev, h})
	}
	sort.Slice(hs, func(i, j int) bool {
		return bytes.Compare(hs[i].h[:], hs[j].h[:]) < 0
	})
	out := make([]evidence.Evidence, 0, len(hs))
	for _, h := range hs {
		out = append(out, h.ev)
	}
	return out
}

func deepCopyAttestation(t *testing.T, att *attestation.Attestation) *attestation.Attestation {
	t.Helper()
	b, err := json.Marshal(att)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	var out attestation.Attestation
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}
	return &out
}

// TestE2E_TrustLifecycle is the canonical gate. Stages are ordered and
// share state: each stage consumes the previous one's outputs.
func TestE2E_TrustLifecycle(t *testing.T) {
	ctx := context.Background()

	// ── Stage 1: key hierarchy ───────────────────────────────────
	// Derivation must be deterministic and isolated: same path, same key;
	// different paths, unrelated keys.
	rootPriv, rootPub := deriveKey(t, []byte("e2e-root-of-trust"))
	orgAPriv, orgA := deriveKey(t, rootPriv.StdKey(), "org", "a")
	_, orgBPub := deriveKey(t, rootPriv.StdKey(), "org", "b")
	tokyoPriv, tokyoPub := deriveKey(t, orgAPriv.StdKey(), "inventory", "tokyo")
	_, osakaPub := deriveKey(t, orgAPriv.StdKey(), "inventory", "osaka")

	t.Run("1_key_hierarchy", func(t *testing.T) {
		again, _ := deriveKey(t, rootPriv.StdKey(), "org", "a")
		if !again.Public().Equal(orgA) {
			t.Fatal("derivation is not deterministic: org/a key changed across derivations")
		}

		pubs := map[string]*ed25519.PublicKey{
			"root":            rootPub,
			"org/a":           orgA,
			"org/b":           orgBPub,
			"inventory/tokyo": tokyoPub,
			"inventory/osaka": osakaPub,
		}
		names := make([]string, 0, len(pubs))
		for name := range pubs {
			names = append(names, name)
		}
		sort.Strings(names)
		for i := 0; i < len(names); i++ {
			for j := i + 1; j < len(names); j++ {
				if pubs[names[i]].Equal(pubs[names[j]]) {
					t.Fatalf("key collision: %s and %s derived the same key", names[i], names[j])
				}
			}
		}

		// A child's secret under the parent's path never reproduces
		// the parent's key.
		wrongParent, _ := deriveKey(t, tokyoPriv.StdKey(), "org", "a")
		if wrongParent.Public().Equal(orgA) {
			t.Fatal("child secret reproduced the parent key under the parent path")
		}
		wrongSibling, _ := deriveKey(t, rootPriv.StdKey(), "inventory", "osaka")
		if wrongSibling.Public().Equal(osakaPub) {
			t.Fatal("root secret reproduced the sibling key under the sibling path")
		}
	})

	// ── Stage 2: identity binding ────────────────────────────────
	var orgDID, tokyoDID did.DID
	t.Run("2_identity_binding", func(t *testing.T) {
		var err error
		if orgDID, err = did.Parse("did:trust:org-a"); err != nil {
			t.Fatalf("parse org DID: %v", err)
		}
		if tokyoDID, err = did.Parse("did:trust:org-a:inventory:tokyo"); err != nil {
			t.Fatalf("parse tokyo DID: %v", err)
		}
		if orgDID.Method() != "trust" || tokyoDID.Method() != "trust" {
			t.Fatalf("unexpected DID method: %q / %q", orgDID.Method(), tokyoDID.Method())
		}
		if !did.IsDID("did:trust:org-a") || did.IsDID("not-a-did") {
			t.Fatal("DID classification broken")
		}
		otherOrg, err := did.Parse("did:trust:org-b")
		if err != nil {
			t.Fatalf("parse other org DID: %v", err)
		}
		if otherOrg.MethodSpecificID() == orgDID.MethodSpecificID() {
			t.Fatal("distinct organizations resolved to the same identity")
		}
		if _, err := did.Parse("not-a-did"); err == nil {
			t.Fatal("non-DID string accepted")
		}
	})

	// ── Stage 3: root authority, self-asserted and signed ────────
	var rootAuth *authority.Authority
	t.Run("3_root_authority", func(t *testing.T) {
		depth := 3
		rootAuth = &authority.Authority{
			Subject: orgDID.String(),
			Capabilities: []authority.Capability{
				authority.CapabilityAttest,
				authority.CapabilityDelegate,
			},
			Scope: authority.Scope{
				Resources:     []string{"inventory/osaka", "inventory/tokyo"},
				Organizations: []string{"org-a"},
			},
			Validity:              authority.Validity{NotBefore: notBefore, NotAfter: notAfter},
			DelegationConstraints: authority.DelegationConstraints{MaxDepth: &depth},
			Status:                authority.StatusActive,
		}
		if err := authority.Validate(rootAuth); err != nil {
			t.Fatalf("root authority invalid: %v", err)
		}
		if err := authority.SignAuthority(ctx, rootAuth, newLocalSigner(t, rootPriv), "root-key"); err != nil {
			t.Fatalf("SignAuthority: %v", err)
		}
		if err := authority.VerifyAuthorityProof(rootAuth, rootPub); err != nil {
			t.Fatalf("root authority proof: %v", err)
		}

		// Identity binding: the proof binds the authority to the root
		// key. A child key or any unrelated key must be rejected.
		_, wrongPub := deriveKey(t, []byte("unrelated-key"))
		for name, pub := range map[string]*ed25519.PublicKey{
			"child key":     orgA,
			"unrelated key": wrongPub,
		} {
			if err := authority.VerifyAuthorityProof(rootAuth, pub); err == nil {
				t.Fatalf("root authority proof verified under the %s", name)
			}
		}
	})

	// ── Stage 4: delegation ──────────────────────────────────────
	var workerAuth *authority.Authority
	t.Run("4_delegation", func(t *testing.T) {
		inventorySigner := newLocalSigner(t, orgAPriv)
		childDepth := 2
		inventoryAuth, err := delegation.Derive(rootAuth, delegation.DelegationSpec{
			Subject:      tokyoDID.String(),
			Capabilities: []authority.Capability{authority.CapabilityAttest},
			Scope: authority.Scope{
				Resources:     []string{"inventory/tokyo"},
				Organizations: []string{"org-a"},
			},
			Validity: authority.Validity{
				NotBefore: notBefore,
				NotAfter:  notAfter.Add(-time.Hour),
			},
			DelegationConstraints: authority.DelegationConstraints{MaxDepth: &childDepth},
		})
		if err != nil {
			t.Fatalf("derive inventory authority: %v", err)
		}
		if err := authority.SignAuthority(ctx, inventoryAuth, inventorySigner, "org-a-key"); err != nil {
			t.Fatalf("SignAuthority(inventory): %v", err)
		}
		if err := authority.VerifyAuthorityProof(inventoryAuth, orgA); err != nil {
			t.Fatalf("inventory authority proof: %v", err)
		}
		if inventoryAuth.Parent == nil ||
			*inventoryAuth.Parent != mustAuthorityRef(t, rootAuth) {
			t.Fatal("child is not content-addressed to its parent")
		}

		// A worker derives from the inventory authority — never from the org.
		// Its scope and depth stay strictly below the inventory authority's.
		workerDepth := 1
		workerAuth, err = delegation.Derive(inventoryAuth, delegation.DelegationSpec{
			Subject:               "did:trust:org-a:inventory:tokyo:worker-1",
			Capabilities:          []authority.Capability{authority.CapabilityAttest},
			Scope:                 inventoryAuth.Scope,
			Validity:              inventoryAuth.Validity,
			DelegationConstraints: authority.DelegationConstraints{MaxDepth: &workerDepth},
		})
		if err != nil {
			t.Fatalf("derive worker authority: %v", err)
		}
		if err := authority.SignAuthority(ctx, workerAuth, newLocalSigner(t, tokyoPriv), "tokyo-worker-key"); err != nil {
			t.Fatalf("SignAuthority(worker): %v", err)
		}
		if err := authority.VerifyAuthorityProof(workerAuth, tokyoPub); err != nil {
			t.Fatalf("worker authority proof: %v", err)
		}

		// Escalation is rejected, never clamped.
		depth := 2
		escalations := []struct {
			name string
			spec delegation.DelegationSpec
			want error
		}{
			{
				"capability",
				delegation.DelegationSpec{
					Subject:               workerAuth.Subject,
					Capabilities:          []authority.Capability{authority.CapabilityRevoke},
					Validity:              inventoryAuth.Validity,
					DelegationConstraints: authority.DelegationConstraints{MaxDepth: &depth},
				},
				delegation.ErrCapabilityEscalation,
			},
			{
				"scope",
				delegation.DelegationSpec{
					Subject:               workerAuth.Subject,
					Capabilities:          []authority.Capability{authority.CapabilityAttest},
					Scope:                 authority.Scope{Organizations: []string{"org-b"}},
					Validity:              inventoryAuth.Validity,
					DelegationConstraints: authority.DelegationConstraints{MaxDepth: &depth},
				},
				delegation.ErrScopeEscalation,
			},
			{
				"validity",
				delegation.DelegationSpec{
					Subject:      workerAuth.Subject,
					Capabilities: []authority.Capability{authority.CapabilityAttest},
					Scope:        inventoryAuth.Scope,
					Validity: authority.Validity{
						NotBefore: inventoryAuth.Validity.NotBefore,
						NotAfter:  inventoryAuth.Validity.NotAfter.Add(time.Hour),
					},
					DelegationConstraints: authority.DelegationConstraints{MaxDepth: &depth},
				},
				delegation.ErrValidityEscalation,
			},
			{
				"depth",
				delegation.DelegationSpec{
					Subject:               workerAuth.Subject,
					Capabilities:          []authority.Capability{authority.CapabilityAttest},
					Scope:                 inventoryAuth.Scope,
					Validity:              inventoryAuth.Validity,
					DelegationConstraints: authority.DelegationConstraints{},
				},
				delegation.ErrDepthEscalation,
			},
		}
		for _, esc := range escalations {
			if _, err := delegation.Derive(inventoryAuth, esc.spec); !errors.Is(err, esc.want) {
				t.Fatalf("%s escalation: got %v, want %v", esc.name, err, esc.want)
			}
		}

		// Revocation changes the canonical hash — a revoked authority is
		// a different object, so content-addressed references no longer match.
		revoked := *workerAuth
		revoked.Status = authority.StatusRevoked
		revokedHash, err := authority.CanonicalHash(&revoked)
		if err != nil {
			t.Fatalf("canonical hash of revoked authority: %v", err)
		}
		if revokedHash == mustAuthorityHash(t, workerAuth) {
			t.Fatal("revocation did not change the authority's identity")
		}
	})

	// ── Stage 5: attestation under the delegated authority ───────
	var att *attestation.Attestation
	t.Run("5_attestation", func(t *testing.T) {
		att = &attestation.Attestation{
			Issuer:            workerAuth.Subject,
			SigningKeyID:      "tokyo-worker-key",
			SigningKeyVersion: 1,
			AuthorityRef:      mustAuthorityRef(t, workerAuth),
			Capability:        authority.CapabilityAttest,
			Claim: claim.Claim{
				Issuer:  workerAuth.Subject,
				Subject: "did:trust:org-a:inventory:tokyo:crate-42",
				Type:    claim.ClaimType{Namespace: "inventory", Name: "stock-level"},
				Value:   map[string]any{"sku": "CRATE-42", "count": 17},
				Validity: authority.Validity{
					NotBefore: notBefore,
					NotAfter:  workerAuth.Validity.NotAfter,
				},
				Provenance: claim.Provenance{
					Source:    "warehouse/tokyo/scanner-7",
					Method:    "verified-import",
					Timestamp: base,
				},
			},
			Evidence: sortedEvidence(t, []evidence.Evidence{
				testEvidence("ev-b"), testEvidence("ev-a"),
			}),
			IssuedAt: base,
			Validity: workerAuth.Validity,
			Status:   authority.StatusActive,
		}
		if err := attestation.Validate(att); err != nil {
			t.Fatalf("attestation invalid: %v", err)
		}

		// Canonicalize → hash. Construction order must not matter.
		h1, err := attestation.CanonicalHash(att)
		if err != nil {
			t.Fatalf("canonical hash: %v", err)
		}
		if h1 != mustAttestationHash(t, deepCopyAttestation(t, att)) {
			t.Fatal("canonical hash depends on construction order")
		}

		if err := attestation.SignAttestation(ctx, att, newLocalSigner(t, tokyoPriv), "tokyo-worker-key"); err != nil {
			t.Fatalf("SignAttestation: %v", err)
		}
		if err := attestation.VerifySignature(att, tokyoPub); err != nil {
			t.Fatalf("VerifySignature: %v", err)
		}

		// The signed attestation binds to the delegated authority and
		// the worker leaf key — not to the org key, not to the root.
		if att.AuthorityRef != mustAuthorityRef(t, workerAuth) {
			t.Fatal("AuthorityRef does not name the delegated authority")
		}
		for name, pub := range map[string]*ed25519.PublicKey{
			"organization key": orgA,
			"root key":         rootPub,
		} {
			if err := attestation.VerifySignature(att, pub); err == nil {
				t.Fatalf("attestation verified under the %s", name)
			}
		}
	})

	// ── Stage 6: serialization is lossless ───────────────────────
	t.Run("6_serialization", func(t *testing.T) {
		wantHash := mustAttestationHash(t, att)

		jsonCopy := deepCopyAttestation(t, att)
		if mustAttestationHash(t, jsonCopy) != wantHash {
			t.Fatal("JSON round trip changed the canonical hash")
		}
		if err := attestation.VerifySignature(jsonCopy, tokyoPub); err != nil {
			t.Fatalf("verify after JSON round trip: %v", err)
		}

		token, err := attestation.MarshalEAT(att)
		if err != nil {
			t.Fatalf("MarshalEAT: %v", err)
		}
		eatCopy, err := attestation.UnmarshalEAT(token)
		if err != nil {
			t.Fatalf("UnmarshalEAT: %v", err)
		}
		if mustAttestationHash(t, eatCopy) != wantHash {
			t.Fatal("EAT round trip changed the canonical hash")
		}
		if err := attestation.VerifySignature(eatCopy, tokyoPub); err != nil {
			t.Fatalf("verify after EAT round trip: %v", err)
		}
	})

	// ── Stage 7: tamper resistance ────────────────────────────────
	// One mutated field per case: verification must fail every time.
	t.Run("7_tamper", func(t *testing.T) {
		cases := []struct {
			name   string
			mutate func(a *attestation.Attestation)
		}{
			{"issuer", func(a *attestation.Attestation) { a.Issuer = "did:trust:org-b" }},
			{"signing-key-id", func(a *attestation.Attestation) { a.SigningKeyID = "other-key" }},
			{"signing-key-version", func(a *attestation.Attestation) { a.SigningKeyVersion = 2 }},
			{"authority-ref", func(a *attestation.Attestation) {
				a.AuthorityRef = hex.EncodeToString(make([]byte, 32))
			}},
			{"capability", func(a *attestation.Attestation) { a.Capability.Name = "revoke" }},
			{"claim-issuer", func(a *attestation.Attestation) { a.Claim.Issuer = "did:trust:org-b" }},
			{"claim-subject", func(a *attestation.Attestation) {
				a.Claim.Subject = "did:trust:org-a:inventory:tokyo:crate-43"
			}},
			{"claim-value", func(a *attestation.Attestation) {
				a.Claim.Value = map[string]any{"sku": "CRATE-42", "count": 18}
			}},
			{"claim-validity", func(a *attestation.Attestation) {
				a.Claim.Validity.NotAfter = a.Claim.Validity.NotAfter.Add(time.Minute)
			}},
			{"issued-at", func(a *attestation.Attestation) { a.IssuedAt = base.Add(time.Second) }},
			{"validity-not-after", func(a *attestation.Attestation) {
				a.Validity.NotAfter = a.Validity.NotAfter.Add(time.Second)
			}},
			{"status", func(a *attestation.Attestation) { a.Status = authority.StatusRevoked }},
			{"algorithm", func(a *attestation.Attestation) { a.Algorithm = signature.AlgorithmES256K }},
			{"signature", func(a *attestation.Attestation) { a.Signature[0] ^= 0xFF }},
			{"evidence", func(a *attestation.Attestation) { a.Evidence[0].Identifier = "ev-zzz" }},
		}
		for _, tc := range cases {
			tc := tc
			t.Run(tc.name, func(t *testing.T) {
				t.Parallel()
				tampered := deepCopyAttestation(t, att)
				tc.mutate(tampered)
				if err := attestation.VerifySignature(tampered, tokyoPub); err == nil {
					t.Fatalf("tampered %s still verifies", tc.name)
				}
			})
		}
	})

	// ── Stage 8: validity windows are committed, not enforced ────
	// The window is inside the signed hash, so an expired attestation
	// cannot be edited into a valid one without breaking the signature.
	t.Run("8_validity", func(t *testing.T) {
		if err := attestation.Validate(att); err != nil {
			t.Fatalf("valid attestation rejected: %v", err)
		}
		expired := deepCopyAttestation(t, att)
		expired.Validity = authority.Validity{
			NotBefore: notBefore,
			NotAfter:  base.Add(-time.Hour),
		}
		if err := attestation.Validate(expired); err != nil {
			t.Fatalf("Validate must be structural-only: %v", err)
		}
		if err := attestation.VerifySignature(expired, tokyoPub); err == nil {
			t.Fatal("moving NotAfter past the signature kept the signature valid")
		}
		future := deepCopyAttestation(t, att)
		future.Validity = authority.Validity{
			NotBefore: notAfter.Add(time.Hour),
			NotAfter:  notAfter.Add(2 * time.Hour),
		}
		if err := attestation.VerifySignature(future, tokyoPub); err == nil {
			t.Fatal("moving the validity window kept the signature valid")
		}
	})

	// ── Stage 9: Merkle commitment over the produced objects ─────
	t.Run("9_merkle", func(t *testing.T) {
		rootH := mustAuthorityHash(t, rootAuth)
		workerH := mustAuthorityHash(t, workerAuth)
		attH := mustAttestationHash(t, att)
		leaves := [][]byte{
			rootH[:],
			workerH[:],
			attH[:],
		}
		tree, err := merkle.New(leaves)
		if err != nil {
			t.Fatalf("merkle.New: %v", err)
		}
		root := tree.Root()
		for i, leaf := range leaves {
			proof, err := tree.Proof(i)
			if err != nil {
				t.Fatalf("proof(%d): %v", i, err)
			}
			if !merkle.Verify(root, leaf, proof) {
				t.Fatalf("proof(%d) failed to verify", i)
			}
		}

		proof, err := tree.Proof(1)
		if err != nil {
			t.Fatalf("proof(1): %v", err)
		}
		badLeaf := append([]byte(nil), leaves[1]...)
		badLeaf[0] ^= 0xff
		if merkle.Verify(root, badLeaf, proof) {
			t.Fatal("tampered leaf verified")
		}
		wrongRoot := append([]byte(nil), root...)
		wrongRoot[0] ^= 0xff
		if merkle.Verify(wrongRoot, leaves[1], proof) {
			t.Fatal("wrong root verified")
		}

		tree2, err := merkle.New(leaves)
		if err != nil {
			t.Fatalf("merkle.New (rebuild): %v", err)
		}
		if !bytes.Equal(tree2.Root(), root) {
			t.Fatal("merkle root is not deterministic")
		}
	})

	// ── Stage 10: KMS adapter — key custody stays remote ─────────
	t.Run("10_kms_adapter", func(t *testing.T) {
		// The stub is the only place the private key exists.
		remote := newStubKMS(t)
		signer := kms.NewKMSSigner(remote, kms.SignPathJOSE)

		kmsAttestation := deepCopyAttestation(t, att)
		kmsAttestation.Signature = nil
		kmsAttestation.Issuer = "did:trust:org-a:inventory:tokyo:kms"
		if err := attestation.SignAttestation(ctx, kmsAttestation, signer, "kms-key-1"); err != nil {
			t.Fatalf("KMS-backed SignAttestation: %v", err)
		}
		pub, err := signer.PublicKey(ctx)
		if err != nil {
			t.Fatalf("KMSSigner.PublicKey: %v", err)
		}
		if err := attestation.VerifySignature(kmsAttestation, pub); err != nil {
			t.Fatalf("verify KMS-signed attestation: %v", err)
		}

		// EVM path: 65-byte r||s||v whose recovery id recovers the
		// KMS public key.
		digest := mustAttestationHash(t, kmsAttestation)
		evmSig, err := remote.Sign(ctx, digest[:], kms.SignOptions{Path: kms.SignPathEVM})
		if err != nil {
			t.Fatalf("KMS EVM sign: %v", err)
		}
		if len(evmSig) != 65 {
			t.Fatalf("EVM signature length = %d, want 65", len(evmSig))
		}
		recID, err := kms.ComputeRecoveryID(evmSig[:64], digest[:], remote.pub)
		if err != nil {
			t.Fatalf("ComputeRecoveryID: %v", err)
		}
		if recID != evmSig[64] {
			t.Fatalf("recovery id = %d, signature carries %d", recID, evmSig[64])
		}
	})
}

// stubKMS implements kms.RemoteSigner over an in-process secp256k1
// key. It stands in for the remote provider: the key lives only here,
// behind the interface, never inside the attestation path.
type stubKMS struct {
	pub  *secp256k1.PublicKey
	priv *secp256k1.PrivateKey
}

func newStubKMS(t *testing.T) *stubKMS {
	t.Helper()
	priv, pub, err := secp256k1.GenerateKey()
	if err != nil {
		t.Fatalf("secp256k1.GenerateKey: %v", err)
	}
	return &stubKMS{pub: pub, priv: priv}
}

func (s *stubKMS) Sign(ctx context.Context, digest []byte, opts kms.SignOptions) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	switch opts.Path {
	case kms.SignPathJOSE:
		return s.priv.Sign(digest)
	case kms.SignPathEVM:
		sig, recID, err := s.priv.SignRecoverable(digest)
		if err != nil {
			return nil, err
		}
		return append(sig, recID), nil
	default:
		return nil, fmt.Errorf("kms stub: unknown path %d", opts.Path)
	}
}

func (s *stubKMS) PublicKey(context.Context) (*secp256k1.PublicKey, error) {
	return s.pub, nil
}
