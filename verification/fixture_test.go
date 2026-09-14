package verification

import (
	"context"
	"crypto"
	"crypto/sha256"
	"fmt"
	"testing"
	"time"

	"github.com/bperin/trust/attestation"
	"github.com/bperin/trust/authority"
	"github.com/bperin/trust/claim"
	"github.com/bperin/trust/crypto/ed25519"
	"github.com/bperin/trust/evidence"
	"github.com/bperin/trust/identity/did"
	"github.com/bperin/trust/signature"
)

const (
	testRootDID = "did:trust:root"
	testMidDID  = "did:trust:mid"
	testLeafDID = "did:trust:leaf"
)

// stubResolver resolves the fixture DIDs to documents carrying the
// fixture public keys.
type stubResolver struct {
	docs map[string]*did.Document
}

func (r *stubResolver) Resolve(d did.DID) (*did.Document, error) {
	doc, ok := r.docs[d.String()]
	if !ok {
		return nil, fmt.Errorf("stub resolver: unresolved DID %q", d.String())
	}
	return doc, nil
}

// fixtureOpts carries pre-sign mutations for failure fixtures: claim
// scope escalation and a revoked hop must be applied before signing so
// signatures stay valid.
type fixtureOpts struct {
	evidence       [][]byte
	claimResources []string
	revokeHop      int
}

// fixture is a valid offline verification fixture: a three-hop
type fixture struct {
	rootPriv *ed25519.PrivateKey
	midPriv  *ed25519.PrivateKey
	leafPriv *ed25519.PrivateKey
	attPriv  *ed25519.PrivateKey
	rootPub  *ed25519.PublicKey
	midPub   *ed25519.PublicKey
	leafPub  *ed25519.PublicKey
	attPub   *ed25519.PublicKey
	chain    []AuthorityHop
	att      *attestation.Attestation
	resolver *stubResolver
	now      time.Time
	validity authority.Validity

	// evidence holds the supplied content for each evidence entry,
	// indexed like att.Evidence.
	evidence [][]byte

	// detachedRoot is a second, independently signed root authority
	// used to splice a broken chain in failure tests.
	detachedRoot AuthorityHop
}

// buildFixture assembles a valid leaf→root fixture. Each entry in
// evidence becomes an attestation evidence reference whose supplied
// content is returned in Inputs.Evidence.
func buildFixture(t *testing.T, evidence ...[]byte) *fixture {
	t.Helper()
	return buildFixtureWith(t, fixtureOpts{evidence: evidence})
}

// makeDetachedRoot builds a second validly-signed root authority with
// the same subject and validity as the fixture root but a fresh key.
func (f *fixture) makeDetachedRoot(t *testing.T) {
	t.Helper()
	priv, pub, err := ed25519.GenerateKey()
	if err != nil {
		t.Fatalf("generate detached root key: %v", err)
	}
	root := &authority.Authority{
		Subject:      testRootDID,
		Capabilities: []authority.Capability{authority.CapabilityAttest, authority.CapabilityDelegate},
		// Narrow the window so the detached root's canonical hash
		// differs from the original root's — the mid authority's
		// parent reference then points elsewhere: a broken chain.
		Validity: authority.Validity{
			NotBefore: f.validity.NotBefore.Add(30 * time.Minute),
			NotAfter:  f.validity.NotAfter,
		},
		Status: authority.StatusActive,
	}
	if err := authority.SignAuthority(context.Background(), root, mustSigner(t, priv), "root-key"); err != nil {
		t.Fatalf("sign detached root: %v", err)
	}
	// Register the detached root's key so key binding still resolves.
	f.resolver.docs[testRootDID] = &did.Document{
		ID: testRootDID,
		VerificationMethod: []did.Method{{
			ID:                 testRootDID + "#root-key",
			Type:               "Ed25519VerificationKey2020",
			Controller:         testRootDID,
			PublicKeyMultibase: multibaseZ(t, pub),
		}},
	}
	f.detachedRoot = AuthorityHop{Authority: root, PublicKey: pub}
}

// buildFixtureWith assembles a fixture, applying pre-sign mutations.
func buildFixtureWith(t *testing.T, o fixtureOpts) *fixture {
	t.Helper()

	now := time.Now().Truncate(time.Second).UTC()
	validity := authority.Validity{NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour)}

	rootPriv, rootPub, err := ed25519.GenerateKey()
	if err != nil {
		t.Fatalf("generate root key: %v", err)
	}
	midPriv, midPub, err := ed25519.GenerateKey()
	if err != nil {
		t.Fatalf("generate mid key: %v", err)
	}
	leafPriv, leafPub, err := ed25519.GenerateKey()
	if err != nil {
		t.Fatalf("generate leaf key: %v", err)
	}
	attPriv, attPub, err := ed25519.GenerateKey()
	if err != nil {
		t.Fatalf("generate attestation key: %v", err)
	}
	ctx := context.Background()

	root := &authority.Authority{
		Subject:      testRootDID,
		Capabilities: []authority.Capability{authority.CapabilityAttest, authority.CapabilityDelegate},
		Validity:     validity,
		Status:       authority.StatusActive,
	}
	if err := authority.SignAuthority(ctx, root, mustSigner(t, rootPriv), "root-key"); err != nil {
		t.Fatalf("sign root authority: %v", err)
	}

	midStatus := authority.StatusActive
	if o.revokeHop == 1 {
		midStatus = authority.StatusRevoked
	}
	mid := &authority.Authority{
		Subject:      testMidDID,
		Capabilities: []authority.Capability{authority.CapabilityAttest, authority.CapabilityDelegate},
		Validity:     validity,
		Status:       midStatus,
	}
	if err := setParentFromHash(mid, root); err != nil {
		t.Fatalf("link mid to root: %v", err)
	}
	if err := authority.SignAuthority(ctx, mid, mustSigner(t, midPriv), "mid-key"); err != nil {
		t.Fatalf("sign mid authority: %v", err)
	}

	leaf := &authority.Authority{
		Subject:      testLeafDID,
		Capabilities: []authority.Capability{authority.CapabilityAttest},
		Validity:     validity,
		Status:       authority.StatusActive,
	}
	if err := setParentFromHash(leaf, mid); err != nil {
		t.Fatalf("link leaf to mid: %v", err)
	}
	if err := authority.SignAuthority(ctx, leaf, mustSigner(t, leafPriv), "leaf-key"); err != nil {
		t.Fatalf("sign leaf authority: %v", err)
	}

	leafRef, err := hashRef(authority.CanonicalHash(leaf))
	if err != nil {
		t.Fatalf("leaf hash: %v", err)
	}

	att := &attestation.Attestation{
		Issuer:            testLeafDID,
		SigningKeyID:      "att-key",
		SigningKeyVersion: 1,
		AuthorityRef:      leafRef,
		Capability:        authority.CapabilityAttest,
		Claim: claim.Claim{
			Issuer:     testLeafDID,
			Subject:    "did:trust:subject",
			Type:       claim.ClaimType{Namespace: "trust", Name: "role"},
			Value:      map[string]any{"role": "admin"},
			Scope:      claimScope(o.claimResources),
			Validity:   validity,
			Provenance: claim.Provenance{Source: "fixture", Method: "self-attested", Timestamp: now},
		},
		IssuedAt: now,
		Validity: validity,
		Status:   authority.StatusActive,
	}
	for _, content := range o.evidence {
		sum := sha256.Sum256(content)
		att.Evidence = append(att.Evidence, evidence.Evidence{
			Identifier:  fmt.Sprintf("ev-%x", sum[:4]),
			ContentHash: append([]byte(nil), sum[:]...),
			MediaType:   "text/plain",
			Locator:     "fixture://material",
			Provenance:  evidence.Provenance{Source: "fixture", Method: "generated", Timestamp: now},
		})
	}
	if err := attestation.SignAttestation(ctx, att, mustSigner(t, attPriv), "att-key"); err != nil {
		t.Fatalf("sign attestation: %v", err)
	}

	f := &fixture{
		rootPriv: rootPriv,
		midPriv:  midPriv,
		leafPriv: leafPriv,
		attPriv:  attPriv,
		rootPub:  rootPub,
		midPub:   midPub,
		leafPub:  leafPub,
		attPub:   attPub,
		chain: []AuthorityHop{
			{Authority: leaf, PublicKey: leafPub},
			{Authority: mid, PublicKey: midPub},
			{Authority: root, PublicKey: rootPub},
		},
		att:      att,
		resolver: &stubResolver{docs: map[string]*did.Document{}},
		now:      now,
		validity: validity,
		evidence: o.evidence,
	}
	f.resolver.docs[testLeafDID] = &did.Document{
		ID: testLeafDID,
		VerificationMethod: []did.Method{{
			ID:                 testLeafDID + "#att-key",
			Type:               "Ed25519VerificationKey2020",
			Controller:         testLeafDID,
			PublicKeyMultibase: multibaseZ(t, attPub),
		}},
	}
	f.resolver.docs[testRootDID] = &did.Document{
		ID: testRootDID,
		VerificationMethod: []did.Method{{
			ID:                 testRootDID + "#root-key",
			Type:               "Ed25519VerificationKey2020",
			Controller:         testRootDID,
			PublicKeyMultibase: multibaseZ(t, rootPub),
		}},
	}
	return f
}

// inputs assembles the verification Inputs for the fixture.
func (f *fixture) inputs() Inputs {
	in := Inputs{
		Attestation:      f.att,
		SigningKey:       f.attPub,
		Chain:            f.chain,
		IdentityResolver: f.resolver,
		Now:              f.now,
	}
	if len(f.att.Evidence) > 0 {
		in.Evidence = map[string][]byte{}
		for i := range f.att.Evidence {
			eh, err := evidence.CanonicalHash(&f.att.Evidence[i])
			if err != nil {
				continue
			}
			in.Evidence[hashRefHex(eh)] = f.evidence[i]
		}
	}
	return in
}

// hashRefHex renders a canonical hash as hex.
func hashRefHex(h [32]byte) string {
	return fmt.Sprintf("%x", h[:])
}

// claimScope builds a Scope with the given resources.
func claimScope(resources []string) authority.Scope {
	if len(resources) == 0 {
		return authority.Scope{}
	}
	return authority.Scope{Resources: resources}
}

// setParentFromHash sets auth.Parent to the canonical-hash hex of to the canonical-hash hex of
// parent, mirroring delegation.Derive.
func setParentFromHash(auth, parent *authority.Authority) error {
	ph, err := authority.CanonicalHash(parent)
	if err != nil {
		return err
	}
	ref := hashRefHex(ph)
	auth.Parent = &ref
	return nil
}

// mustSigner wraps a private key in a LocalSigner or fails the test.
func mustSigner(t *testing.T, key crypto.PrivateKey) signature.Signer {
	t.Helper()
	s, err := signature.NewLocalSigner(key)
	if err != nil {
		t.Fatalf("NewLocalSigner: %v", err)
	}
	return s
}

// multibaseZ encodes a public key as multibase base58btc.
func multibaseZ(t *testing.T, pub *ed25519.PublicKey) string {
	t.Helper()
	b := pub.Bytes()
	return "z" + encodeBase58BTC(b[:])
}

// encodeBase58BTC encodes bytes as base58btc.
func encodeBase58BTC(b []byte) string {
	const alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
	zeros := 0
	for zeros < len(b) && b[zeros] == 0 {
		zeros++
	}
	out := make([]byte, 0, len(b)*2)
	for _, c := range b {
		carry := int(c)
		for i := range out {
			carry += 256 * int(out[i])
			out[i] = byte(carry % 58)
			carry /= 58
		}
		for carry > 0 {
			out = append(out, byte(carry%58))
			carry /= 58
		}
	}
	res := make([]byte, 0, zeros+len(out))
	for i := 0; i < zeros; i++ {
		res = append(res, alphabet[0])
	}
	for i := len(out) - 1; i >= 0; i-- {
		res = append(res, alphabet[out[i]])
	}
	return string(res)
}
