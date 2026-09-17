package verification

import (
	"context"
	"crypto"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"math/big"
	"testing"
	"time"

	"github.com/bperin/trust/attestation"
	"github.com/bperin/trust/authority"
	"github.com/bperin/trust/claim"
	"github.com/bperin/trust/crypto/ecdsa"
	"github.com/bperin/trust/crypto/ed25519"
	"github.com/bperin/trust/crypto/rsa"
	"github.com/bperin/trust/crypto/secp256k1"
	"github.com/bperin/trust/evidence"
	"github.com/bperin/trust/identity/did"
	jwkutil "github.com/bperin/trust/identity/jwk"
	"github.com/bperin/trust/signature"
)

// fixtureRSABits is the RSA modulus size generated for RSA fixtures.
const fixtureRSABits = 2048

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

	// alg is the signature algorithm of every key in the fixture; zero
	// means Ed25519.
	alg signature.Algorithm
}

// fixture is a valid three-hop offline verification fixture.
type fixture struct {
	rootPriv crypto.PrivateKey
	midPriv  crypto.PrivateKey
	leafPriv crypto.PrivateKey
	attPriv  crypto.PrivateKey
	rootPub  crypto.PublicKey
	midPub   crypto.PublicKey
	leafPub  crypto.PublicKey
	attPub   crypto.PublicKey
	alg      signature.Algorithm
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

// buildFixtureAlg assembles a valid leaf→root fixture whose keys all use alg.
func buildFixtureAlg(t *testing.T, alg signature.Algorithm) *fixture {
	t.Helper()
	return buildFixtureWith(t, fixtureOpts{alg: alg})
}

// makeDetachedRoot builds a second validly-signed root authority with
// the same subject and validity as the fixture root but a fresh key.
func (f *fixture) makeDetachedRoot(t *testing.T) {
	t.Helper()
	priv, pub := newKeyPair(t, f.alg)
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
		ID:                 testRootDID,
		VerificationMethod: []did.Method{methodFor(t, testRootDID, "root-key", pub)},
	}
	f.detachedRoot = AuthorityHop{Authority: root, PublicKey: pub}
}

// buildFixtureWith assembles a fixture, applying pre-sign mutations.
func buildFixtureWith(t *testing.T, o fixtureOpts) *fixture {
	t.Helper()

	now := time.Now().Truncate(time.Second).UTC()
	validity := authority.Validity{NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour)}

	alg := o.alg
	if alg == 0 {
		alg = signature.AlgorithmEdDSA
	}
	rootPriv, rootPub := newKeyPair(t, alg)
	midPriv, midPub := newKeyPair(t, alg)
	leafPriv, leafPub := newKeyPair(t, alg)
	attPriv, attPub := newKeyPair(t, alg)
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
		alg:      alg,
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
		ID:                 testLeafDID,
		VerificationMethod: []did.Method{methodFor(t, testLeafDID, "att-key", attPub)},
	}
	f.resolver.docs[testRootDID] = &did.Document{
		ID:                 testRootDID,
		VerificationMethod: []did.Method{methodFor(t, testRootDID, "root-key", rootPub)},
	}
	return f
}

// resignAttestation re-signs the attestation after a pre-hash mutation.
func (f *fixture) resignAttestation(t *testing.T) {
	t.Helper()
	if err := attestation.SignAttestation(context.Background(), f.att, mustSigner(t, f.attPriv), f.att.SigningKeyID); err != nil {
		t.Fatalf("re-sign attestation: %v", err)
	}
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

// setParentFromHash sets auth.Parent to the canonical-hash hex of parent, mirroring delegation.Derive.
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

// newKeyPair generates a trust key pair for alg.
func newKeyPair(t *testing.T, alg signature.Algorithm) (crypto.PrivateKey, crypto.PublicKey) {
	t.Helper()
	switch alg {
	case signature.AlgorithmEdDSA:
		priv, pub, err := ed25519.GenerateKey()
		if err != nil {
			t.Fatalf("generate EdDSA key: %v", err)
		}
		return priv, pub
	case signature.AlgorithmES256:
		priv, pub, err := ecdsa.GenerateKey(elliptic.P256(), crypto.SHA256)
		if err != nil {
			t.Fatalf("generate ES256 key: %v", err)
		}
		return priv, pub
	case signature.AlgorithmES384:
		priv, pub, err := ecdsa.GenerateKey(elliptic.P384(), crypto.SHA384)
		if err != nil {
			t.Fatalf("generate ES384 key: %v", err)
		}
		return priv, pub
	case signature.AlgorithmES256K:
		priv, pub, err := secp256k1.GenerateKey()
		if err != nil {
			t.Fatalf("generate ES256K key: %v", err)
		}
		return priv, pub
	case signature.AlgorithmPS256, signature.AlgorithmPS384, signature.AlgorithmPS512:
		priv, pub, err := rsa.GeneratePSSKey(fixtureRSABits, hashForAlg(alg))
		if err != nil {
			t.Fatalf("generate %s key: %v", alg.JOSE(), err)
		}
		return priv, pub
	case signature.AlgorithmRS256, signature.AlgorithmRS384, signature.AlgorithmRS512:
		priv, pub, err := rsa.GeneratePKCS1Key(fixtureRSABits, hashForAlg(alg))
		if err != nil {
			t.Fatalf("generate %s key: %v", alg.JOSE(), err)
		}
		return priv, pub
	default:
		t.Fatalf("no key generator for algorithm %q", alg.JOSE())
		return nil, nil
	}
}

// hashForAlg returns the hash an RSA algorithm signs.
func hashForAlg(alg signature.Algorithm) crypto.Hash {
	switch alg {
	case signature.AlgorithmPS384, signature.AlgorithmRS384:
		return crypto.SHA384
	case signature.AlgorithmPS512, signature.AlgorithmRS512:
		return crypto.SHA512
	default:
		return crypto.SHA256
	}
}

// methodFor builds a verification method declaring pub's algorithm, encoding
// the key material the way the fixture exercises that algorithm.
func methodFor(t *testing.T, docID, keyID string, pub crypto.PublicKey) did.Method {
	t.Helper()
	alg, err := signature.AlgorithmForPublicKey(pub)
	if err != nil {
		t.Fatalf("algorithm for a %T: %v", pub, err)
	}
	m := did.Method{ID: docID + "#" + keyID, Controller: docID}
	switch alg {
	case signature.AlgorithmEdDSA:
		m.Type = "Ed25519VerificationKey2020"
		m.PublicKeyMultibase = multibaseZ(keyMaterial(t, pub, "raw"))
	case signature.AlgorithmES256:
		m.Type = "EcdsaSecp256r1VerificationKey2019"
		m.PublicKeyMultibase = multibaseU(keyMaterial(t, pub, "uncompressed"))
	case signature.AlgorithmES384:
		m.Type = "EcdsaSecp256r1VerificationKey2019"
		m.PublicKeyMultibase = multibaseF(keyMaterial(t, pub, "coordinates"))
	case signature.AlgorithmES256K:
		m.Type = "EcdsaSecp256k1VerificationKey2019"
		m.PublicKeyMultibase = multibaseZ(keyMaterial(t, pub, "compressed"))
	default:
		m.Type = "JsonWebKey2020"
		m.PublicKeyJWK = jwkFor(t, pub)
	}
	return m
}

// keyMaterial returns a trust public key's multibase-encodable bytes in the
// named point form: raw, compressed, uncompressed, or coordinates.
func keyMaterial(t *testing.T, pub crypto.PublicKey, form string) []byte {
	t.Helper()
	switch k := pub.(type) {
	case *ed25519.PublicKey:
		if form != "raw" {
			t.Fatalf("Ed25519 has no %q encoding", form)
		}
		b := k.Bytes()
		return b[:]
	case *secp256k1.PublicKey:
		switch form {
		case "raw", "compressed":
			return k.Bytes()
		case "uncompressed":
			return k.BytesUncompressed()
		case "coordinates":
			b := k.BytesUncompressed()
			return b[1:]
		}
	case *ecdsa.PublicKey:
		field := k.Curve().Params().BitSize / 8
		switch form {
		case "compressed":
			return compressedPoint(k.X(), k.Y(), field)
		case "uncompressed":
			return uncompressedPoint(k.X(), k.Y(), field)
		case "coordinates":
			return coordinates(k.X(), k.Y(), field)
		}
	}
	t.Fatalf("no %q encoding for a %T", form, pub)
	return nil
}

// jwkFor marshals a trust public key into a JWK member.
func jwkFor(t *testing.T, pub crypto.PublicKey) map[string]any {
	t.Helper()
	m, err := jwkutil.Marshal(pub)
	if err != nil {
		t.Fatalf("marshal JWK: %v", err)
	}
	return m
}

// coordinates encodes a curve point as fixed-width x||y bytes.
func coordinates(x, y *big.Int, field int) []byte {
	return append(coordinate(x, field), coordinate(y, field)...)
}

// coordinate encodes one curve coordinate as fixed-width big-endian bytes.
func coordinate(v *big.Int, field int) []byte {
	out := make([]byte, field)
	b := v.Bytes()
	copy(out[field-len(b):], b)
	return out
}

// uncompressedPoint encodes a curve point as 0x04||x||y bytes.
func uncompressedPoint(x, y *big.Int, field int) []byte {
	return append([]byte{0x04}, coordinates(x, y, field)...)
}

// compressedPoint encodes a curve point as its 0x02 or 0x03 prefixed x coordinate.
func compressedPoint(x, y *big.Int, field int) []byte {
	prefix := byte(0x02)
	if y.Bit(0) == 1 {
		prefix = 0x03
	}
	return append([]byte{prefix}, coordinate(x, field)...)
}

// multibaseZ encodes raw key bytes as multibase base58btc.
func multibaseZ(raw []byte) string {
	return "z" + encodeBase58BTC(raw)
}

// multibaseU encodes raw key bytes as multibase base64url.
func multibaseU(raw []byte) string {
	return "u" + base64.RawURLEncoding.EncodeToString(raw)
}

// multibaseF encodes raw key bytes as multibase base16.
func multibaseF(raw []byte) string {
	return "f" + hex.EncodeToString(raw)
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
