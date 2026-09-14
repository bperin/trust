package attestation

import (
	"bytes"
	stded25519 "crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"testing"

	"github.com/bperin/trust/canonical"
	trusted25519 "github.com/bperin/trust/crypto/ed25519"
	"github.com/veraison/go-cose"
)

// TestEAT_WireFixture verifies the EAT codec consumes a COSE_Sign1
// token produced by an independent code path
// (github.com/veraison/go-cose directly), not by the attestation
// codec's own marshal path.
//
// A08 requires an independent wire fixture for every codec moved or
// created. The round-trip test shares one encoder on both sides;
// this fixture constructs the COSE_Sign1 message with go-cose
// directly over an independently CBOR-encoded attestation map, then
// feeds the raw bytes to UnmarshalEAT. If the codec's wire format
// drifts, this test catches it independently.
//
// The fixture uses a deterministic Ed25519 key (RFC 8032 Test Vector
// 1 seed) so the token bytes are reproducible. The COSE signature is
// genuine — go-cose signs the Sig_structure — and the signature slot
// is recovered verbatim into Attestation.Signature. The assertion
// that the recovered attestation passes VerifyAttestation is owned
// by TASK-071 (wave 3).
func TestEAT_WireFixture(t *testing.T) {
	t.Parallel()

	// Deterministic Ed25519 key from a known seed (RFC 8032 Test
	// Vector 1 seed). go-cose's signer needs the stdlib private key;
	// the codec needs no key at all.
	seed := hexDecode(t, "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
	stdPriv := stded25519.NewKeyFromSeed(seed)
	stdPub := stdPriv.Public().(stded25519.PublicKey)

	trustPub, err := trusted25519.NewPublicKey(stdPub)
	if err != nil {
		t.Fatalf("NewPublicKey: got error %v, want nil", err)
	}

	// Build the attestation claim map independently of eatClaims: the
	// fields are set by hand and encoded with canonical CBOR options,
	// so the fixture does not share the codec's map builder. Evidence
	// is cleared so the map and the hashed identity agree.
	att := testAttestation(t)
	att.Signature = nil
	att.Evidence = nil
	h, err := CanonicalHash(att)
	if err != nil {
		t.Fatalf("CanonicalHash: %v", err)
	}
	capability, err := canonicalJSON(att.Capability)
	if err != nil {
		t.Fatalf("canonicalJSON capability: %v", err)
	}
	claimBytes, err := canonicalJSON(att.Claim)
	if err != nil {
		t.Fatalf("canonicalJSON claim: %v", err)
	}
	claims := map[int64]any{
		ClaimIssuer:            att.Issuer,
		ClaimExpiry:            att.Validity.NotAfter.Unix(),
		ClaimNotBefore:         att.Validity.NotBefore.Unix(),
		ClaimIssuedAt:          att.IssuedAt.Unix(),
		ClaimCWTID:             hex.EncodeToString(h[:]),
		labelAuthorityRef:      att.AuthorityRef,
		labelCapability:        capability,
		labelClaim:             claimBytes,
		labelEvidence:          [][]byte{},
		labelSigningKeyID:      att.SigningKeyID,
		labelSigningKeyVersion: int64(att.SigningKeyVersion),
		labelAlgorithm:         att.Algorithm.COSE(),
		labelStatus:            int64(att.Status),
	}
	payload, err := canonical.CBOREncode(claims)
	if err != nil {
		t.Fatalf("CBOREncode: %v", err)
	}

	// Construct the COSE_Sign1 message directly with go-cose and
	// produce a genuine Ed25519 signature over the Sig_structure.
	protected := cose.ProtectedHeader{}
	protected.SetAlgorithm(cose.AlgorithmEdDSA)
	protected[4] = []byte("did:example:attester#keys-1") // kid

	msg := cose.UntaggedSign1Message{
		Headers: cose.Headers{
			Protected:   protected,
			Unprotected: cose.UnprotectedHeader{},
		},
		Payload: payload,
	}
	signer, err := cose.NewSigner(cose.AlgorithmEdDSA, stdPriv)
	if err != nil {
		t.Fatalf("NewSigner: got error %v, want nil", err)
	}
	if err := msg.Sign(rand.Reader, nil, signer); err != nil {
		t.Fatalf("Sign: got error %v, want nil", err)
	}
	token, err := msg.MarshalCBOR()
	if err != nil {
		t.Fatalf("MarshalCBOR: got error %v, want nil", err)
	}

	// Consume the independently-produced token through UnmarshalEAT.
	recovered, err := UnmarshalEAT(token)
	if err != nil {
		t.Fatalf("UnmarshalEAT independent token: got error %v, want nil", err)
	}

	// Assert every field survived the wire.
	if got, want := recovered.Issuer, att.Issuer; got != want {
		t.Errorf("Issuer: got %q, want %q", got, want)
	}
	if got, want := recovered.SigningKeyID, att.SigningKeyID; got != want {
		t.Errorf("SigningKeyID: got %q, want %q", got, want)
	}
	if got, want := recovered.SigningKeyVersion, att.SigningKeyVersion; got != want {
		t.Errorf("SigningKeyVersion: got %d, want %d", got, want)
	}
	if got, want := recovered.AuthorityRef, att.AuthorityRef; got != want {
		t.Errorf("AuthorityRef: got %q, want %q", got, want)
	}
	if got, want := recovered.Capability, att.Capability; got != want {
		t.Errorf("Capability: got %+v, want %+v", got, want)
	}
	if got, want := recovered.Claim.Issuer, att.Claim.Issuer; got != want {
		t.Errorf("Claim.Issuer: got %q, want %q", got, want)
	}
	if got, want := recovered.Claim.Subject, att.Claim.Subject; got != want {
		t.Errorf("Claim.Subject: got %q, want %q", got, want)
	}
	if !recovered.Claim.Validity.NotAfter.Equal(att.Claim.Validity.NotAfter) {
		t.Errorf("Claim.Validity.NotAfter: got %v, want %v", recovered.Claim.Validity.NotAfter, att.Claim.Validity.NotAfter)
	}
	if !recovered.IssuedAt.Equal(att.IssuedAt) {
		t.Errorf("IssuedAt: got %v, want %v", recovered.IssuedAt, att.IssuedAt)
	}
	if !recovered.Validity.NotBefore.Equal(att.Validity.NotBefore) {
		t.Errorf("Validity.NotBefore: got %v, want %v", recovered.Validity.NotBefore, att.Validity.NotBefore)
	}
	if !recovered.Validity.NotAfter.Equal(att.Validity.NotAfter) {
		t.Errorf("Validity.NotAfter: got %v, want %v", recovered.Validity.NotAfter, att.Validity.NotAfter)
	}
	if got, want := recovered.Status, att.Status; got != want {
		t.Errorf("Status: got %d, want %d", got, want)
	}
	if got, want := recovered.Algorithm, att.Algorithm; got != want {
		t.Errorf("Algorithm: got %s, want %s", got.JOSE(), want.JOSE())
	}
	if len(recovered.Signature) == 0 {
		t.Fatal("recovered Signature is empty — the COSE signature slot was dropped")
	}
	if !bytes.Equal(recovered.Signature, msg.Signature) {
		t.Errorf("Signature: got %x, want the go-cose signature %x", recovered.Signature, msg.Signature)
	}
	_ = trustPub
}
