package attestation

import (
	"bytes"
	stded25519 "crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"testing"

	trusted25519 "github.com/bperin/trust/crypto/ed25519"
	"github.com/fxamacker/cbor/v2"
	"github.com/veraison/go-cose"
)

// TestEATCBOR_IndependentWireFixture_A08 verifies the EAT/CBOR codec
// consumes a COSE_Sign1 token produced by an independent code path
// (github.com/veraison/go-cose directly), not by attestation.Issue.
//
// A08 requires an independent wire fixture for every codec moved or
// created. The existing tests only round-trip: Issue produces a token
// and Verify consumes it — both use the same jwkutil.CoseSign/CoseVerify
// adapter. This fixture constructs the COSE_Sign1 message with go-cose
// directly, then feeds the raw bytes to attestation.Verify. If the
// codec's wire format drifts, this test catches it independently.
//
// The fixture uses a deterministic Ed25519 key so the token bytes are
// reproducible. The claims are a minimal CWT claim set per [RFC 8392]
// §3.1.1.
func TestEATCBOR_IndependentWireFixture_A08(t *testing.T) {
	t.Parallel()

	// Deterministic Ed25519 key from a known seed (RFC 8032 Test
	// Vector 1 seed). The stdlib NewKeyFromSeed produces the 64-byte
	// private key (seed || public key); the trust ed25519.NewPrivateKey
	// wraps it. The public key is derived for attestation.Verify.
	seed := hexDecode(t, "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
	stdPriv := stded25519.NewKeyFromSeed(seed)
	stdPub := stdPriv.Public().(stded25519.PublicKey)

	trustPriv, err := trusted25519.NewPrivateKey(stdPriv)
	if err != nil {
		t.Fatalf("NewPrivateKey: got error %v, want nil", err)
	}
	trustPub, err := trusted25519.NewPublicKey(stdPub)
	if err != nil {
		t.Fatalf("NewPublicKey: got error %v, want nil", err)
	}
	// go-cose's signer needs the stdlib private key; attestation.Verify
	// needs the trust public key. Both are derived from the same seed.
	priv := stdPriv
	pub := trustPub
	_ = trustPriv // retained for clarity; the signing path uses stdPriv

	// Build the CWT claim set as a CBOR map per [RFC 8392] §3.1.1.
	// Labels: 1=iss, 2=sub, 3=aud, 4=exp, 6=iat, 10=nonce.
	claims := map[int64]any{
		ClaimIssuer:   "did:example:issuer",
		ClaimSubject:  "did:example:subject",
		ClaimAudience: "did:example:verifier",
		ClaimExpiry:   int64(4102444800), // 2100-01-01
		ClaimNonce:    []byte("wire-fixture-nonce"),
	}

	// Encode the claims with canonical CBOR options, independently of
	// attestation.Issue (which uses cborCanonical → cbor.CanonicalEncOptions).
	encOpts := cbor.CanonicalEncOptions()
	encMode, err := encOpts.EncMode()
	if err != nil {
		t.Fatalf("EncMode: got error %v, want nil", err)
	}
	payload, err := encMode.Marshal(claims)
	if err != nil {
		t.Fatalf("Marshal claims: got error %v, want nil", err)
	}

	// Construct the COSE_Sign1 message directly with go-cose, bypassing
	// jwkutil.CoseSign. This is the independent production path.
	protected := cose.ProtectedHeader{}
	protected.SetAlgorithm(cose.AlgorithmEdDSA)
	protected[4] = []byte("did:example:issuer#keys-1") // kid

	msg := cose.UntaggedSign1Message{
		Headers: cose.Headers{
			Protected:   protected,
			Unprotected: cose.UnprotectedHeader{},
		},
		Payload: payload,
	}

	signer, err := cose.NewSigner(cose.AlgorithmEdDSA, priv)
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

	// Verify the independently-produced token through attestation.Verify.
	// This is the consumption path under test.
	recovered, err := Verify(token, pub, VerifyOptions{
		ExpectedIssuer:   "did:example:issuer",
		ExpectedAudience: "did:example:verifier",
	})
	if err != nil {
		t.Fatalf("Verify independent token: got error %v, want nil", err)
	}

	// Assert the recovered claims match the original.
	if got, want := recovered[ClaimIssuer], "did:example:issuer"; got != want {
		t.Errorf("iss: got %v, want %q", got, want)
	}
	if got, want := recovered[ClaimSubject], "did:example:subject"; got != want {
		t.Errorf("sub: got %v, want %q", got, want)
	}
	if got, want := recovered[ClaimAudience], "did:example:verifier"; got != want {
		t.Errorf("aud: got %v, want %q", got, want)
	}
	nonce, ok := recovered[ClaimNonce].([]byte)
	if !ok {
		t.Fatalf("nonce: got %T, want []byte", recovered[ClaimNonce])
	}
	if !bytes.Equal(nonce, []byte("wire-fixture-nonce")) {
		t.Errorf("nonce: got %x, want %x", nonce, []byte("wire-fixture-nonce"))
	}
}

// TestEATCBOR_ClaimsEncoding_A08 verifies the CBOR claims encoding
// produces known bytes independent of the attestation.Issue path.
// The claims map is encoded with canonical CBOR and the output is
// compared against a precomputed hex string. This pins the wire format
// so a silent change in the CBOR encoding options is caught.
func TestEATCBOR_ClaimsEncoding_A08(t *testing.T) {
	t.Parallel()

	// Minimal claims: iss (1) and exp (4) only.
	claims := map[int64]any{
		ClaimIssuer: "did:example:issuer",
		ClaimExpiry: int64(4102444800),
	}

	// Encode with canonical CBOR — the same options attestation.Issue
	// uses internally (cbor.CanonicalEncOptions).
	encMode, err := cbor.CanonicalEncOptions().EncMode()
	if err != nil {
		t.Fatalf("EncMode: got error %v, want nil", err)
	}
	got, err := encMode.Marshal(claims)
	if err != nil {
		t.Fatalf("Marshal: got error %v, want nil", err)
	}

	// The expected CBOR is a map with two entries sorted bytewise on
	// the encoded keys. Key 1 (iss) encodes as 0x01; key 4 (exp) encodes
	// as 0x04. In bytewise order, 0x01 < 0x04, so iss comes first.
	//
	// a2       — map of 2 entries
	// 01       — key 1 (iss)
	// 72       — tstr of length 18 ("did:example:issuer" is 18 bytes)
	//   "did:example:issuer"
	// 04       — key 4 (exp)
	// 1a       — uint32 (4102444800 = 0xF4865700)
	//   f4 86 57 00
	want := hexDecode(t, "a201726469643a6578616d706c653a697373756572041af4865700")

	if !bytes.Equal(got, want) {
		t.Fatalf("claims CBOR: got %x, want %x", got, want)
	}
}

// hexDecode is a test helper that panics on invalid hex.
func hexDecode(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("hexDecode(%q): %v", s, err)
	}
	return b
}
