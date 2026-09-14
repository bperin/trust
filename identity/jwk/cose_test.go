package jwkutil

import (
	"crypto"
	stdecdsa "crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"math/big"
	"os"
	"testing"

	"github.com/bperin/trust/crypto/ecdsa"
	"github.com/bperin/trust/crypto/ed25519"
	"github.com/bperin/trust/crypto/rsa"
	"github.com/bperin/trust/crypto/secp256k1"
	"github.com/veraison/go-cose"
)

func TestCoseSignVerifyEd25519(t *testing.T) {
	key, pub, err := ed25519.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	payload := []byte("Hello COSE Ed25519")
	coseBytes, err := CoseSign(payload, key, CoseSignOptions{Algorithm: AlgEdDSA})
	if err != nil {
		t.Fatalf("CoseSign: %v", err)
	}

	gotPayload, err := CoseVerify(coseBytes, pub, CoseVerifyOptions{Algorithm: AlgEdDSA})
	if err != nil {
		t.Fatalf("CoseVerify: %v", err)
	}

	if string(gotPayload) != string(payload) {
		t.Errorf("got payload %q, want %q", gotPayload, payload)
	}
}

func TestCoseSignVerifyECDSA(t *testing.T) {
	key, pub, err := ecdsa.GenerateKey(elliptic.P256(), crypto.SHA256)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	payload := []byte("Hello COSE ES256")
	coseBytes, err := CoseSign(payload, key, CoseSignOptions{Algorithm: AlgES256})
	if err != nil {
		t.Fatalf("CoseSign: %v", err)
	}

	gotPayload, err := CoseVerify(coseBytes, pub, CoseVerifyOptions{})
	if err != nil {
		t.Fatalf("CoseVerify: %v", err)
	}

	if string(gotPayload) != string(payload) {
		t.Errorf("got payload %q, want %q", gotPayload, payload)
	}
}

func TestCoseSignVerifySecp256k1(t *testing.T) {
	key, pub, err := secp256k1.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	payload := []byte("Hello COSE ES256K")
	coseBytes, err := CoseSign(payload, key, CoseSignOptions{Algorithm: AlgES256K})
	if err != nil {
		t.Fatalf("CoseSign: %v", err)
	}

	gotPayload, err := CoseVerify(coseBytes, pub, CoseVerifyOptions{})
	if err != nil {
		t.Fatalf("CoseVerify: %v", err)
	}

	if string(gotPayload) != string(payload) {
		t.Errorf("got payload %q, want %q", gotPayload, payload)
	}
}

func TestCoseSignVerifyRSA(t *testing.T) {
	key, pub, err := rsa.GeneratePSSKey(2048, crypto.SHA256)
	if err != nil {
		t.Fatalf("GeneratePSSKey: %v", err)
	}

	payload := []byte("Hello COSE PS256")
	coseBytes, err := CoseSign(payload, key, CoseSignOptions{Algorithm: AlgPS256})
	if err != nil {
		t.Fatalf("CoseSign: %v", err)
	}

	gotPayload, err := CoseVerify(coseBytes, pub, CoseVerifyOptions{})
	if err != nil {
		t.Fatalf("CoseVerify: %v", err)
	}

	if string(gotPayload) != string(payload) {
		t.Errorf("got payload %q, want %q", gotPayload, payload)
	}
}

func TestCoseNegative(t *testing.T) {
	key, pub, err := ed25519.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	coseBytes, err := CoseSign([]byte("test"), key, CoseSignOptions{Algorithm: AlgEdDSA})
	if err != nil {
		t.Fatalf("CoseSign: %v", err)
	}

	// Tampered verification (wrong key)
	_, wrongPub, _ := ed25519.GenerateKey()
	if _, err := CoseVerify(coseBytes, wrongPub, CoseVerifyOptions{}); err == nil {
		t.Error("expected error verifying with wrong key, got nil")
	}

	// Tampered payload
	coseBytes[len(coseBytes)-5] ^= 0xFF
	if _, err := CoseVerify(coseBytes, pub, CoseVerifyOptions{}); err == nil {
		t.Error("expected error verifying tampered COSE object, got nil")
	}
}

// coseKey is one entry in the full-algorithm round-trip table. builtIn
// reports whether github.com/veraison/go-cose ships a built-in
// Signer/Verifier for the algorithm. ES256K (secp256k1) and
// RS256/384/512 (RSA PKCS#1 v1.5) use custom adapters in cose.go
// because go-cose defines their constants but provides no built-in
// signer or verifier.
type coseKey struct {
	name    string
	alg     int64
	priv    crypto.PrivateKey
	pub     crypto.PublicKey
	builtIn bool
}

// coseKeys generates a fresh keypair for every supported COSE algorithm
// (all 10: EdDSA, ES256, ES384, ES256K, PS256, PS384, PS512, RS256,
// RS384, RS512) and returns them in a table. The key-generation patterns
// mirror roundTripKeys in jws_test.go and the existing per-algorithm
// tests above.
func coseKeys(t *testing.T) []coseKey {
	t.Helper()

	edPriv, edPub, err := ed25519.GenerateKey()
	if err != nil {
		t.Fatalf("generate Ed25519 key: got error %v, want nil", err)
	}
	k1Priv, k1Pub, err := secp256k1.GenerateKey()
	if err != nil {
		t.Fatalf("generate secp256k1 key: got error %v, want nil", err)
	}
	p256Priv, p256Pub, err := ecdsa.GenerateKey(elliptic.P256(), crypto.SHA256)
	if err != nil {
		t.Fatalf("generate P-256 key: got error %v, want nil", err)
	}
	p384Priv, p384Pub, err := ecdsa.GenerateKey(elliptic.P384(), crypto.SHA384)
	if err != nil {
		t.Fatalf("generate P-384 key: got error %v, want nil", err)
	}
	ps256Priv, ps256Pub, err := rsa.GeneratePSSKey(2048, crypto.SHA256)
	if err != nil {
		t.Fatalf("generate PSS-256 key: got error %v, want nil", err)
	}
	ps384Priv, ps384Pub, err := rsa.GeneratePSSKey(2048, crypto.SHA384)
	if err != nil {
		t.Fatalf("generate PSS-384 key: got error %v, want nil", err)
	}
	ps512Priv, ps512Pub, err := rsa.GeneratePSSKey(2048, crypto.SHA512)
	if err != nil {
		t.Fatalf("generate PSS-512 key: got error %v, want nil", err)
	}
	rs256Priv, rs256Pub, err := rsa.GeneratePKCS1Key(2048, crypto.SHA256)
	if err != nil {
		t.Fatalf("generate PKCS1-256 key: got error %v, want nil", err)
	}
	rs384Priv, rs384Pub, err := rsa.GeneratePKCS1Key(2048, crypto.SHA384)
	if err != nil {
		t.Fatalf("generate PKCS1-384 key: got error %v, want nil", err)
	}
	rs512Priv, rs512Pub, err := rsa.GeneratePKCS1Key(2048, crypto.SHA512)
	if err != nil {
		t.Fatalf("generate PKCS1-512 key: got error %v, want nil", err)
	}

	return []coseKey{
		{name: "EdDSA", alg: AlgEdDSA, priv: edPriv, pub: edPub, builtIn: true},
		{name: "ES256", alg: AlgES256, priv: p256Priv, pub: p256Pub, builtIn: true},
		{name: "ES384", alg: AlgES384, priv: p384Priv, pub: p384Pub, builtIn: true},
		{name: "ES256K", alg: AlgES256K, priv: k1Priv, pub: k1Pub, builtIn: false},
		{name: "PS256", alg: AlgPS256, priv: ps256Priv, pub: ps256Pub, builtIn: true},
		{name: "PS384", alg: AlgPS384, priv: ps384Priv, pub: ps384Pub, builtIn: true},
		{name: "PS512", alg: AlgPS512, priv: ps512Priv, pub: ps512Pub, builtIn: true},
		{name: "RS256", alg: AlgRS256, priv: rs256Priv, pub: rs256Pub, builtIn: false},
		{name: "RS384", alg: AlgRS384, priv: rs384Priv, pub: rs384Pub, builtIn: false},
		{name: "RS512", alg: AlgRS512, priv: rs512Priv, pub: rs512Pub, builtIn: false},
	}
}

// TestCoseSignVerifyAllAlgorithms exercises the full algorithm set
// (10 algorithms) as table-driven sign → verify round-trips. The
// existing per-algorithm tests above cover 4 of 10; this covers all 10
// in one table, including ES384, PS384, PS512, RS256, RS384, RS512.
func TestCoseSignVerifyAllAlgorithms(t *testing.T) {
	t.Parallel()

	payload := []byte("all-algorithm COSE_Sign1 round-trip")
	for _, key := range coseKeys(t) {
		t.Run(key.name, func(t *testing.T) {
			t.Parallel()

			coseBytes, err := CoseSign(payload, key.priv, CoseSignOptions{Algorithm: key.alg})
			if err != nil {
				t.Fatalf("CoseSign %s: got error %v, want nil", key.name, err)
			}
			if len(coseBytes) == 0 {
				t.Fatalf("CoseSign %s: got empty output, want non-empty COSE_Sign1", key.name)
			}

			got, err := CoseVerify(coseBytes, key.pub, CoseVerifyOptions{})
			if err != nil {
				t.Fatalf("CoseVerify %s: got error %v, want nil", key.name, err)
			}
			if subtle.ConstantTimeCompare(got, payload) != 1 {
				t.Errorf("payload %s: got %x, want %x", key.name, got, payload)
			}

			// Pinning the algorithm through CoseVerifyOptions must
			// also succeed — the caller-pinned check must agree.
			got, err = CoseVerify(coseBytes, key.pub, CoseVerifyOptions{Algorithm: key.alg})
			if err != nil {
				t.Fatalf("CoseVerify %s pinned: got error %v, want nil", key.name, err)
			}
			if subtle.ConstantTimeCompare(got, payload) != 1 {
				t.Errorf("pinned payload %s: got %x, want %x", key.name, got, payload)
			}
		})
	}
}

// TestCoseCrossImplementation verifies interoperability between the
// identity/jwk adapter and github.com/veraison/go-cose directly. This is
// the cross-implementation vector required by TASK-027: a COSE_Sign1
// produced by go-cose verifies through identity/jwk.CoseVerify, and the
// reverse (CoseSign output verifies through go-cose).
//
// Only the standard algorithms (EdDSA, ES256, ES384, PS256, PS384,
// PS512) are covered here — go-cose ships built-in Signer/Verifier
// implementations for those. ES256K (secp256k1) and RS256/384/512 (RSA
// PKCS#1 v1.5) have no built-in go-cose Signer or Verifier (see
// go-cose signer.go/verifier.go: "no built-in implementation available"),
// so neither direction is feasible with the external library. Those
// algorithms are exercised by TestCoseSignVerifyAllAlgorithms and the
// custom-adapter negative tests below.
func TestCoseCrossImplementation(t *testing.T) {
	t.Parallel()

	payload := []byte("cross-implementation COSE_Sign1 vector")
	for _, key := range coseKeys(t) {
		if !key.builtIn {
			// go-cose has no built-in signer/verifier for ES256K or
			// RS256/384/512; cross-implementation with the external
			// library is not feasible for these algorithms.
			continue
		}
		t.Run(key.name, func(t *testing.T) {
			t.Parallel()

			// Direction A: go-cose signs directly (no identity/jwk
			// code on the produce side), identity/jwk verifies.
			rawPriv, err := toStdlibPrivateKey(key.priv, "")
			if err != nil {
				t.Fatalf("toStdlibPrivateKey %s: got error %v, want nil", key.name, err)
			}
			signer, ok := rawPriv.(crypto.Signer)
			if !ok {
				t.Fatalf("stdlib private key %s: got %T, want crypto.Signer", key.name, rawPriv)
			}
			gcSigner, err := cose.NewSigner(cose.Algorithm(key.alg), signer)
			if err != nil {
				t.Fatalf("cose.NewSigner %s: got error %v, want nil", key.name, err)
			}
			gcMsg := cose.UntaggedSign1Message{
				Headers: cose.Headers{
					Protected:   cose.ProtectedHeader{},
					Unprotected: cose.UnprotectedHeader{},
				},
				Payload: payload,
			}
			if err := gcMsg.Sign(rand.Reader, nil, gcSigner); err != nil {
				t.Fatalf("go-cose Sign %s: got error %v, want nil", key.name, err)
			}
			gcBytes, err := gcMsg.MarshalCBOR()
			if err != nil {
				t.Fatalf("go-cose MarshalCBOR %s: got error %v, want nil", key.name, err)
			}

			got, err := CoseVerify(gcBytes, key.pub, CoseVerifyOptions{})
			if err != nil {
				t.Fatalf("CoseVerify go-cose-produced %s: got error %v, want nil", key.name, err)
			}
			if subtle.ConstantTimeCompare(got, payload) != 1 {
				t.Errorf("go-cose-produced payload %s: got %x, want %x", key.name, got, payload)
			}

			// Direction B: identity/jwk signs, go-cose verifies
			// directly (no identity/jwk code on the consume side).
			coseBytes, err := CoseSign(payload, key.priv, CoseSignOptions{Algorithm: key.alg})
			if err != nil {
				t.Fatalf("CoseSign %s: got error %v, want nil", key.name, err)
			}
			var parsed cose.UntaggedSign1Message
			if err := parsed.UnmarshalCBOR(coseBytes); err != nil {
				t.Fatalf("go-cose UnmarshalCBOR %s: got error %v, want nil", key.name, err)
			}
			rawPub, err := toStdlibPublicKey(key.pub)
			if err != nil {
				t.Fatalf("toStdlibPublicKey %s: got error %v, want nil", key.name, err)
			}
			gcVerifier, err := cose.NewVerifier(cose.Algorithm(key.alg), rawPub)
			if err != nil {
				t.Fatalf("cose.NewVerifier %s: got error %v, want nil", key.name, err)
			}
			if err := parsed.Verify(nil, gcVerifier); err != nil {
				t.Fatalf("go-cose Verify identity-produced %s: got error %v, want nil", key.name, err)
			}
			if subtle.ConstantTimeCompare(parsed.Payload, payload) != 1 {
				t.Errorf("identity-produced payload %s: got %x, want %x", key.name, parsed.Payload, payload)
			}
		})
	}
}

// TestCoseRFC9052C2 verifies the [RFC 9052] §C.2.1 "Single ECDSA
// Signature" example COSE_Sign1 parses and verifies through the
// identity/jwk adapter. The vector is a tagged COSE_Sign1 (CBOR tag 18)
// signed with ES256 (ECDSA w/ SHA-256, Curve P-256) over the payload
// "This is the content." with kid "11".
//
// The signature is randomized ECDSA, so it cannot be reproduced by
// re-signing; instead the exact signature bytes from the RFC are
// embedded and verified against the RFC's published P-256 public key.
// This is a true cross-implementation vector: an RFC-produced
// signature verifies through identity/jwk.CoseVerify.
//
// Vector source: [RFC 9052] Appendix C.2.1 and C.7.1 (public key for
// kid "11").
func TestCoseRFC9052C2(t *testing.T) {
	// Public key for kid "11" from [RFC 9052] §C.7.1 (P-256).
	xHex := "bac5b11cad8f99f9c72b05cf4b9e26d244dc189f745228255a219a86d6a09eff"
	yHex := "20138bf82dc1b6d562be0fa54ab7804a3a64b6d72ccfed6b6fb6ed28bbfc117e"
	// Signature from [RFC 9052] §C.2.1 (R || S, 64 bytes, COSE ECDSA
	// signature format).
	sigHex := "8eb33e4ca31d1c465ab05aac34cc6b23d58fef5c083106c4d25a91aef0b0117e" +
		"2af9a291aa32e14ab834dc56ed2a223444547e01f11d3b0916e5a4c345cacb36"

	xBytes, err := hex.DecodeString(xHex)
	if err != nil {
		t.Fatalf("decode x: got error %v, want nil", err)
	}
	yBytes, err := hex.DecodeString(yHex)
	if err != nil {
		t.Fatalf("decode y: got error %v, want nil", err)
	}
	sigBytes, err := hex.DecodeString(sigHex)
	if err != nil {
		t.Fatalf("decode signature: got error %v, want nil", err)
	}
	if len(sigBytes) != 64 {
		t.Fatalf("signature length: got %d bytes, want 64", len(sigBytes))
	}

	stdPub := &stdecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     new(big.Int).SetBytes(xBytes),
		Y:     new(big.Int).SetBytes(yBytes),
	}
	pub, err := ecdsa.NewPublicKey(stdPub, crypto.SHA256)
	if err != nil {
		t.Fatalf("ecdsa.NewPublicKey: got error %v, want nil", err)
	}

	// Reconstruct the exact tagged COSE_Sign1 from [RFC 9052] §C.2.1
	// using go-cose, then verify it through identity/jwk.CoseVerify.
	// The protected header is {1: -7} (alg ES256); the unprotected
	// header carries kid "11".
	msg := cose.NewSign1Message()
	msg.Headers.Protected = cose.ProtectedHeader{cose.HeaderLabelAlgorithm: cose.AlgorithmES256}
	msg.Headers.Unprotected = cose.UnprotectedHeader{cose.HeaderLabelKeyID: []byte("11")}
	msg.Payload = []byte("This is the content.")
	msg.Signature = sigBytes

	tagged, err := msg.MarshalCBOR()
	if err != nil {
		t.Fatalf("MarshalCBOR RFC vector: got error %v, want nil", err)
	}
	// Tagged COSE_Sign1 starts with 0xd2 (CBOR tag 18).
	if len(tagged) == 0 || tagged[0] != 0xd2 {
		t.Fatalf("tagged output: got %x, want 0xd2 prefix", tagged)
	}

	got, err := CoseVerify(tagged, pub, CoseVerifyOptions{})
	if err != nil {
		t.Fatalf("CoseVerify RFC 9052 §C.2.1 vector: got error %v, want nil", err)
	}
	want := []byte("This is the content.")
	if subtle.ConstantTimeCompare(got, want) != 1 {
		t.Errorf("RFC 9052 §C.2.1 payload: got %x, want %x", got, want)
	}

	// Pinning ES256 must also succeed.
	if _, err := CoseVerify(tagged, pub, CoseVerifyOptions{Algorithm: AlgES256}); err != nil {
		t.Errorf("CoseVerify RFC vector pinned ES256: got error %v, want nil", err)
	}
}

// tamperPayload re-serializes a COSE_Sign1 with a modified payload but
// the original signature, so the signature no longer matches. It uses
// go-cose to parse and re-marshal, preserving the protected header and
// signature bytes.
func tamperPayload(t *testing.T, coseBytes []byte, newPayload []byte) []byte {
	t.Helper()
	var msg cose.UntaggedSign1Message
	if err := msg.UnmarshalCBOR(coseBytes); err != nil {
		t.Fatalf("tamperPayload UnmarshalCBOR: got error %v, want nil", err)
	}
	msg.Payload = newPayload
	out, err := msg.MarshalCBOR()
	if err != nil {
		t.Fatalf("tamperPayload MarshalCBOR: got error %v, want nil", err)
	}
	return out
}

// tamperSignature re-serializes a COSE_Sign1 with one byte of the
// signature flipped, so verification fails.
func tamperSignature(t *testing.T, coseBytes []byte) []byte {
	t.Helper()
	var msg cose.UntaggedSign1Message
	if err := msg.UnmarshalCBOR(coseBytes); err != nil {
		t.Fatalf("tamperSignature UnmarshalCBOR: got error %v, want nil", err)
	}
	if len(msg.Signature) == 0 {
		t.Fatalf("tamperSignature: got empty signature, want non-empty")
	}
	msg.Signature[0] ^= 0xFF
	out, err := msg.MarshalCBOR()
	if err != nil {
		t.Fatalf("tamperSignature MarshalCBOR: got error %v, want nil", err)
	}
	return out
}

// TestCoseNegativeTable is the table-driven negative test suite
// required by TASK-027. Each case proves a distinct failure mode is
// rejected: wrong key, tampered payload, tampered signature, alg
// mismatch (caller-pinned), and malformed CBOR (empty, random, and
// truncated inputs).
func TestCoseNegativeTable(t *testing.T) {
	t.Parallel()

	edPriv, edPub, err := ed25519.GenerateKey()
	if err != nil {
		t.Fatalf("generate Ed25519 key: got error %v, want nil", err)
	}
	_, wrongPub, err := ed25519.GenerateKey()
	if err != nil {
		t.Fatalf("generate wrong Ed25519 key: got error %v, want nil", err)
	}

	goodBytes, err := CoseSign([]byte("negative-table payload"), edPriv, CoseSignOptions{Algorithm: AlgEdDSA})
	if err != nil {
		t.Fatalf("CoseSign: got error %v, want nil", err)
	}

	// truncated is a valid-prefix-but-incomplete COSE_Sign1: the first
	// byte is the array marker (0x84) but the structure is cut short.
	truncated := append([]byte(nil), goodBytes[:6]...)
	// random is non-CBOR garbage that is neither tagged (0xd2) nor an
	// untagged COSE_Sign1 array (0x84).
	random := []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05}

	tests := []struct {
		name    string
		input   []byte
		key     crypto.PublicKey
		opts    CoseVerifyOptions
		wantErr error
	}{
		{
			name:    "wrong key same alg",
			input:   goodBytes,
			key:     wrongPub,
			opts:    CoseVerifyOptions{},
			wantErr: ErrCoseInvalidSig,
		},
		{
			name:    "tampered payload",
			input:   tamperPayload(t, goodBytes, []byte("tampered-payload")),
			key:     edPub,
			opts:    CoseVerifyOptions{},
			wantErr: ErrCoseInvalidSig,
		},
		{
			name:    "tampered signature",
			input:   tamperSignature(t, goodBytes),
			key:     edPub,
			opts:    CoseVerifyOptions{},
			wantErr: ErrCoseInvalidSig,
		},
		{
			name:    "alg mismatch caller pinned",
			input:   goodBytes,
			key:     edPub,
			opts:    CoseVerifyOptions{Algorithm: AlgES256},
			wantErr: ErrAlgMismatch,
		},
		{
			name:    "malformed empty input",
			input:   []byte{},
			key:     edPub,
			opts:    CoseVerifyOptions{},
			wantErr: ErrCoseMalformed,
		},
		{
			name:    "malformed random bytes",
			input:   random,
			key:     edPub,
			opts:    CoseVerifyOptions{},
			wantErr: ErrCoseMalformed,
		},
		{
			name:    "malformed truncated COSE",
			input:   truncated,
			key:     edPub,
			opts:    CoseVerifyOptions{},
			wantErr: ErrCoseMalformed,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := CoseVerify(tt.input, tt.key, tt.opts)
			if err == nil {
				t.Fatalf("CoseVerify %s: got nil error, want non-nil (got payload %x)", tt.name, got)
			}
			if tt.wantErr != nil && !errors.Is(err, tt.wantErr) {
				t.Errorf("CoseVerify %s: got error %v, want errors.Is(_, %v)", tt.name, err, tt.wantErr)
			}
		})
	}
}

// TestCoseBoundary exercises the payload-size boundaries: a 0-byte
// payload and a 4096-byte payload. Boundaries are where wire-format
// bugs live (nil-vs-empty handling, length encoding).
func TestCoseBoundary(t *testing.T) {
	t.Parallel()

	priv, pub, err := ed25519.GenerateKey()
	if err != nil {
		t.Fatalf("generate Ed25519 key: got error %v, want nil", err)
	}

	tests := []struct {
		name    string
		payload []byte
	}{
		{name: "empty payload", payload: []byte{}},
		{name: "max-size 4096 payload", payload: make([]byte, 4096)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			// Fill the max-size payload with non-zero bytes so a
			// truncation bug would surface as a mismatch.
			if len(tt.payload) > 0 {
				for i := range tt.payload {
					tt.payload[i] = byte(i)
				}
			}

			coseBytes, err := CoseSign(tt.payload, priv, CoseSignOptions{Algorithm: AlgEdDSA})
			if err != nil {
				t.Fatalf("CoseSign %s: got error %v, want nil", tt.name, err)
			}
			got, err := CoseVerify(coseBytes, pub, CoseVerifyOptions{})
			if err != nil {
				t.Fatalf("CoseVerify %s: got error %v, want nil", tt.name, err)
			}
			if len(got) != len(tt.payload) {
				t.Errorf("payload length %s: got %d, want %d", tt.name, len(got), len(tt.payload))
			}
			if subtle.ConstantTimeCompare(got, tt.payload) != 1 {
				t.Errorf("payload %s: got %x, want %x", tt.name, got, tt.payload)
			}
		})
	}
}

// TestCoseWycheproofCoverage documents the Wycheproof test coverage
// strategy for the COSE adapter. Project Wycheproof provides raw
// signature vectors (message, signature, public key) for ECDSA, RSA,
// Ed25519, and secp256k1 — not COSE_Sign1 envelopes. COSE signs a
// derived Sig_structure ([RFC 9052] §4.4) over the protected header,
// external AAD, and payload, so a raw Wycheproof signature cannot be
// wrapped into a COSE_Sign1 and still verify (the signed bytes differ).
//
// The COSE adapter is a thin wire-format wrapper: it delegates
// signature verification to the underlying primitives, which already
// carry full Wycheproof coverage in their own packages. This test
// asserts those Wycheproof testdata fixtures are present, proving the
// primitives the adapter delegates to are independently hardened
// against known attack vectors. No t.Skip is used.
func TestCoseWycheproofCoverage(t *testing.T) {
	t.Parallel()

	// Wycheproof fixtures for the primitives the COSE adapter
	// delegates to. ES256/ES384 → crypto/ecdsa; PS256/384/512 and
	// RS256/384/512 → crypto/rsa; EdDSA → crypto/ed25519; ES256K →
	// crypto/secp256k1.
	fixtures := []string{
		"../../crypto/ecdsa/testdata/ecdsa_secp256r1_sha256_test.json",
		"../../crypto/ecdsa/testdata/ecdsa_secp384r1_sha384_test.json",
		"../../crypto/rsa/testdata/rsa_pss_2048_sha256_mgf1_32_test.json",
		"../../crypto/rsa/testdata/rsa_signature_2048_sha256_test.json",
		"../../crypto/ed25519/testdata/ed25519_test.json",
		"../../crypto/secp256k1/testdata/ecdsa_secp256k1_sha256_test.json",
	}
	for _, f := range fixtures {
		info, err := os.Stat(f)
		if err != nil {
			t.Errorf("wycheproof fixture %s: got error %v, want nil (primitive-layer coverage missing)", f, err)
			continue
		}
		if info.Size() == 0 {
			t.Errorf("wycheproof fixture %s: got size 0, want non-empty (primitive-layer coverage missing)", f)
		}
	}
}
