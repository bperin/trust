package verification

import (
	"bytes"
	"crypto"
	"encoding/base64"
	"errors"
	"strings"
	"testing"

	"github.com/bperin/trust/identity/did"
	"github.com/bperin/trust/signature"
)

// everyAlgorithm lists the ten registered signature algorithms.
var everyAlgorithm = []signature.Algorithm{
	signature.AlgorithmEdDSA,
	signature.AlgorithmES256K,
	signature.AlgorithmES256,
	signature.AlgorithmES384,
	signature.AlgorithmPS256,
	signature.AlgorithmPS384,
	signature.AlgorithmPS512,
	signature.AlgorithmRS256,
	signature.AlgorithmRS384,
	signature.AlgorithmRS512,
}

// bindTestMethod binds one verification method from a single-method document.
func bindTestMethod(t *testing.T, m did.Method) (crypto.PublicKey, error) {
	t.Helper()
	doc := &did.Document{ID: m.Controller, VerificationMethod: []did.Method{m}}
	return DocumentKeyBinder{}.Bind(strings.TrimPrefix(m.ID, m.Controller+"#"), doc)
}

// materialMethod generates a key for keyAlg and encodes it under declaredType.
// An empty form means the method carries a JWK; mutate edits that JWK.
func materialMethod(t *testing.T, keyAlg signature.Algorithm, declaredType, form, prefix string, mutate func(map[string]any)) did.Method {
	t.Helper()
	_, pub := newKeyPair(t, keyAlg)
	m := did.Method{ID: testLeafDID + "#k1", Type: declaredType, Controller: testLeafDID}
	if form == "" {
		member := jwkFor(t, pub)
		if mutate != nil {
			mutate(member)
		}
		m.PublicKeyJWK = member
		return m
	}
	if mutate != nil {
		t.Fatalf("materialMethod: JWK mutation on a %q encoding", form)
	}
	m.PublicKeyMultibase = multibaseWith(prefix, keyMaterial(t, pub, form))
	return m
}

// multibaseWith encodes raw under the z, u, or f multibase prefix.
func multibaseWith(prefix string, raw []byte) string {
	switch prefix {
	case "u":
		return multibaseU(raw)
	case "f":
		return multibaseF(raw)
	default:
		return multibaseZ(raw)
	}
}

// TestKeyBinder_BindsEveryEncoding binds one verification method per declared
// algorithm and key-material encoding.
func TestKeyBinder_BindsEveryEncoding(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name         string
		alg          signature.Algorithm
		declaredType string
		form         string
		prefix       string
	}{
		{"Ed25519 base58btc suite", signature.AlgorithmEdDSA, "Ed25519VerificationKey2020", "raw", "z"},
		{"Ed25519 2018 suite base64url", signature.AlgorithmEdDSA, "Ed25519VerificationKey2018", "raw", "u"},
		{"Ed25519 bare JOSE name", signature.AlgorithmEdDSA, "EdDSA", "raw", "z"},
		{"Ed25519 COSE label", signature.AlgorithmEdDSA, "-8", "raw", "z"},
		{"Ed25519 JOSE name in suite form", signature.AlgorithmEdDSA, "EdDSAVerificationKey2020", "raw", "z"},
		{"Ed25519 JWK", signature.AlgorithmEdDSA, "JsonWebKey2020", "", ""},
		{"P-256 uncompressed point", signature.AlgorithmES256, "EcdsaSecp256r1VerificationKey2019", "uncompressed", "z"},
		{"P-256 compressed point", signature.AlgorithmES256, "ES256", "compressed", "u"},
		{"P-256 coordinates base16", signature.AlgorithmES256, "ES256VerificationKey2020", "coordinates", "f"},
		{"P-256 JWK", signature.AlgorithmES256, "JsonWebKey2020", "", ""},
		{"P-384 uncompressed point", signature.AlgorithmES384, "EcdsaSecp256r1VerificationKey2019", "uncompressed", "z"},
		{"P-384 compressed point", signature.AlgorithmES384, "ES384", "compressed", "u"},
		{"P-384 coordinates base16", signature.AlgorithmES384, "ES384", "coordinates", "f"},
		{"P-384 JWK", signature.AlgorithmES384, "JsonWebKey2020", "", ""},
		{"secp256k1 compressed point", signature.AlgorithmES256K, "EcdsaSecp256k1VerificationKey2019", "compressed", "z"},
		{"secp256k1 uncompressed point", signature.AlgorithmES256K, "ES256K", "uncompressed", "u"},
		{"secp256k1 coordinates base16", signature.AlgorithmES256K, "EcdsaSecp256k1RecoveryMethod2020", "coordinates", "f"},
		{"secp256k1 JWK", signature.AlgorithmES256K, "JsonWebKey2020", "", ""},
		{"PS256 JWK", signature.AlgorithmPS256, "JsonWebKey2020", "", ""},
		{"PS384 JWK", signature.AlgorithmPS384, "JsonWebKey2020", "", ""},
		{"PS512 JWK", signature.AlgorithmPS512, "JsonWebKey2020", "", ""},
		{"PS256 RSA suite", signature.AlgorithmPS256, "RsaVerificationKey2018", "", ""},
		{"RS256 JWK", signature.AlgorithmRS256, "JsonWebKey2020", "", ""},
		{"RS384 JWK", signature.AlgorithmRS384, "JsonWebKey2020", "", ""},
		{"RS512 JWK", signature.AlgorithmRS512, "JsonWebKey2020", "", ""},
		{"RS512 bare JOSE name", signature.AlgorithmRS512, "RS512", "", ""},
		{"P-384 with no declared suite", signature.AlgorithmES384, "", "coordinates", "f"},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			m := materialMethod(t, tc.alg, tc.declaredType, tc.form, tc.prefix, nil)
			got, err := bindTestMethod(t, m)
			if err != nil {
				t.Fatalf("Bind(%q, type %q): got error %v, want a %s key", m.ID, tc.declaredType, err, tc.alg.JOSE())
			}
			bound, err := signature.AlgorithmForPublicKey(got)
			if err != nil {
				t.Fatalf("AlgorithmForPublicKey(%T): %v", got, err)
			}
			if bound != tc.alg {
				t.Errorf("bound algorithm = %s from a %T, want %s", bound.JOSE(), got, tc.alg.JOSE())
			}
		})
	}
}

// TestKeyBinder_BindsDeclaredKeyMaterial binds each generated key and compares
// the bound key against the key that was encoded.
func TestKeyBinder_BindsDeclaredKeyMaterial(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name         string
		alg          signature.Algorithm
		declaredType string
		form         string
		prefix       string
	}{
		{"Ed25519", signature.AlgorithmEdDSA, "Ed25519VerificationKey2020", "raw", "z"},
		{"P-256", signature.AlgorithmES256, "EcdsaSecp256r1VerificationKey2019", "uncompressed", "z"},
		{"P-384", signature.AlgorithmES384, "EcdsaSecp256r1VerificationKey2019", "coordinates", "f"},
		{"secp256k1", signature.AlgorithmES256K, "EcdsaSecp256k1VerificationKey2019", "compressed", "z"},
		{"PS384", signature.AlgorithmPS384, "JsonWebKey2020", "", ""},
		{"RS256", signature.AlgorithmRS256, "RsaVerificationKey2018", "", ""},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, pub := newKeyPair(t, tc.alg)
			m := did.Method{ID: testLeafDID + "#k1", Type: tc.declaredType, Controller: testLeafDID}
			if tc.form == "" {
				m.PublicKeyJWK = jwkFor(t, pub)
			} else {
				m.PublicKeyMultibase = multibaseWith(tc.prefix, keyMaterial(t, pub, tc.form))
			}
			got, err := bindTestMethod(t, m)
			if err != nil {
				t.Fatalf("Bind: got error %v, want the %s key", err, tc.alg.JOSE())
			}
			if !samePublicKey(got, pub) {
				t.Errorf("bound key = %T, want the generated %T key", got, pub)
			}
		})
	}
}

// TestKeyBinder_BindsRSAJWKWithUnpaddedModulus binds an RSA JWK whose modulus
// carries no leading zero byte, per [RFC 7518] §6.3.1.
func TestKeyBinder_BindsRSAJWKWithUnpaddedModulus(t *testing.T) {
	t.Parallel()
	_, pub := newKeyPair(t, signature.AlgorithmRS256)
	member := jwkFor(t, pub)
	n, ok := member["n"].(string)
	if !ok || n == "" || strings.HasPrefix(n, "AA") {
		t.Fatalf("JWK modulus = %q, want unpadded base64url", n)
	}
	got, err := bindTestMethod(t, did.Method{
		ID: testLeafDID + "#k1", Type: "JsonWebKey2020", Controller: testLeafDID, PublicKeyJWK: member,
	})
	if err != nil {
		t.Fatalf("Bind: got error %v, want an RS256 key", err)
	}
	if alg, _ := signature.AlgorithmForPublicKey(got); alg != signature.AlgorithmRS256 {
		t.Errorf("bound algorithm = %s, want RS256", alg.JOSE())
	}
}

// TestKeyBinder_RejectsDeclaredAlgorithmContradictions rejects material whose
// declared algorithm differs from the key it encodes.
func TestKeyBinder_RejectsDeclaredAlgorithmContradictions(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name         string
		keyAlg       signature.Algorithm
		declaredType string
		form         string
		prefix       string
	}{
		{"declared ES384 with an Ed25519 key", signature.AlgorithmEdDSA, "ES384", "raw", "z"},
		{"declared EdDSA with a P-256 point", signature.AlgorithmES256, "Ed25519VerificationKey2020", "uncompressed", "z"},
		{"declared EdDSA with a P-256 JWK", signature.AlgorithmES256, "Ed25519VerificationKey2020", "", ""},
		{"declared EdDSA with P-384 coordinates", signature.AlgorithmES384, "Ed25519VerificationKey2020", "coordinates", "f"},
		{"declared EdDSA with a secp256k1 point", signature.AlgorithmES256K, "Ed25519VerificationKey2018", "compressed", "z"},
		{"declared ES256 with a P-384 point", signature.AlgorithmES384, "ES256", "uncompressed", "z"},
		{"declared ES384 with P-256 coordinates", signature.AlgorithmES256, "ES384", "coordinates", "f"},
		{"declared ES256 with a secp256k1 JWK", signature.AlgorithmES256K, "EcdsaSecp256r1VerificationKey2019", "", ""},
		{"declared ES256K with a P-256 JWK", signature.AlgorithmES256, "EcdsaSecp256k1VerificationKey2019", "", ""},
		{"declared RS256 with a PS256 JWK", signature.AlgorithmPS256, "RS256", "", ""},
		{"declared PS384 with an RS384 JWK", signature.AlgorithmRS384, "PS384", "", ""},
		{"declared EdDSA with an RS512 JWK", signature.AlgorithmRS512, "Ed25519VerificationKey2020", "", ""},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			m := materialMethod(t, tc.keyAlg, tc.declaredType, tc.form, tc.prefix, nil)
			got, err := bindTestMethod(t, m)
			if err == nil {
				t.Fatalf("Bind returned a %T, want ErrKeyBinding for type %q", got, tc.declaredType)
			}
			if !errors.Is(err, ErrKeyBinding) {
				t.Errorf("errors.Is(err, ErrKeyBinding) = false for err %v, want true", err)
			}
			if errors.Is(err, ErrStructural) {
				t.Errorf("err = %v, want the contradiction typed as ErrKeyBinding not ErrStructural", err)
			}
		})
	}
}

// TestKeyBinder_RejectsContradictoryJWKMembers rejects a JWK whose members
// disagree with each other or name an unusable key.
func TestKeyBinder_RejectsContradictoryJWKMembers(t *testing.T) {
	t.Parallel()
	set := func(k string, v any) func(map[string]any) {
		return func(m map[string]any) { m[k] = v }
	}
	drop := func(k string) func(map[string]any) {
		return func(m map[string]any) { delete(m, k) }
	}
	cases := []struct {
		name   string
		keyAlg signature.Algorithm
		typ    string
		mutate func(map[string]any)
	}{
		{"JWK alg contradicts its crv", signature.AlgorithmES256, "JsonWebKey2020", set("alg", "EdDSA")},
		{"JWK alg none", signature.AlgorithmEdDSA, "JsonWebKey2020", set("alg", "none")},
		{"JWK RSA alg on an EC key", signature.AlgorithmES256, "JsonWebKey2020", set("alg", "RS256")},
		{"JWK crv contradicts its kty", signature.AlgorithmEdDSA, "JsonWebKey2020", set("kty", "EC")},
		{"unsupported JWK crv", signature.AlgorithmES256, "JsonWebKey2020", set("crv", "P-521")},
		{"unsupported JWK kty", signature.AlgorithmEdDSA, "JsonWebKey2020", set("kty", "oct")},
		{"RSA JWK without alg or declaration", signature.AlgorithmPS256, "JsonWebKey2020", drop("alg")},
		{"RSA JWK with an unknown alg", signature.AlgorithmPS256, "JsonWebKey2020", set("alg", "PS123")},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			m := materialMethod(t, tc.keyAlg, tc.typ, "", "", tc.mutate)
			got, err := bindTestMethod(t, m)
			if err == nil {
				t.Fatalf("Bind returned a %T, want ErrKeyBinding", got)
			}
			if !errors.Is(err, ErrKeyBinding) {
				t.Errorf("errors.Is(err, ErrKeyBinding) = false for err %v, want true", err)
			}
		})
	}
}

// TestKeyBinder_RejectsMalformedKeyMaterial rejects structural defects in the
// encoded key material instead of coercing it to another algorithm.
func TestKeyBinder_RejectsMalformedKeyMaterial(t *testing.T) {
	t.Parallel()
	_, edPub := newKeyPair(t, signature.AlgorithmEdDSA)
	edRaw := keyMaterial(t, edPub, "raw")
	_, p256Pub := newKeyPair(t, signature.AlgorithmES256)
	p256Uncompressed := keyMaterial(t, p256Pub, "uncompressed")
	_, p384Pub := newKeyPair(t, signature.AlgorithmES384)
	p384Coordinates := keyMaterial(t, p384Pub, "coordinates")

	cases := []struct {
		name         string
		declaredType string
		multibase    string
	}{
		{"truncated Ed25519 key", "Ed25519VerificationKey2020", multibaseZ(edRaw[:len(edRaw)-1])},
		{"oversized Ed25519 key", "Ed25519VerificationKey2020", multibaseZ(append(append([]byte{}, edRaw...), 0x00, 0x01))},
		{"Ed25519 keypair material", "Ed25519VerificationKey2020", multibaseF(bytes.Repeat([]byte{0xff}, 64))},
		{"truncated P-256 point", "ES256", multibaseZ(p256Uncompressed[:len(p256Uncompressed)-3])},
		{"oversized P-256 point", "ES256", multibaseZ(append(append([]byte{}, p256Uncompressed...), 0x00))},
		{"non-point material", "ES256", multibaseZ(append([]byte{0x05}, p256Uncompressed[1:]...))},
		{"truncated P-384 coordinates", "ES384", multibaseF(p384Coordinates[:len(p384Coordinates)-1])},
		{"oversized P-384 coordinates", "ES384", multibaseF(append(append([]byte{}, p384Coordinates...), 0x00, 0x00))},
		{"empty multibase value", "Ed25519VerificationKey2020", "z"},
		{"unsupported multibase prefix", "Ed25519VerificationKey2020", "b" + base64.StdEncoding.EncodeToString(edRaw)},
		{"invalid base58 character", "Ed25519VerificationKey2020", "z0OIl"},
		{"invalid base16 character", "Ed25519VerificationKey2020", "fzz"},
		{"padded base64url value", "Ed25519VerificationKey2020", multibaseU(edRaw) + "="},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			m := did.Method{ID: testLeafDID + "#k1", Type: tc.declaredType, Controller: testLeafDID, PublicKeyMultibase: tc.multibase}
			got, err := bindTestMethod(t, m)
			if err == nil {
				t.Fatalf("Bind returned a %T for %q, want ErrStructural", got, tc.multibase)
			}
			if !errors.Is(err, ErrStructural) {
				t.Errorf("errors.Is(err, ErrStructural) = false for err %v, want true", err)
			}
		})
	}
}

// TestKeyBinder_RejectsUnsupportedMethodType rejects a suite name that declares
// no registered algorithm.
func TestKeyBinder_RejectsUnsupportedMethodType(t *testing.T) {
	t.Parallel()
	_, pub := newKeyPair(t, signature.AlgorithmEdDSA)
	m := did.Method{
		ID: testLeafDID + "#k1", Type: "NonsenseKey2021", Controller: testLeafDID,
		PublicKeyMultibase: multibaseZ(keyMaterial(t, pub, "raw")),
	}
	got, err := bindTestMethod(t, m)
	if err == nil {
		t.Fatalf("Bind returned a %T, want ErrKeyBinding for an unsupported type", got)
	}
	if !errors.Is(err, ErrKeyBinding) {
		t.Errorf("errors.Is(err, ErrKeyBinding) = false for err %v, want true", err)
	}
}

// TestKeyBinder_RejectsUnusableDocuments rejects a nil document, a document
// without the requested key, and a method with no key material.
func TestKeyBinder_RejectsUnusableDocuments(t *testing.T) {
	t.Parallel()
	materialless := did.Method{ID: testLeafDID + "#k1", Type: "EcdsaSecp256k1RecoveryMethod2020", Controller: testLeafDID, BlockchainAccountId: "eip155:1:0x123456789012345678901234567890abcdef00"}
	doc := &did.Document{ID: testLeafDID, VerificationMethod: []did.Method{materialless}}

	cases := []struct {
		name   string
		keyID  string
		doc    *did.Document
		needle string
	}{
		{"nil document", "k1", nil, "nil DID document"},
		{"absent key", "other-key", doc, "key not found"},
		{"method without key material", "k1", doc, "key not found"},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := DocumentKeyBinder{}.Bind(tc.keyID, tc.doc)
			if err == nil {
				t.Fatalf("Bind(%q) returned a %T, want an error", tc.keyID, got)
			}
			if !strings.Contains(err.Error(), tc.needle) {
				t.Errorf("err = %v, want it to mention %q", err, tc.needle)
			}
			if got != nil {
				t.Errorf("bound key = %T, want nil", got)
			}
		})
	}
}

// TestKeyBinder_BlocksAccountIDForOtherSuites binds a method whose declared
// algorithm comes from its CAIP-10 account identifier, and rejects that
// identifier on a suite that cannot carry a blockchain account.
func TestKeyBinder_BlocksAccountIDForOtherSuites(t *testing.T) {
	t.Parallel()
	const account = "eip155:1:0x123456789012345678901234567890abcdef00"
	cases := []struct {
		name    string
		keyAlg  signature.Algorithm
		typ     string
		wantErr bool
	}{
		{"recovery suite with a CAIP-10 account", signature.AlgorithmES256K, "EcdsaSecp256k1RecoveryMethod2020", false},
		{"JWK suite with a CAIP-10 account", signature.AlgorithmES256K, "JsonWebKey2020", false},
		{"Ed25519 suite with a CAIP-10 account", signature.AlgorithmEdDSA, "Ed25519VerificationKey2020", true},
		{"P-256 suite with a CAIP-10 account", signature.AlgorithmES256, "EcdsaSecp256r1VerificationKey2019", true},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			m := materialMethod(t, tc.keyAlg, tc.typ, "", "", nil)
			m.BlockchainAccountId = account
			got, err := bindTestMethod(t, m)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("Bind returned a %T, want ErrKeyBinding", got)
				}
				if !errors.Is(err, ErrKeyBinding) {
					t.Errorf("errors.Is(err, ErrKeyBinding) = false for err %v, want true", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("Bind: got error %v, want the %s key", err, tc.keyAlg.JOSE())
			}
			if alg, _ := signature.AlgorithmForPublicKey(got); alg != tc.keyAlg {
				t.Errorf("bound algorithm = %s, want %s", alg.JOSE(), tc.keyAlg.JOSE())
			}
		})
	}
}

// TestKeyBinder_VerifiesEveryAlgorithm runs the full engine on a fixture whose
// keys use each registered algorithm.
func TestKeyBinder_VerifiesEveryAlgorithm(t *testing.T) {
	t.Parallel()
	for _, alg := range everyAlgorithm {
		alg := alg
		t.Run(alg.JOSE(), func(t *testing.T) {
			t.Parallel()
			f := buildFixtureAlg(t, alg)
			if f.att.Algorithm != alg {
				t.Fatalf("attestation algorithm = %s, want %s", f.att.Algorithm.JOSE(), alg.JOSE())
			}
			res, err := NewEngine().Verify(f.inputs())
			if err != nil {
				t.Fatalf("Verify: %v", err)
			}
			if !res.Valid {
				for _, fl := range res.Failures {
					t.Errorf("failure: check=%v hop=%d err=%v", fl.Check, fl.Hop, fl.Err)
				}
				t.Fatalf("%s fixture reported invalid, want valid", alg.JOSE())
			}
		})
	}
}
