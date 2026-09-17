package signature

import (
	"crypto"
	stdecdsa "crypto/ecdsa"
	"crypto/elliptic"
	stdrsa "crypto/rsa"
	"encoding/asn1"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bperin/trust/crypto/ecdsa"
	"github.com/bperin/trust/crypto/ed25519"
	"github.com/bperin/trust/crypto/rsa"
	"github.com/bperin/trust/crypto/secp256k1"
)

// Wycheproof suites are committed under crypto/*/testdata for the primitive
// wrappers. The dispatch layer is what callers actually use, so the same
// vectors are replayed through Verify(alg, key, sig, msg) here.
//
// Vector: [Wycheproof] ed25519_test.json, ecdsa_secp256r1_sha256_test.json,
// ecdsa_secp384r1_sha384_test.json, ecdsa_secp256k1_sha256_test.json,
// rsa_pss_*_test.json, rsa_signature_*_test.json.
const (
	wpEd25519File   = "../crypto/ed25519/testdata/ed25519_test.json"
	wpP256File      = "../crypto/ecdsa/testdata/ecdsa_secp256r1_sha256_test.json"
	wpP384File      = "../crypto/ecdsa/testdata/ecdsa_secp384r1_sha384_test.json"
	wpK256File      = "../crypto/secp256k1/testdata/ecdsa_secp256k1_sha256_test.json"
	wpRSAPathPrefix = "../crypto/rsa/testdata"
)

// wpSuite is the subset of a Wycheproof JSON file this harness reads.
type wpSuite struct {
	Algorithm     string    `json:"algorithm"`
	NumberOfTests int       `json:"numberOfTests"`
	TestGroups    []wpGroup `json:"testGroups"`
}

type wpGroup struct {
	KeySize   int      `json:"keySize"`
	SHA       string   `json:"sha"`
	MgfSHA    string   `json:"mgfSha"`
	SLen      int      `json:"sLen"`
	PublicKey wpKey    `json:"publicKey"`
	Tests     []wpTest `json:"tests"`
}

type wpKey struct {
	PK           string `json:"pk"`
	Uncompressed string `json:"uncompressed"`
	Modulus      string `json:"modulus"`
	Exponent     string `json:"publicExponent"`
}

type wpTest struct {
	TcID    int      `json:"tcId"`
	Comment string   `json:"comment"`
	Flags   []string `json:"flags"`
	Msg     string   `json:"msg"`
	Sig     string   `json:"sig"`
	Result  string   `json:"result"`
}

// wpCase is one Wycheproof vector expressed against the dispatch layer.
type wpCase struct {
	name string
	tcID int
	alg  Algorithm
	key  crypto.PublicKey
	msg  []byte
	sig  []byte
	// result is the Wycheproof expectation: valid, acceptable, or invalid.
	result string
	// want is the Verify result expected once the dispatch layer's own wire
	// rules are applied; they are stricter than Wycheproof for ES256K.
	want bool
	// note explains a want that deviates from result.
	note string
	// skipped records why the case cannot reach Verify, empty when it can.
	skipped string
}

// wpHalfN is n/2 for secp256k1, the [EIP-2] low-s boundary.
var wpHalfN = new(big.Int).Rsh(secp256k1OrderN, 1)

// wpNewCase builds a dispatch case for one Wycheproof test.
func wpNewCase(t *testing.T, alg Algorithm, key crypto.PublicKey, tc wpTest, rawRS bool) wpCase {
	t.Helper()
	c := wpCase{
		name:   wpName(tc),
		tcID:   tc.TcID,
		alg:    alg,
		key:    key,
		msg:    wpHex(t, "msg", tc.Msg),
		result: tc.Result,
		want:   tc.Result != "invalid",
	}
	sig := wpHex(t, "sig", tc.Sig)
	if rawRS {
		rs, why := wpRSFromDER(sig)
		if rs == nil {
			c.skipped = why
			return c
		}
		sig = rs
		// ES256K rejects high-s per [EIP-2]; Wycheproof calls the malleated
		// pair valid, so the dispatch-layer expectation is the stricter one.
		if new(big.Int).SetBytes(sig[32:]).Cmp(wpHalfN) > 0 {
			c.want = false
			c.note = "high-s is malleable and rejected per [EIP-2]"
		}
	}
	c.sig = sig
	return c
}

// wpLoad reads a Wycheproof file, failing when it is absent.
func wpLoad(t *testing.T, path string) wpSuite {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("wycheproof vectors missing at %s: %v", path, err)
	}
	var suite wpSuite
	if err := json.Unmarshal(data, &suite); err != nil {
		t.Fatalf("unmarshal %s: %v", path, err)
	}
	if suite.NumberOfTests <= 0 {
		t.Fatalf("%s: numberOfTests = %d, want a positive count", path, suite.NumberOfTests)
	}
	return suite
}

// wpName renders a subtest name from a Wycheproof test case.
func wpName(tc wpTest) string {
	comment := strings.NewReplacer(" ", "_", "/", "_", "(", "", ")", "", ",", "", ":", "").Replace(tc.Comment)
	if comment == "" {
		comment = "untitled"
	}
	return fmt.Sprintf("tc%d_%s", tc.TcID, comment)
}

// wpHex decodes a Wycheproof hex field, failing the test on bad input.
func wpHex(t *testing.T, what, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("decode %s (%q): %v", what, s, err)
	}
	return b
}

// wpRSFromDER converts a canonical DER ECDSA-Sig-Value into the 64-byte r||s
// form ES256K carries, or explains why the encoding cannot be converted.
func wpRSFromDER(derBytes []byte) ([]byte, string) {
	var value struct{ R, S *big.Int }
	rest, err := asn1.Unmarshal(derBytes, &value)
	if err != nil {
		return nil, "not decodable as ECDSA-Sig-Value"
	}
	if len(rest) != 0 {
		return nil, "trailing bytes after ECDSA-Sig-Value"
	}
	if value.R == nil || value.S == nil || value.R.Sign() <= 0 || value.S.Sign() <= 0 {
		return nil, "non-positive scalar"
	}
	if value.R.Cmp(secp256k1OrderN) >= 0 || value.S.Cmp(secp256k1OrderN) >= 0 {
		return nil, "scalar at or above the secp256k1 order"
	}
	reencoded, err := asn1.Marshal(value)
	if err != nil {
		return nil, "cannot re-encode"
	}
	if string(reencoded) != string(derBytes) {
		return nil, "non-canonical DER"
	}
	r, s := value.R.Bytes(), value.S.Bytes()
	if len(r) > 32 || len(s) > 32 {
		return nil, "scalar wider than 32 bytes"
	}
	out := make([]byte, 64)
	copy(out[32-len(r):32], r)
	copy(out[64-len(s):], s)
	return out, ""
}

// wpEd25519Cases reads the EdDSA suite.
func wpEd25519Cases(t *testing.T) []wpCase {
	t.Helper()
	var cases []wpCase
	for _, group := range wpLoad(t, wpEd25519File).TestGroups {
		pub, err := ed25519.NewPublicKey(wpHex(t, "publicKey.pk", group.PublicKey.PK))
		if err != nil {
			continue // groups carrying deliberately unparseable keys
		}
		for _, tc := range group.Tests {
			cases = append(cases, wpNewCase(t, AlgorithmEdDSA, pub, tc, false))
		}
	}
	return cases
}

// wpECCases reads an ECDSA suite for one NIST curve.
func wpECCases(t *testing.T, path string, curve elliptic.Curve) []wpCase {
	t.Helper()
	var cases []wpCase
	for _, group := range wpLoad(t, path).TestGroups {
		x, y := elliptic.Unmarshal(curve, wpHex(t, "publicKey.uncompressed", group.PublicKey.Uncompressed))
		if x == nil {
			continue // groups carrying deliberately unparseable keys
		}
		hash, ok := wpHashFor(group.SHA)
		if !ok {
			continue
		}
		pub, err := ecdsa.NewPublicKey(&stdecdsa.PublicKey{Curve: curve, X: x, Y: y}, hash)
		if err != nil {
			continue
		}
		alg, err := AlgorithmForPublicKey(pub)
		if err != nil {
			continue
		}
		for _, tc := range group.Tests {
			cases = append(cases, wpNewCase(t, alg, pub, tc, false))
		}
	}
	return cases
}

// wpSecp256k1Cases reads the secp256k1 SHA-256 suite.
func wpSecp256k1Cases(t *testing.T) []wpCase {
	t.Helper()
	var cases []wpCase
	for _, group := range wpLoad(t, wpK256File).TestGroups {
		pub := wpSecp256k1Key(t, group)
		if pub == nil {
			continue
		}
		for _, tc := range group.Tests {
			cases = append(cases, wpNewCase(t, AlgorithmES256K, pub, tc, true))
		}
	}
	return cases
}

// wpSecp256k1Key decodes a group's uncompressed point into the trust key type.
func wpSecp256k1Key(t *testing.T, group wpGroup) *secp256k1.PublicKey {
	t.Helper()
	raw := wpHex(t, "publicKey.uncompressed", group.PublicKey.Uncompressed)
	if len(raw) != 65 || raw[0] != 0x04 {
		return nil
	}
	prefix := byte(0x02)
	if raw[64]&1 == 1 {
		prefix = 0x03
	}
	pub, err := secp256k1.NewPublicKey(append([]byte{prefix}, raw[1:33]...))
	if err != nil {
		return nil
	}
	return pub
}

// wpRSACases reads the RSA suites, filtering to the key sizes and PSS
// parameters the trust wrappers bind.
func wpRSACases(t *testing.T, dir, pattern string, pss bool) []wpCase {
	t.Helper()
	paths, err := filepath.Glob(filepath.Join(dir, pattern))
	if err != nil {
		t.Fatalf("glob %s in %s: %v", pattern, dir, err)
	}
	if len(paths) == 0 {
		t.Fatalf("no wycheproof files matching %s in %s", pattern, dir)
	}
	var cases []wpCase
	for _, path := range paths {
		for _, group := range wpLoad(t, path).TestGroups {
			hash, ok := wpHashFor(group.SHA)
			if !ok || group.KeySize < 2048 {
				continue
			}
			if pss && (group.SLen != hash.Size() || (group.MgfSHA != "" && group.MgfSHA != group.SHA)) {
				continue // salt or MGF hash the bound PSS parameters do not carry
			}
			stdPub := &stdrsa.PublicKey{
				N: new(big.Int).SetBytes(wpHex(t, "publicKey.modulus", group.PublicKey.Modulus)),
				E: int(new(big.Int).SetBytes(wpHex(t, "publicKey.publicExponent", group.PublicKey.Exponent)).Int64()),
			}
			var pub crypto.PublicKey
			var err error
			if pss {
				pub, err = rsa.NewPSSPublicKey(stdPub, hash)
			} else {
				pub, err = rsa.NewPKCS1PublicKey(stdPub, hash)
			}
			if err != nil {
				continue
			}
			alg, err := AlgorithmForPublicKey(pub)
			if err != nil {
				continue
			}
			for _, tc := range group.Tests {
				cases = append(cases, wpNewCase(t, alg, pub, tc, false))
			}
		}
	}
	return cases
}

// wpHashFor maps a Wycheproof hash name to a crypto.Hash.
func wpHashFor(name string) (crypto.Hash, bool) {
	switch name {
	case "SHA-256":
		return crypto.SHA256, true
	case "SHA-384":
		return crypto.SHA384, true
	case "SHA-512":
		return crypto.SHA512, true
	default:
		return 0, false
	}
}

// TestWycheproofThroughDispatch replays every committed Wycheproof signature
// suite through the dispatch layer.
func TestWycheproofThroughDispatch(t *testing.T) {
	t.Parallel()

	suites := []struct {
		name  string
		cases func(t *testing.T) []wpCase
	}{
		{"EdDSA", wpEd25519Cases},
		{"ES256", func(t *testing.T) []wpCase { return wpECCases(t, wpP256File, elliptic.P256()) }},
		{"ES384", func(t *testing.T) []wpCase { return wpECCases(t, wpP384File, elliptic.P384()) }},
		{"ES256K", wpSecp256k1Cases},
		{"RSA-PSS", func(t *testing.T) []wpCase { return wpRSACases(t, wpRSAPathPrefix, "rsa_pss_*_test.json", true) }},
		{"RSA-PKCS1", func(t *testing.T) []wpCase {
			return wpRSACases(t, wpRSAPathPrefix, "rsa_signature_*_test.json", false)
		}},
	}

	for _, suite := range suites {
		t.Run(suite.name, func(t *testing.T) {
			cases := suite.cases(t)
			if len(cases) == 0 {
				t.Fatalf("%s: no wycheproof case reached the dispatch layer", suite.name)
			}
			var ran, rejected, unconverted int
			for _, c := range cases {
				if c.skipped != "" {
					unconverted++
					if c.result == "valid" {
						t.Errorf("%s %s: valid vector cannot be expressed in the %s wire format: %s",
							suite.name, c.name, c.alg.JOSE(), c.skipped)
					}
					continue
				}
				ran++
				ok, err := Verify(c.alg, c.key, c.sig, c.msg)
				switch c.result {
				case "valid", "invalid":
					if ok != c.want {
						t.Errorf("%s %s: Verify(%s) = %v, want %v [flags/result %q]%s",
							suite.name, c.name, c.alg.JOSE(), ok, c.want, c.result, c.suffix())
					}
					if err != nil {
						t.Errorf("%s %s: Verify(%s) returned error %v with ok=%v, want the (result, nil) contract",
							suite.name, c.name, c.alg.JOSE(), err, ok)
					}
					if !ok {
						rejected++
					}
				case "acceptable":
					if err != nil {
						t.Errorf("%s %s: Verify(%s) returned error %v for an acceptable vector",
							suite.name, c.name, c.alg.JOSE(), err)
					}
				default:
					t.Errorf("%s %s: unknown result %q", suite.name, c.name, c.result)
				}
			}
			if ran == 0 {
				t.Fatalf("%s: every case was filtered out, nothing reached Verify", suite.name)
			}
			if rejected == 0 {
				t.Fatalf("%s: no invalid vector was exercised", suite.name)
			}
			t.Logf("%s: %d vectors ran through Verify, %d rejected, %d not expressible in the wire format",
				suite.name, ran, rejected, unconverted)
		})
	}
}

// suffix renders the deviation note for a failure message.
func (c wpCase) suffix() string {
	if c.note == "" {
		return ""
	}
	return " — " + c.note
}
