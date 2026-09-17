package verification

import (
	"crypto"
	stdecdsa "crypto/ecdsa"
	"crypto/elliptic"
	"errors"
	"fmt"
	"math/big"
	"strconv"
	"strings"

	"github.com/bperin/trust/crypto/ecdsa"
	"github.com/bperin/trust/crypto/secp256k1"
	"github.com/bperin/trust/identity/did"
	jwkutil "github.com/bperin/trust/identity/jwk"
	"github.com/bperin/trust/signature"
)

// Encoded public-key material lengths, in bytes. P-256 and secp256k1 share the
// 33-, 64- and 65-byte point forms.
const (
	ed25519Bytes          = 32
	p256CompressedBytes   = 33
	p256CoordinatesBytes  = 64
	p256UncompressedBytes = 65
	p384CompressedBytes   = 49
	p384CoordinatesBytes  = 96
	p384UncompressedBytes = 97
	secp256k1FieldBytes   = 32
)

// ecUncompressedPrefix is the multicodec byte introducing an uncompressed
// curve point.
const ecUncompressedPrefix = 0x04

// suiteTypeSuffix is the repo's verification-method suite name form,
// appended to a JOSE algorithm name.
const suiteTypeSuffix = "VerificationKey2020"

// rsaKeyAlgorithms are the RSA schemes a verification method can declare.
var rsaKeyAlgorithms = []signature.Algorithm{
	signature.AlgorithmPS256,
	signature.AlgorithmPS384,
	signature.AlgorithmPS512,
	signature.AlgorithmRS256,
	signature.AlgorithmRS384,
	signature.AlgorithmRS512,
}

// suiteKeyAlgorithms maps a verification-method suite name to the
// algorithms it declares; an empty list constrains the key material not at all.
var suiteKeyAlgorithms = map[string][]signature.Algorithm{
	"Ed25519VerificationKey2018":        {signature.AlgorithmEdDSA},
	"Ed25519VerificationKey2020":        {signature.AlgorithmEdDSA},
	"EcdsaSecp256k1VerificationKey2019": {signature.AlgorithmES256K},
	"EcdsaSecp256k1RecoveryMethod2020":  {signature.AlgorithmES256K},
	"EcdsaSecp256r1VerificationKey2019": {signature.AlgorithmES256, signature.AlgorithmES384},
	"RsaVerificationKey2018":            rsaKeyAlgorithms,
	"JsonWebKey2020":                    nil,
}

// keyCandidate is one algorithm a piece of key material can encode.
type keyCandidate struct {
	alg signature.Algorithm
	key crypto.PublicKey
}

// bindMethod resolves one verification method's declared algorithm and
// returns the key its material encodes.
func bindMethod(m did.Method) (crypto.PublicKey, error) {
	declared, err := declaredAlgorithms(m)
	if err != nil {
		return nil, err
	}
	if m.PublicKeyMultibase != "" {
		raw, err := decodeMultibase(m.PublicKeyMultibase)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrStructural, err)
		}
		cands, err := candidatesForRawKey(raw)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrStructural, err)
		}
		return selectCandidate(cands, declared, m.Type)
	}
	return bindJWK(m.PublicKeyJWK, m.Type, declared)
}

// declaredAlgorithms returns the algorithms the method's declared type and
// account identifier permit; nil means nothing is declared.
func declaredAlgorithms(m did.Method) ([]signature.Algorithm, error) {
	cands, err := algorithmsForSuiteType(m.Type)
	if err != nil {
		return nil, err
	}
	if m.BlockchainAccountId == "" {
		return cands, nil
	}
	secp := []signature.Algorithm{signature.AlgorithmES256K}
	if len(cands) == 0 {
		return secp, nil
	}
	if !containsAlgorithm(cands, signature.AlgorithmES256K) {
		return nil, fmt.Errorf("%w: suite %q cannot bind a blockchain account", ErrKeyBinding, m.Type)
	}
	return secp, nil
}

// algorithmsForSuiteType resolves a verification-method suite name to the
// algorithms it declares: a known suite name, a bare JOSE name, a decimal
// COSE label, or a JOSE name in the repo's suite-name form.
func algorithmsForSuiteType(typeName string) ([]signature.Algorithm, error) {
	if typeName == "" {
		return nil, nil
	}
	if cands, ok := suiteKeyAlgorithms[typeName]; ok {
		return cands, nil
	}
	if alg, ok := signature.AlgorithmForJOSE(typeName); ok {
		return []signature.Algorithm{alg}, nil
	}
	if label, err := strconv.ParseInt(typeName, 10, 64); err == nil {
		if alg, ok := signature.AlgorithmForCOSE(label); ok {
			return []signature.Algorithm{alg}, nil
		}
	}
	if base, ok := strings.CutSuffix(typeName, suiteTypeSuffix); ok {
		if alg, ok := signature.AlgorithmForJOSE(base); ok {
			return []signature.Algorithm{alg}, nil
		}
	}
	return nil, fmt.Errorf("%w: unsupported verification method type %q", ErrKeyBinding, typeName)
}

// candidatesForRawKey returns every registered algorithm whose trust key
// type the raw bytes encode.
func candidatesForRawKey(raw []byte) ([]keyCandidate, error) {
	var cands []keyCandidate
	add := func(alg signature.Algorithm, key crypto.PublicKey) {
		cands = append(cands, keyCandidate{alg: alg, key: key})
	}
	switch len(raw) {
	case ed25519Bytes:
		if key, err := trustEd25519Pub(raw); err == nil {
			add(signature.AlgorithmEdDSA, key)
		}
	case p256CompressedBytes:
		if key, err := secp256k1.NewPublicKey(raw); err == nil {
			add(signature.AlgorithmES256K, key)
		}
		if key, err := ecdsaKeyForPoint(elliptic.P256(), crypto.SHA256, raw); err == nil {
			add(signature.AlgorithmES256, key)
		}
	case p256CoordinatesBytes:
		if key, err := secp256k1KeyForXY(raw); err == nil {
			add(signature.AlgorithmES256K, key)
		}
		if key, err := ecdsaKeyForPoint(elliptic.P256(), crypto.SHA256, raw); err == nil {
			add(signature.AlgorithmES256, key)
		}
	case p256UncompressedBytes:
		if key, err := secp256k1KeyForUncompressed(raw); err == nil {
			add(signature.AlgorithmES256K, key)
		}
		if key, err := ecdsaKeyForPoint(elliptic.P256(), crypto.SHA256, raw); err == nil {
			add(signature.AlgorithmES256, key)
		}
	case p384CompressedBytes, p384CoordinatesBytes, p384UncompressedBytes:
		if key, err := ecdsaKeyForPoint(elliptic.P384(), crypto.SHA384, raw); err == nil {
			add(signature.AlgorithmES384, key)
		}
	}
	if len(cands) == 0 {
		return nil, fmt.Errorf("no registered algorithm key encodes as %d bytes", len(raw))
	}
	return cands, nil
}

// ecdsaKeyForPoint builds a trust ECDSA public key from an uncompressed,
// compressed, or concatenated-coordinate encoding of a curve point.
func ecdsaKeyForPoint(curve elliptic.Curve, hash crypto.Hash, raw []byte) (crypto.PublicKey, error) {
	field := curve.Params().BitSize / 8
	x, y := curvePointBytes(curve, raw, field)
	if x == nil {
		return nil, fmt.Errorf("ecdsa: %d bytes are not a %s point", len(raw), curve.Params().Name)
	}
	return ecdsa.NewPublicKey(&stdecdsa.PublicKey{Curve: curve, X: x, Y: y}, hash)
}

// curvePointBytes decodes a curve point, rejecting out-of-range and
// off-curve coordinates.
func curvePointBytes(curve elliptic.Curve, raw []byte, field int) (*big.Int, *big.Int) {
	var x, y *big.Int
	switch {
	case len(raw) == 1+2*field && raw[0] == ecUncompressedPrefix:
		x, y = elliptic.Unmarshal(curve, raw)
	case len(raw) == 1+field && (raw[0] == 0x02 || raw[0] == 0x03):
		x, y = elliptic.UnmarshalCompressed(curve, raw)
	case len(raw) == 2*field:
		x, y = new(big.Int).SetBytes(raw[:field]), new(big.Int).SetBytes(raw[field:])
		if !pointInRange(curve, x, y) || !curve.IsOnCurve(x, y) {
			return nil, nil
		}
	}
	if x == nil || y == nil {
		return nil, nil
	}
	if !pointInRange(curve, x, y) {
		return nil, nil
	}
	return x, y
}

// pointInRange reports whether both coordinates are in [0, p-1].
func pointInRange(curve elliptic.Curve, x, y *big.Int) bool {
	p := curve.Params().P
	return x != nil && y != nil && x.Sign() >= 0 && y.Sign() >= 0 && x.Cmp(p) < 0 && y.Cmp(p) < 0
}

// secp256k1KeyForXY builds a trust secp256k1 public key from concatenated
// x||y coordinates, compressing the point for the parser.
func secp256k1KeyForXY(xy []byte) (crypto.PublicKey, error) {
	if len(xy) != 2*secp256k1FieldBytes {
		return nil, errors.New("secp256k1: want 64 coordinate bytes")
	}
	compressed := make([]byte, 1+secp256k1FieldBytes)
	if xy[len(xy)-1]&1 == 0 {
		compressed[0] = 0x02
	} else {
		compressed[0] = 0x03
	}
	copy(compressed[1:], xy[:secp256k1FieldBytes])
	return secp256k1.NewPublicKey(compressed)
}

// secp256k1KeyForUncompressed builds a trust secp256k1 public key from a
// 0x04-prefixed uncompressed point.
func secp256k1KeyForUncompressed(point []byte) (crypto.PublicKey, error) {
	if len(point) != 1+2*secp256k1FieldBytes || point[0] != ecUncompressedPrefix {
		return nil, errors.New("secp256k1: want 65-byte uncompressed point")
	}
	return secp256k1KeyForXY(point[1:])
}

// bindJWK resolves a JWK's kty, crv, and RSA members against the declared
// algorithms and parses the key.
func bindJWK(member map[string]any, typeName string, declared []signature.Algorithm) (crypto.PublicKey, error) {
	cands, err := algorithmsForJWK(member)
	if err != nil {
		return nil, err
	}
	matches := intersectAlgorithms(cands, declared)
	if len(matches) == 0 {
		return nil, fmt.Errorf("%w: verification method %q declares %s, JWK material encodes %s",
			ErrKeyBinding, typeName, algorithmList(declared), algorithmList(cands))
	}
	if len(matches) > 1 {
		return nil, fmt.Errorf("%w: JWK material fits %s; declare the algorithm", ErrKeyBinding, algorithmList(matches))
	}
	key, err := jwkutil.Unmarshal(jwkWithAlg(member, matches[0]))
	if err != nil {
		return nil, fmt.Errorf("%w: jwk: %v", ErrStructural, err)
	}
	got, err := signature.AlgorithmForPublicKey(key)
	if err != nil || got != matches[0] {
		return nil, fmt.Errorf("%w: jwk material resolves to %s, want %s",
			ErrKeyBinding, algorithmName(got), algorithmName(matches[0]))
	}
	return key, nil
}

// algorithmsForJWK returns the algorithms a JWK's kty, crv, and alg
// members declare.
func algorithmsForJWK(member map[string]any) ([]signature.Algorithm, error) {
	kty, _ := member["kty"].(string)
	crv, _ := member["crv"].(string)
	name, hasAlg := member["alg"].(string)

	one := func(alg signature.Algorithm) ([]signature.Algorithm, error) {
		if hasAlg && name != alg.JOSE() {
			return nil, fmt.Errorf("%w: JWK alg %q contradicts kty %q crv %q", ErrKeyBinding, name, kty, crv)
		}
		return []signature.Algorithm{alg}, nil
	}
	switch kty {
	case "OKP":
		if crv != "Ed25519" {
			return nil, fmt.Errorf("%w: JWK crv %q is not a signing key", ErrKeyBinding, crv)
		}
		return one(signature.AlgorithmEdDSA)
	case "EC":
		switch crv {
		case "P-256":
			return one(signature.AlgorithmES256)
		case "P-384":
			return one(signature.AlgorithmES384)
		case "secp256k1":
			return one(signature.AlgorithmES256K)
		default:
			return nil, fmt.Errorf("%w: JWK crv %q is unsupported", ErrKeyBinding, crv)
		}
	case "RSA":
		if !hasAlg {
			return rsaKeyAlgorithms, nil
		}
		alg, ok := signature.AlgorithmForJOSE(name)
		if !ok || !containsAlgorithm(rsaKeyAlgorithms, alg) {
			return nil, fmt.Errorf("%w: JWK alg %q is not an RSA signing algorithm", ErrKeyBinding, name)
		}
		return []signature.Algorithm{alg}, nil
	default:
		return nil, fmt.Errorf("%w: JWK kty %q is unsupported", ErrKeyBinding, kty)
	}
}

// jwkWithAlg returns a JWK carrying the resolved alg, leaving the original
// map untouched.
func jwkWithAlg(member map[string]any, alg signature.Algorithm) map[string]any {
	if name, ok := member["alg"].(string); ok && name != "" {
		return member
	}
	out := make(map[string]any, len(member)+1)
	for k, v := range member {
		out[k] = v
	}
	out["alg"] = alg.JOSE()
	return out
}

// selectCandidate returns the single key candidate the declared
// algorithms permit; a declaration no candidate satisfies is a contradiction.
func selectCandidate(cands []keyCandidate, declared []signature.Algorithm, typeName string) (crypto.PublicKey, error) {
	var matches []keyCandidate
	for _, c := range cands {
		if len(declared) == 0 || containsAlgorithm(declared, c.alg) {
			matches = append(matches, c)
		}
	}
	switch len(matches) {
	case 1:
		return matches[0].key, nil
	case 0:
		return nil, fmt.Errorf("%w: verification method %q declares %s, key material encodes %s",
			ErrKeyBinding, typeName, algorithmList(declared), candidateList(cands))
	default:
		return nil, fmt.Errorf("%w: key material fits %s; declare the algorithm", ErrKeyBinding, candidateList(matches))
	}
}

// intersectAlgorithms returns the candidates also permitted by declared,
// treating an empty declared list as no constraint.
func intersectAlgorithms(cands, declared []signature.Algorithm) []signature.Algorithm {
	var out []signature.Algorithm
	for _, c := range cands {
		if len(declared) == 0 || containsAlgorithm(declared, c) {
			out = append(out, c)
		}
	}
	return out
}

// containsAlgorithm reports whether list includes want.
func containsAlgorithm(list []signature.Algorithm, want signature.Algorithm) bool {
	for _, a := range list {
		if a == want {
			return true
		}
	}
	return false
}

// candidateList renders key candidates for an error message.
func candidateList(cands []keyCandidate) string {
	algs := make([]signature.Algorithm, 0, len(cands))
	for _, c := range cands {
		algs = append(algs, c.alg)
	}
	return algorithmList(algs)
}

// algorithmList renders algorithms for an error message.
func algorithmList(algs []signature.Algorithm) string {
	if len(algs) == 0 {
		return "no registered algorithm"
	}
	names := make([]string, 0, len(algs))
	for _, a := range algs {
		names = append(names, algorithmName(a))
	}
	return strings.Join(names, "|")
}

// algorithmName renders an algorithm, falling back to its ordinal.
func algorithmName(a signature.Algorithm) string {
	if name := a.JOSE(); name != "" {
		return name
	}
	return fmt.Sprintf("alg#%d", int(a))
}
