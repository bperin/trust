// Package signature provides a unified signature dispatch with a
// canonical Algorithm type that carries both the JOSE string name
// ([RFC 7518] / [RFC 8812]) and COSE int64 label ([RFC 8152] /
// [RFC 9053]) for each registered algorithm. The package-private
// registry maps each Algorithm to sign/verify closures that delegate
// to the trust/crypto/* key implementations. No exported
// registration API exists — the registry is populated by init() in
// each per-algorithm file and is immutable after package
// initialization.
package signature

// Algorithm is a canonical signature algorithm identifier that
// carries both the JOSE string name and COSE int64 label for each
// registered algorithm. It is integer-backed so it can be used with
// real const declarations (Go does not permit const struct values).
// The type is comparable with == and usable as a map key.
//
// Project algorithms: ed25519 [RFC 8037]; [FIPS 186-5], secp256k1
// [SEC 2 v2]; [RFC 6979]; [EIP-2], ecdsa-p256 [FIPS 186-4] (P-256),
// ecdsa-p384 [FIPS 186-4] (P-384), rsa-pss [RFC 8017] (PKCS#1 v2.2,
// PSS), rsa-pkcs1v15 [RFC 8017] §8.2.
type Algorithm int

// Algorithm constants for all supported signature algorithms.
// Consumers reference algorithms by constant, never by bare string.
// JOSE names per [RFC 7518] §3.1, [RFC 8812] §3.1 (ES256K).
// COSE labels per [RFC 8152] §8.1, [RFC 9053] §4.1.
const (
	AlgorithmEdDSA Algorithm = iota + 1
	AlgorithmES256K
	AlgorithmES256
	AlgorithmES384
	AlgorithmPS256
	AlgorithmPS384
	AlgorithmPS512
	AlgorithmRS256
	AlgorithmRS384
	AlgorithmRS512
)

// algorithmInfo holds the JOSE and COSE identifiers for an algorithm.
type algorithmInfo struct {
	jose string
	cose int64
}

// algorithmTable maps each Algorithm constant to its wire-format
// identifiers. This is the single source of truth for JOSE/COSE
// projections. Index 0 is intentionally unused (constants start at
// iota + 1) — the zero Algorithm value represents "unregistered".
var algorithmTable = [...]algorithmInfo{
	AlgorithmEdDSA:  {"EdDSA", -8},
	AlgorithmES256K:  {"ES256K", -47},
	AlgorithmES256:  {"ES256", -7},
	AlgorithmES384:  {"ES384", -35},
	AlgorithmPS256:  {"PS256", -37},
	AlgorithmPS384:  {"PS384", -38},
	AlgorithmPS512:  {"PS512", -39},
	AlgorithmRS256:  {"RS256", -257},
	AlgorithmRS384:  {"RS384", -258},
	AlgorithmRS512:  {"RS512", -259},
}

// JOSE returns the [RFC 7518] / [RFC 8812] JOSE algorithm name for
// this algorithm. It is a value-receiver method so it can be called
// on const Algorithm values (e.g., AlgorithmEdDSA.JOSE()).
// Returns "" for unregistered Algorithm values.
func (a Algorithm) JOSE() string {
	if int(a) < 0 || int(a) >= len(algorithmTable) {
		return ""
	}
	return algorithmTable[a].jose
}

// COSE returns the [RFC 8152] / [RFC 9053] COSE algorithm label for
// this algorithm. It is a value-receiver method so it can be called
// on const Algorithm values (e.g., AlgorithmEdDSA.COSE()).
// Returns 0 for unregistered Algorithm values.
func (a Algorithm) COSE() int64 {
	if int(a) < 0 || int(a) >= len(algorithmTable) {
		return 0
	}
	return algorithmTable[a].cose
}

// AlgorithmForJOSE resolves a [RFC 7518] §3.1 / [RFC 8812] §3.1
// (ES256K) JOSE algorithm string to the canonical Algorithm. Returns
// (_, false) if the string is not a registered algorithm. This lets
// a caller that already has a JWT alg header resolve it without
// re-introducing a mapping table.
func AlgorithmForJOSE(name string) (Algorithm, bool) {
	for i := Algorithm(1); int(i) < len(algorithmTable); i++ {
		if algorithmTable[i].jose == name {
			return i, true
		}
	}
	return 0, false
}

// AlgorithmForCOSE resolves a [RFC 8152] §8.1 / [RFC 9053] §4.1 COSE
// algorithm label to the canonical Algorithm. Returns (_, false) if
// the label is not a registered algorithm. This lets a caller that
// already has a COSE label resolve it without re-introducing a
// mapping table.
func AlgorithmForCOSE(label int64) (Algorithm, bool) {
	for i := Algorithm(1); int(i) < len(algorithmTable); i++ {
		if algorithmTable[i].cose == label {
			return i, true
		}
	}
	return 0, false
}
