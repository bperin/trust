// Package signature provides a unified signature dispatch with a
// canonical Algorithm type carrying the JOSE string name and COSE
// int64 label for each registered algorithm. The registry is
// populated by init() in each per-algorithm file; no exported
// registration API exists.
package signature

// Algorithm is a canonical signature algorithm identifier carrying
// both the JOSE string name and COSE int64 label for a registered
// algorithm. It is integer-backed so it can be used in const
// declarations, compared with ==, and used as a map key.
type Algorithm int

// Supported signature algorithms. JOSE names follow [RFC 7518] and
// [RFC 8812]; COSE labels follow [RFC 8152] and [RFC 9053].
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
// identifiers. Index 0 is unused; the zero Algorithm value
// represents "unregistered".
var algorithmTable = [...]algorithmInfo{
	AlgorithmEdDSA:  {"EdDSA", -8},
	AlgorithmES256K: {"ES256K", -47},
	AlgorithmES256:  {"ES256", -7},
	AlgorithmES384:  {"ES384", -35},
	AlgorithmPS256:  {"PS256", -37},
	AlgorithmPS384:  {"PS384", -38},
	AlgorithmPS512:  {"PS512", -39},
	AlgorithmRS256:  {"RS256", -257},
	AlgorithmRS384:  {"RS384", -258},
	AlgorithmRS512:  {"RS512", -259},
}

// JOSE returns the JOSE algorithm name ([RFC 7518], [RFC 8812]).
// It returns "" for unregistered Algorithm values.
func (a Algorithm) JOSE() string {
	if int(a) < 0 || int(a) >= len(algorithmTable) {
		return ""
	}
	return algorithmTable[a].jose
}

// COSE returns the COSE algorithm label ([RFC 8152], [RFC 9053]).
// It returns 0 for unregistered Algorithm values.
func (a Algorithm) COSE() int64 {
	if int(a) < 0 || int(a) >= len(algorithmTable) {
		return 0
	}
	return algorithmTable[a].cose
}

// AlgorithmForJOSE resolves a JOSE algorithm name to the canonical
// Algorithm. It returns false if the name is not registered.
func AlgorithmForJOSE(name string) (Algorithm, bool) {
	for i := Algorithm(1); int(i) < len(algorithmTable); i++ {
		if algorithmTable[i].jose == name {
			return i, true
		}
	}
	return 0, false
}

// AlgorithmForCOSE resolves a COSE algorithm label to the canonical
// Algorithm. It returns false if the label is not registered.
func AlgorithmForCOSE(label int64) (Algorithm, bool) {
	for i := Algorithm(1); int(i) < len(algorithmTable); i++ {
		if algorithmTable[i].cose == label {
			return i, true
		}
	}
	return 0, false
}
