package signature

import (
	"strconv"
	"testing"
)

// TestAlgorithmJOSEProjections verifies that every Algorithm constant
// projects to the correct JOSE string name per [RFC 7518] §3.1 and
// [RFC 8812] §3.1 (ES256K).
func TestAlgorithmJOSEProjections(t *testing.T) {
	tests := []struct {
		name string
		alg  Algorithm
		jose string
	}{
		{"EdDSA", AlgorithmEdDSA, "EdDSA"},
		{"ES256K", AlgorithmES256K, "ES256K"},
		{"ES256", AlgorithmES256, "ES256"},
		{"ES384", AlgorithmES384, "ES384"},
		{"PS256", AlgorithmPS256, "PS256"},
		{"PS384", AlgorithmPS384, "PS384"},
		{"PS512", AlgorithmPS512, "PS512"},
		{"RS256", AlgorithmRS256, "RS256"},
		{"RS384", AlgorithmRS384, "RS384"},
		{"RS512", AlgorithmRS512, "RS512"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.alg.JOSE()
			if got != tt.jose {
				t.Errorf("%s.JOSE() = %q, want %q", tt.name, got, tt.jose)
			}
		})
	}
}

// TestAlgorithmCOSEProjections verifies that every Algorithm constant
// projects to the correct COSE int64 label per [RFC 8152] §8.1 and
// [RFC 9053] §4.1.
func TestAlgorithmCOSEProjections(t *testing.T) {
	tests := []struct {
		name string
		alg  Algorithm
		cose int64
	}{
		{"EdDSA", AlgorithmEdDSA, -8},
		{"ES256K", AlgorithmES256K, -47},
		{"ES256", AlgorithmES256, -7},
		{"ES384", AlgorithmES384, -35},
		{"PS256", AlgorithmPS256, -37},
		{"PS384", AlgorithmPS384, -38},
		{"PS512", AlgorithmPS512, -39},
		{"RS256", AlgorithmRS256, -257},
		{"RS384", AlgorithmRS384, -258},
		{"RS512", AlgorithmRS512, -259},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.alg.COSE()
			if got != tt.cose {
				t.Errorf("%s.COSE() = %d, want %d", tt.name, got, tt.cose)
			}
		})
	}
}

// TestAlgorithmForJOSE verifies the inverse parsing from JOSE string
// to canonical Algorithm.
func TestAlgorithmForJOSE(t *testing.T) {
	tests := []struct {
		jose string
		want Algorithm
		ok   bool
	}{
		{"EdDSA", AlgorithmEdDSA, true},
		{"ES256K", AlgorithmES256K, true},
		{"ES256", AlgorithmES256, true},
		{"ES384", AlgorithmES384, true},
		{"PS256", AlgorithmPS256, true},
		{"PS384", AlgorithmPS384, true},
		{"PS512", AlgorithmPS512, true},
		{"RS256", AlgorithmRS256, true},
		{"RS384", AlgorithmRS384, true},
		{"RS512", AlgorithmRS512, true},
		{"nonsense", 0, false},
		{"", 0, false},
	}

	for _, tt := range tests {
		t.Run(tt.jose, func(t *testing.T) {
			got, ok := AlgorithmForJOSE(tt.jose)
			if ok != tt.ok {
				t.Errorf("AlgorithmForJOSE(%q) ok = %v, want %v", tt.jose, ok, tt.ok)
			}
			if ok && got != tt.want {
				t.Errorf("AlgorithmForJOSE(%q) = %v, want %v", tt.jose, got, tt.want)
			}
		})
	}
}

// TestAlgorithmForCOSE verifies the inverse parsing from COSE label
// to canonical Algorithm.
func TestAlgorithmForCOSE(t *testing.T) {
	tests := []struct {
		cose int64
		want Algorithm
		ok   bool
	}{
		{-8, AlgorithmEdDSA, true},
		{-47, AlgorithmES256K, true},
		{-7, AlgorithmES256, true},
		{-35, AlgorithmES384, true},
		{-37, AlgorithmPS256, true},
		{-38, AlgorithmPS384, true},
		{-39, AlgorithmPS512, true},
		{-257, AlgorithmRS256, true},
		{-258, AlgorithmRS384, true},
		{-259, AlgorithmRS512, true},
		{999, 0, false},
		{0, 0, false},
	}

	for _, tt := range tests {
		t.Run(strconv.FormatInt(tt.cose, 10), func(t *testing.T) {
			got, ok := AlgorithmForCOSE(tt.cose)
			if ok != tt.ok {
				t.Errorf("AlgorithmForCOSE(%d) ok = %v, want %v", tt.cose, ok, tt.ok)
			}
			if ok && got != tt.want {
				t.Errorf("AlgorithmForCOSE(%d) = %v, want %v", tt.cose, got, tt.want)
			}
		})
	}
}

// TestAlgorithmRoundTrip verifies that every Algorithm's JOSE and COSE
// projections round-trip back through AlgorithmForJOSE and
// AlgorithmForCOSE.
func TestAlgorithmRoundTrip(t *testing.T) {
	for alg := Algorithm(1); int(alg) < len(algorithmTable); alg++ {
		jose := alg.JOSE()
		cose := alg.COSE()

		fromJOSE, ok := AlgorithmForJOSE(jose)
		if !ok || fromJOSE != alg {
			t.Errorf("JOSE round-trip failed: %s -> %v (ok=%v), want %v", jose, fromJOSE, ok, alg)
		}

		fromCOSE, ok := AlgorithmForCOSE(cose)
		if !ok || fromCOSE != alg {
			t.Errorf("COSE round-trip failed: %d -> %v (ok=%v), want %v", cose, fromCOSE, ok, alg)
		}
	}
}

// TestAlgorithmMapKey verifies that Algorithm is usable as a map key.
func TestAlgorithmMapKey(t *testing.T) {
	m := make(map[Algorithm]string)
	m[AlgorithmEdDSA] = "test"
	if m[AlgorithmEdDSA] != "test" {
		t.Error("Algorithm is not usable as a map key")
	}
}

// TestAlgorithmComparable verifies that Algorithm is comparable with ==.
func TestAlgorithmComparable(t *testing.T) {
	if AlgorithmEdDSA != AlgorithmEdDSA {
		t.Error("Algorithm is not comparable with ==")
	}
	if AlgorithmEdDSA == AlgorithmES256K {
		t.Error("different Algorithm constants should not be equal")
	}
}
