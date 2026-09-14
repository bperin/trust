package wallet

import (
	"encoding/hex"
	"testing"
)

// hexDecode is a test helper that panics on invalid hex so test
// vectors fail loudly rather than silently passing with a nil slice.
func hexDecode(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("hexDecode(%q): %v", s, err)
	}
	return b
}
