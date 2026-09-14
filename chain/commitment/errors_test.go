package commitment

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestSentinels_DistinctAndPrefixed(t *testing.T) {
	sentinels := []struct {
		name string
		err  error
	}{
		{"ErrNilAnchor", ErrNilAnchor},
		{"ErrNilWallet", ErrNilWallet},
		{"ErrInvalidAnchor", ErrInvalidAnchor},
		{"ErrMissingTxParams", ErrMissingTxParams},
		{"ErrMalformedReceipt", ErrMalformedReceipt},
		{"ErrChainIDMismatch", ErrChainIDMismatch},
		{"ErrNotConfirmed", ErrNotConfirmed},
		{"ErrRootMismatch", ErrRootMismatch},
		{"ErrBadSignature", ErrBadSignature},
		{"ErrRootGetterFailed", ErrRootGetterFailed},
	}
	for i, a := range sentinels {
		if !strings.HasPrefix(a.err.Error(), "commitment:") {
			t.Errorf("%s.Error() = %q, want prefix %q", a.name, a.err.Error(), "commitment:")
		}
		if !errors.Is(a.err, a.err) {
			t.Errorf("errors.Is(%s, %s) = false, want true", a.name, a.name)
		}
		for j, b := range sentinels {
			if i == j {
				continue
			}
			if errors.Is(a.err, b.err) {
				t.Errorf("errors.Is(%s, %s) = true, want false", a.name, b.name)
			}
		}
	}
}

func TestSentinels_WrappedMatch(t *testing.T) {
	wrapped := fmt.Errorf("commitment: boundary: %w", ErrInvalidAnchor)
	if !errors.Is(wrapped, ErrInvalidAnchor) {
		t.Error("errors.Is(wrapped, ErrInvalidAnchor) = false, want true")
	}
	if errors.Is(wrapped, ErrNilAnchor) {
		t.Error("errors.Is(wrapped, ErrNilAnchor) = true, want false")
	}
}
