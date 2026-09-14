package commitment

import (
	"errors"
	"testing"
)

func TestSentinels_Distinct(t *testing.T) {
	sentinels := []struct {
		name string
		err  error
	}{
		{"ErrEmptyObjects", ErrEmptyObjects},
		{"ErrNilObject", ErrNilObject},
		{"ErrDuplicateObject", ErrDuplicateObject},
		{"ErrObjectNotCommitted", ErrObjectNotCommitted},
		{"ErrNilCommitment", ErrNilCommitment},
		{"ErrAlgorithmMismatch", ErrAlgorithmMismatch},
		{"ErrEmptyCommitment", ErrEmptyCommitment},
		{"ErrSizeMismatch", ErrSizeMismatch},
		{"ErrUnsortedLeaves", ErrUnsortedLeaves},
		{"ErrDuplicateLeaf", ErrDuplicateLeaf},
		{"ErrRootMismatch", ErrRootMismatch},
		{"ErrInclusionFailed", ErrInclusionFailed},
		{"ErrNotPrefix", ErrNotPrefix},
		{"ErrInvalidRange", ErrInvalidRange},
	}
	for i, a := range sentinels {
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
