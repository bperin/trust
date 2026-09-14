package evidence

import (
	"errors"
	"testing"
)

// TestValidateEvidence exercises every structural rejection case and the
// valid case. Every assertion goes through errors.Is against the
// package's sentinel errors.
func TestValidateEvidence(t *testing.T) {
	t.Parallel()

	withIdentifier := func(e *Evidence) { e.Identifier = "" }
	withNilHash := func(e *Evidence) { e.ContentHash = nil }
	withEmptyHash := func(e *Evidence) { e.ContentHash = []byte{} }
	withShortHash := func(e *Evidence) { e.ContentHash = make([]byte, 16) }
	withLongHash := func(e *Evidence) { e.ContentHash = make([]byte, 64) }
	withMediaType := func(e *Evidence) { e.MediaType = "" }
	withLocator := func(e *Evidence) { e.Locator = "" }

	mutated := func(mut func(*Evidence)) *Evidence {
		e := testEvidence()
		mut(e)
		return e
	}

	cases := []struct {
		name    string
		ev      *Evidence
		wantErr error
	}{
		{"nil evidence", nil, ErrNilEvidence},
		{"empty identifier", mutated(withIdentifier), ErrEmptyIdentifier},
		{"nil content hash", mutated(withNilHash), ErrNilContentHash},
		{"empty content hash", mutated(withEmptyHash), ErrEmptyContentHash},
		{"short content hash (16)", mutated(withShortHash), ErrContentHashLength},
		{"long content hash (64)", mutated(withLongHash), ErrContentHashLength},
		{"empty media type", mutated(withMediaType), ErrEmptyMediaType},
		{"empty locator", mutated(withLocator), ErrEmptyLocator},
		{"valid evidence", testEvidence(), nil},
		{"valid evidence, no metadata", func() *Evidence {
			e := testEvidence()
			e.Metadata = nil
			return e
		}(), nil},
		{"valid evidence, zero provenance", func() *Evidence {
			e := testEvidence()
			e.Provenance = Provenance{}
			return e
		}(), nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := ValidateEvidence(tc.ev)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("ValidateEvidence: got err %v, want %v", err, tc.wantErr)
			}
		})
	}
}
