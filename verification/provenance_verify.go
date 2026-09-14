package verification

import (
	"crypto/subtle"
	"encoding/hex"
	"fmt"
)

// VerifyProvenance rebuilds the expected provenance trace from in and
// requires link-for-link equality — kind, ref, subject, key ID,
// parent, count, and order — with the transported prov. Any
// divergence returns an error wrapping ErrProvenanceMismatch; a nil
// prov returns ErrNilProvenance. Refs compare in constant time.
func VerifyProvenance(prov *Provenance, in Inputs) error {
	if prov == nil {
		return ErrNilProvenance
	}
	expected, err := BuildProvenance(in)
	if err != nil {
		return err
	}
	if len(prov.Links) != len(expected.Links) {
		return fmt.Errorf("verification: %w: got %d links, want %d", ErrProvenanceMismatch, len(prov.Links), len(expected.Links))
	}
	for i := range expected.Links {
		if err := compareLinks(prov.Links[i], expected.Links[i]); err != nil {
			return err
		}
	}
	return nil
}

// compareRefs compares two refs in constant time. Hex canonical-hash
// refs compare on their decoded bytes; non-hex refs — e.g. identity
// DIDs — compare as raw strings.
func compareRefs(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	ab, errA := hex.DecodeString(a)
	bb, errB := hex.DecodeString(b)
	if errA != nil || errB != nil {
		return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
	}
	return subtle.ConstantTimeCompare(ab, bb) == 1
}

// compareReports reports a provenance mismatch when the two links
// differ in any field.
func compareLinks(got, want Link) error {
	if got.Kind != want.Kind ||
		got.Subject != want.Subject ||
		got.KeyID != want.KeyID ||
		!compareRefs(got.Ref, want.Ref) ||
		!compareRefs(got.Parent, want.Parent) {
		return fmt.Errorf("verification: %w: link %d differs", ErrProvenanceMismatch, want.Kind)
	}
	return nil
}
