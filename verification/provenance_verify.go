package verification

import (
	"crypto/subtle"
	"encoding/hex"
	"fmt"
)

// VerifyProvenance rebuilds the trace from in and requires link-for-link equality with prov, else ErrProvenanceMismatch.
func VerifyProvenance(prov *Provenance, in Inputs) error {
	if prov == nil {
		return ErrNilProvenance
	}
	expected, err := BuildProvenance(in)
	if err != nil {
		return err
	}
	if len(prov.Links) != len(expected.Links) {
		return fmt.Errorf("verification: link count %d != %d: %w",
			len(prov.Links), len(expected.Links), ErrProvenanceMismatch)
	}
	for i := range expected.Links {
		if !linkEqual(prov.Links[i], expected.Links[i]) {
			return fmt.Errorf("verification: link %d: %w", i, ErrProvenanceMismatch)
		}
	}
	return nil
}

// linkEqual reports whether two links are field-for-field identical.
func linkEqual(a, b Link) bool {
	return a.Kind == b.Kind &&
		refEqual(a.Ref, b.Ref) &&
		refEqual(a.Subject, b.Subject) &&
		refEqual(a.KeyID, b.KeyID) &&
		refEqual(a.Parent, b.Parent)
}

// refEqual compares refs in constant time — hex refs as decoded bytes, others raw.
func refEqual(a, b string) bool {
	da, errA := hex.DecodeString(a)
	db, errB := hex.DecodeString(b)
	if errA == nil && errB == nil {
		return subtle.ConstantTimeCompare(da, db) == 1
	}
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}
