package evidence

import (
	"errors"

	"github.com/bperin/trust/canonical"
)

// ErrNilEvidence is returned by CanonicalHash and ValidateEvidence when
// the evidence is nil.
var ErrNilEvidence = errors.New("evidence: nil evidence")

// CanonicalHash returns the evidence's identity: the [FIPS 180-4]
// SHA-256 digest of the [RFC 8785] JCS-canonical JSON encoding of the
// entire evidence — no field is zeroed or excluded. Identical content
// produces an identical hash; a single differing byte in any field
// changes the identity.
//
// CanonicalHash is distinct from Evidence.ContentHash: ContentHash is
// the stored digest of the external material the evidence references,
// while CanonicalHash is the computed identity of the Evidence value
// itself — ContentHash is one of the fields that identity covers.
func CanonicalHash(ev *Evidence) ([32]byte, error) {
	if ev == nil {
		return [32]byte{}, ErrNilEvidence
	}
	return canonical.CanonicalHash(ev)
}
