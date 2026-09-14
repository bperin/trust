package claim

import (
	"errors"

	"github.com/bperin/trust/canonical"
)

// ErrNilClaim is returned by CanonicalHash and Validate when the claim
// is nil.
var ErrNilClaim = errors.New("claim: nil claim")

// CanonicalHash returns the claim's identity: the [FIPS 180-4] SHA-256
// digest of the [RFC 8785] JCS-canonical JSON encoding of the entire
// claim. No field is zeroed — the whole struct is the identity.
// Identical logical claims produce identical hashes regardless of
// construction order; a single differing byte in any field changes the
// identity.
func CanonicalHash(c *Claim) ([32]byte, error) {
	if c == nil {
		return [32]byte{}, ErrNilClaim
	}
	return canonical.CanonicalHash(c)
}
