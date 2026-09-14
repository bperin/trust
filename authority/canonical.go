package authority

import (
	"errors"

	"github.com/bperin/trust/canonical"
)

// ErrNilAuthority is returned by CanonicalHash and Validate when the
// authority is nil.
var ErrNilAuthority = errors.New("authority: nil authority")

// CanonicalHash returns the authority's identity: the [FIPS 180-4]
// SHA-256 digest of the [RFC 8785] JCS-canonical JSON encoding of the
// authority with Proof.Signature zeroed. Identical content produces an
// identical hash; a single differing byte in any hashed field changes
// the identity.
//
// Proof.Signature is excluded so the identity is stable across
// signing — the digest is what the proof signs. Proof.Algorithm and
// Proof.KeyID remain part of the hashed bytes. The caller's authority
// is not mutated: the signature is zeroed on a shallow copy.
func CanonicalHash(auth *Authority) ([32]byte, error) {
	if auth == nil {
		return [32]byte{}, ErrNilAuthority
	}
	// Hash the unsigned form: project onto a shallow copy with the
	// signature zeroed so the identity is independent of the proof
	// value itself.
	wire := *auth
	wire.Proof.Signature = nil
	return canonical.CanonicalHash(&wire)
}
