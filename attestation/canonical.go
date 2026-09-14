package attestation

import (
	"errors"

	"github.com/bperin/trust/canonical"
)

// ErrNilAttestation is returned by CanonicalHash and Validate when the
// attestation is nil.
var ErrNilAttestation = errors.New("attestation: nil attestation")

// CanonicalHash returns the attestation's identity: the [FIPS 180-4]
// SHA-256 digest of the [RFC 8785] JCS-canonical JSON encoding of the
// attestation with Signature zeroed. Identical content produces an
// identical hash; a single differing byte in any hashed field changes
// the identity.
//
// Signature is excluded so the identity is stable across signing — the
// digest is what the leaf key signs. Algorithm remains part of the
// hashed bytes. The caller's attestation is not mutated: the signature
// is zeroed on a shallow copy.
func CanonicalHash(att *Attestation) ([32]byte, error) {
	if att == nil {
		return [32]byte{}, ErrNilAttestation
	}
	// Hash the unsigned form: project onto a shallow copy with the
	// signature zeroed so the identity is independent of the signature
	// value itself.
	wire := *att
	wire.Signature = nil
	return canonical.CanonicalHash(&wire)
}
