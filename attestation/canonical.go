package attestation

import (
	"errors"

	"github.com/bperin/trust/canonical"
)

var ErrNilAttestation = errors.New("attestation: nil attestation")

// CanonicalHash returns the [FIPS 180-4] SHA-256 digest of the [RFC 8785]
// JCS-canonical JSON encoding of att with Signature zeroed, so the
// identity is stable across signing.
func CanonicalHash(att *Attestation) ([32]byte, error) {
	if att == nil {
		return [32]byte{}, ErrNilAttestation
	}
	wire := *att
	wire.Signature = nil
	return canonical.CanonicalHash(&wire)
}
