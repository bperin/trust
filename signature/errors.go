package signature

import "fmt"

// ErrUnsupportedAlgorithm is returned when a key type is not
// recognized by any registered algorithm or is not a signing key
// (e.g., x25519).
var ErrUnsupportedAlgorithm = fmt.Errorf("signature: unsupported algorithm")

// ErrAlgorithmNotRegistered is returned when an Algorithm constant
// has no registered sign/verify implementation.
var ErrAlgorithmNotRegistered = fmt.Errorf("signature: algorithm not registered")

// ErrAlgMismatch is returned when a key is used under an
// incompatible algorithm. Expected is the key's bound algorithm and
// Got is the algorithm the caller requested.
type ErrAlgMismatch struct {
	Expected Algorithm
	Got      Algorithm
}

// Error implements the error interface.
func (e *ErrAlgMismatch) Error() string {
	return fmt.Sprintf("signature: algorithm mismatch: expected %s, got %s",
		algName(e.Expected), algName(e.Got))
}

// algName renders an Algorithm for error messages, falling back to
// the integer value when the JOSE name is empty.
func algName(a Algorithm) string {
	if name := a.JOSE(); name != "" {
		return name
	}
	return fmt.Sprintf("alg#%d", int(a))
}
