package signature

import "fmt"

// ErrUnsupportedAlgorithm is returned when a key type is not
// recognized by any registered algorithm. This indicates the key
// type is not a signing key (e.g., x25519) or is from a package the
// signature package does not support.
var ErrUnsupportedAlgorithm = fmt.Errorf("signature: unsupported algorithm")

// ErrAlgorithmNotRegistered is returned when an Algorithm constant
// has no registered sign/verify implementation. This indicates a
// missing init() registration, which should be caught by
// TestRegistryCompleteness.
var ErrAlgorithmNotRegistered = fmt.Errorf("signature: algorithm not registered")

// ErrAlgMismatch is a structured error returned when a key is used
// under an incompatible algorithm. It carries the expected algorithm
// (the key's bound algorithm) and the got algorithm (the algorithm
// the caller requested). Tested via errors.As.
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
// the integer value when the JOSE name is empty (unregistered or
// zero Algorithm).
func algName(a Algorithm) string {
	if name := a.JOSE(); name != "" {
		return name
	}
	return fmt.Sprintf("alg#%d", int(a))
}
