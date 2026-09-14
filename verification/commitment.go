package verification

// CommitmentProof carries the caller-supplied material an external
// commitment checker verifies. It is JSON-canonicalizable so it can
// participate in canonical encodings.
type CommitmentProof struct {
	// ID names the commitment the proof refers to.
	ID string `json:"id"`

	// Value carries the proof material the checker interprets.
	Value []byte `json:"value,omitempty"`
}

// CommitmentChecker verifies external commitment proofs against the
// verification inputs. Consumer-side, single method.
type CommitmentChecker interface {
	// Verify checks one commitment proof against the inputs.
	Verify(proof CommitmentProof, in Inputs) error
}
