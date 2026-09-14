package verification

// CommitmentProof carries the caller-supplied material a CommitmentChecker verifies.
type CommitmentProof struct {
	// ID names the commitment the proof refers to.
	ID string `json:"id"`

	// Value carries the proof material the checker interprets.
	Value []byte `json:"value,omitempty"`
}

// CommitmentChecker verifies external commitment proofs against the inputs.
type CommitmentChecker interface {
	// Verify checks one commitment proof against the inputs.
	Verify(proof CommitmentProof, in Inputs) error
}
