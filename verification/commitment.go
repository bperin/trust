package verification

// CommitmentProof carries the caller-supplied material a CommitmentChecker verifies.
type CommitmentProof struct {
	ID    string `json:"id"`
	Value []byte `json:"value,omitempty"`
}

// CommitmentChecker verifies external commitment proofs against the inputs.
type CommitmentChecker interface {
	Verify(proof CommitmentProof, in Inputs) error
}
