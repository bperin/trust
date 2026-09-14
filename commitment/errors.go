package commitment

import "errors"

// ErrEmptyObjects is returned by Build when the objects slice is empty.
var ErrEmptyObjects = errors.New("commitment: empty objects")

// ErrNilObject is returned by LeafHash and Build when a TrustObject is a nil interface or a slice element is nil.
var ErrNilObject = errors.New("commitment: nil object")

// ErrDuplicateObject is returned by Build and rejectDuplicates when two objects share a canonical hash.
var ErrDuplicateObject = errors.New("commitment: duplicate object")

// ErrObjectNotCommitted is returned by InclusionProof when the object's leaf is absent from the commitment's LeafHashes.
var ErrObjectNotCommitted = errors.New("commitment: object not committed")

// ErrNilCommitment is returned by VerifyCommitment, InclusionProof, and ConsistencyProofBetween when the Commitment is nil.
var ErrNilCommitment = errors.New("commitment: nil commitment")

// ErrAlgorithmMismatch is returned by VerifyCommitment when Algorithm is not AlgorithmRFC6962SHA256.
var ErrAlgorithmMismatch = errors.New("commitment: algorithm mismatch")

// ErrEmptyCommitment is returned by VerifyCommitment when Size is zero or LeafHashes is empty.
var ErrEmptyCommitment = errors.New("commitment: empty commitment")

// ErrSizeMismatch is returned by VerifyCommitment when Size differs from len(LeafHashes).
var ErrSizeMismatch = errors.New("commitment: size mismatch")

// ErrUnsortedLeaves is returned by VerifyCommitment when LeafHashes is not in ascending order.
var ErrUnsortedLeaves = errors.New("commitment: unsorted leaves")

// ErrDuplicateLeaf is returned by VerifyCommitment when adjacent LeafHashes are equal.
var ErrDuplicateLeaf = errors.New("commitment: duplicate leaf")

// ErrRootMismatch is returned by VerifyCommitment when the recomputed root differs from Root under constant-time comparison.
var ErrRootMismatch = errors.New("commitment: root mismatch")

// ErrInclusionFailed is returned by VerifyInclusion when Merkle inclusion verification fails.
var ErrInclusionFailed = errors.New("commitment: inclusion failed")

// ErrNotPrefix is returned by ConsistencyProofBetween when the old commitment's LeafHashes is not a prefix of the next commitment's.
var ErrNotPrefix = errors.New("commitment: not a prefix")

// ErrInvalidRange is returned by ConsistencyProofBetween when the old commitment's Size is not less than the next commitment's.
var ErrInvalidRange = errors.New("commitment: invalid range")
