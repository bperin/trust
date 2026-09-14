package commitment

import "github.com/bperin/trust/canonical"

// AlgorithmRFC6962SHA256 identifies the [RFC 6962] §2.1 Merkle tree hash with [FIPS 180-4] SHA-256 used by commitments built here.
const AlgorithmRFC6962SHA256 = "rfc6962-sha256"

// Commitment is a Merkle commitment over an ordered set of trust-object canonical hashes.
type Commitment struct {
	// Root is the [RFC 6962] Merkle tree root over LeafHashes.
	Root [32]byte

	// Size is the number of leaves committed; it equals
	// len(LeafHashes) in a valid commitment.
	Size int

	// LeafHashes is the sorted, duplicate-free list of canonical
	// hashes committed, in ascending bytewise lexicographic order.
	LeafHashes [][32]byte

	// Algorithm is AlgorithmRFC6962SHA256.
	Algorithm string
}

// CanonicalEncoding declares JSON/JCS as the commitment's canonical
// encoding per canonical.EncodingDeclarer.
func (c *Commitment) CanonicalEncoding() canonical.Encoding {
	return canonical.EncodingJSON
}
