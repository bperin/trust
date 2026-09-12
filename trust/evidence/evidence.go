package evidence

import (
	"crypto/subtle"
	"errors"

	"github.com/bperin/trust/crypto/hash"
)

// Sentinel errors returned by VerifyContent. Check them with errors.Is.
var (
	// ErrContentHashMismatch is returned when the SHA-256 of the supplied
	// content does not equal the reference's ContentHash — the bytes at
	// hand are not the bytes the reference identifies.
	ErrContentHashMismatch = errors.New("evidence: content hash mismatch")
	// ErrMissingContentHash is returned when a reference carries the zero
	// ContentHash — there is no identity to verify against.
	ErrMissingContentHash = errors.New("evidence: missing content hash")
)

// EvidenceRef is a content-addressed reference to external evidence.
// ContentHash is the identity; Type and URI are advisory metadata.
type EvidenceRef struct {
	// Type is a canonical evidence type tag, e.g. "pdf", "image", "json".
	Type string `json:"type,omitempty"`
	// URI is an advisory retrieval hint — a URI, file path, or content
	// identifier. It is never trusted as identity and is never
	// dereferenced by this package.
	URI string `json:"uri,omitempty"`
	// ContentHash is the [FIPS 180-4] SHA-256 digest of the evidence
	// bytes. It is the identity of the reference.
	ContentHash [32]byte `json:"contentHash"`
}

// HashContent returns the [FIPS 180-4] SHA-256 digest of content. The
// digest is the identity stored in EvidenceRef.ContentHash. Nil input is
// treated as empty input and produces the SHA-256 of the empty string.
func HashContent(content []byte) [32]byte {
	return hash.NewSHA256().Sum(content)
}

// VerifyContent verifies that content is the byte string identified by
// ref: it hashes content with SHA-256 and compares the digest to
// ref.ContentHash using crypto/subtle.ConstantTimeCompare, which does not
// leak how many digest bytes matched.
//
// ref.URI is never consulted — a dead URI with correct content verifies,
// because ContentHash is the identity and the URI is only a retrieval
// hint. VerifyContent returns ErrMissingContentHash when ref.ContentHash
// is the zero value and ErrContentHashMismatch when the digests differ.
func VerifyContent(ref EvidenceRef, content []byte) error {
	var zero [32]byte
	if subtle.ConstantTimeCompare(ref.ContentHash[:], zero[:]) == 1 {
		return ErrMissingContentHash
	}
	got := HashContent(content)
	if subtle.ConstantTimeCompare(got[:], ref.ContentHash[:]) != 1 {
		return ErrContentHashMismatch
	}
	return nil
}
