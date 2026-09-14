package evidence

import (
	"time"

	"github.com/bperin/trust/canonical"
)

// ContentHashLen is the required byte length of Evidence.ContentHash —
// the [FIPS 180-4] SHA-256 digest size of the external material the
// evidence references.
const ContentHashLen = 32

// Evidence is a content-addressed reference to supporting material: it
// binds an identifier to the hash of the material, its media type, a
// retrieval locator, provenance, and free-form metadata. Evidence carries
// the reference — never the material itself — so a verifier can check the
// reference's structure and identity without fetching content.
type Evidence struct {
	// Identifier names the evidence within its domain — e.g. a URN or
	// a document key. Must be non-empty.
	Identifier string `json:"identifier"`

	// ContentHash is the [FIPS 180-4] SHA-256 digest of the external
	// material this evidence references. Exactly ContentHashLen bytes.
	// It is stored data — distinct from CanonicalHash, the computed
	// identity of this Evidence value.
	ContentHash []byte `json:"contentHash"`

	// MediaType is the MIME media type of the referenced material —
	// e.g. "application/pdf". Must be non-empty.
	MediaType string `json:"mediaType"`

	// Locator says where the material may be retrieved — e.g. a URL or
	// a CID. Must be non-empty. ValidateEvidence never dereferences it.
	Locator string `json:"locator"`

	// Provenance records where the material came from, how it was
	// obtained, and when.
	Provenance Provenance `json:"provenance"`

	// Metadata carries optional free-form attributes, omitted from the
	// canonical form when empty. [RFC 8785] JCS sorts map keys by UTF-16
	// code unit, so iteration order does not affect the canonical bytes.
	// Every value must be JSON-canonicalizable: finite numbers, and
	// integer values exactly representable as IEEE 754 doubles.
	Metadata map[string]any `json:"metadata,omitempty"`
}

// Provenance records the origin of the material an Evidence references:
// the source it came from, the method by which it was obtained, and the
// time it was obtained. It is a value type with no optional fields —
// every field is always present in the [RFC 8785] canonical form.
type Provenance struct {
	// Source identifies where the material came from — e.g. a system
	// name, a DID, or a URL.
	Source string `json:"source"`

	// Method describes how the material was obtained — e.g.
	// "retrieved", "generated", "attested".
	Method string `json:"method"`

	// Timestamp records when the material was obtained. It marshals
	// via the encoding/json default (RFC 3339).
	Timestamp time.Time `json:"timestamp"`
}

// CanonicalEncoding declares the evidence's canonical byte encoding per
// the canonical.EncodingDeclarer interface: canonical.EncodingJSON, the
// JSON Canonicalization Scheme (JCS) per [RFC 8785]. CanonicalHash
// consults this declaration so the encoding selection stays in one place.
func (e *Evidence) CanonicalEncoding() canonical.Encoding {
	return canonical.EncodingJSON
}
