package claim

import (
	"time"

	"github.com/bperin/trust/authority"
	"github.com/bperin/trust/canonical"
)

// Claim is a typed statement an issuer makes about a subject — the
// payload an attestation signs. The entire struct is the claim's
// canonical identity: CanonicalHash digests every field, so a claim is
// self-contained — Scope and Validity are value copies, not references
// to shared authority state.
type Claim struct {
	// Issuer identifies the entity making the claim — a DID. Must be
	// non-empty.
	Issuer string `json:"issuer"`

	// Subject identifies the entity the claim is about — a DID. Must
	// be non-empty.
	Subject string `json:"subject"`

	// Type names what kind of claim this is, under a namespace. The
	// pair (Namespace, Name) is the type's identity.
	Type ClaimType `json:"type"`

	// Value is the claim's payload — any JSON-canonicalizable value.
	// Non-finite numbers and integer literals beyond the IEEE 754
	// exact-integer range are rejected by CanonicalHash. Must be
	// non-nil.
	Value any `json:"value"`

	// Scope narrows where the claim applies. Held by value; a
	// zero-value Scope serializes to {} and is unconstrained.
	Scope authority.Scope `json:"scope"`

	// Validity bounds the claim in time. Held by value. Times marshal
	// via the encoding/json default (RFC 3339).
	Validity authority.Validity `json:"validity"`

	// Provenance records where and how the claim originated. Held by
	// value with no omitempty — it always serializes in full.
	Provenance Provenance `json:"provenance"`
}

// ClaimType names a kind of claim under a namespace, mirroring
// authority.Capability. The pair (Namespace, Name) is the type's
// identity — two claim types are equal iff both fields are equal (Go
// struct equality is the equality contract). The type space is open:
// consumers define ClaimType values in their own namespaces.
type ClaimType struct {
	// Namespace is the claim-type family — e.g. "acme" for a
	// consumer-defined type.
	Namespace string `json:"namespace"`

	// Name is the type within the namespace — e.g. "role".
	Name string `json:"name"`
}

// Provenance records the origin of a claim: where it came from, the
// method by which it was obtained, and when. It is a value type —
// every field always serializes.
type Provenance struct {
	// Source identifies where the claim originated — e.g. a document
	// URI or a system identifier.
	Source string `json:"source"`

	// Method describes how the claim was obtained — e.g. "self-attested"
	// or "verified-import".
	Method string `json:"method"`

	// Timestamp records when the claim was produced. Marshals via the
	// encoding/json default (RFC 3339).
	Timestamp time.Time `json:"timestamp"`
}

// CanonicalEncoding declares the claim's canonical byte encoding per
// the canonical.EncodingDeclarer interface: canonical.EncodingJSON,
// the JSON Canonicalization Scheme (JCS) per [RFC 8785]. CanonicalHash
// consults this declaration so the encoding selection stays in one
// place.
func (c *Claim) CanonicalEncoding() canonical.Encoding {
	return canonical.EncodingJSON
}
