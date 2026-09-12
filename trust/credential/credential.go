package credential

import (
	"crypto/subtle"
	"errors"
	"fmt"
	"time"

	"github.com/bperin/trust/canonical"
	"github.com/bperin/trust/evidence"
)

// Sentinel errors returned by Validate and CanonicalHash. Check them with
// errors.Is.
var (
	// ErrWrongVersion is returned when a VersionedClaim has Version 0.
	// Envelope versions start at 1.
	ErrWrongVersion = errors.New("credential: wrong claim version")
	// ErrMissingField is returned when a required VersionedClaim field
	// (Schema, Subject, Resource, Issuer) is empty or the claim is nil.
	ErrMissingField = errors.New("credential: missing required field")
	// ErrInvalidWindow is returned when a VersionedClaim's validity window
	// is inverted — NotBefore is after NotAfter.
	ErrInvalidWindow = errors.New("credential: invalid validity window")
	// ErrEvidenceHashMissing is returned when a VersionedClaim carries an
	// evidence reference whose ContentHash is the zero digest — a
	// reference with no identity.
	ErrEvidenceHashMissing = errors.New("credential: evidence content hash missing")
)

// VersionedClaim is a versioned claim envelope: the stable cryptographic
// wrapper around a domain payload. The library defines the envelope — subject,
// resource, issuer, validity window, schema, and evidence references — and the
// application owns the payload schema. Multiple valid claims about the same
// resource may coexist; this package does not resolve which applies.
//
// The claim's identity is its canonical hash: CanonicalHash produces the
// [FIPS 180-4] SHA-256 digest of the claim's [RFC 8785] JCS-canonical JSON
// encoding, so identical claims hash identically regardless of Go map
// iteration order.
type VersionedClaim struct {
	// Version is the envelope schema version. It starts at 1.
	Version uint `json:"version"`
	// Schema identifies the payload schema, typically a URI. The library
	// does not interpret it.
	Schema string `json:"schema"`
	// Subject identifies the entity the claim is about — a DID or UUID.
	Subject string `json:"subject"`
	// Resource identifies the resource the claim concerns.
	Resource string `json:"resource"`
	// Issuer identifies the claim issuer — a DID or UUID.
	Issuer string `json:"issuer"`
	// IssuedAt is when the issuer produced the claim.
	IssuedAt time.Time `json:"issuedAt"`
	// NotBefore is the start of the validity window.
	NotBefore time.Time `json:"notBefore"`
	// NotAfter is the end of the validity window.
	NotAfter time.Time `json:"notAfter"`
	// Payload is the extensible domain payload. The library defines the
	// envelope, not the domain schema.
	Payload map[string]interface{} `json:"payload,omitempty"`
	// Evidence carries content-addressed references to supporting
	// evidence. Each ContentHash is the evidence's identity; Type and URI
	// are advisory.
	Evidence []evidence.EvidenceRef `json:"evidence,omitempty"`
}

// CanonicalHash returns the claim's identity: the [FIPS 180-4] SHA-256 digest
// of its canonical bytes, computed by canonical.CanonicalHash using the
// [RFC 8785] JCS JSON encoding. Identical claims produce identical hashes;
// a single differing byte in any field changes the identity.
func CanonicalHash(claim *VersionedClaim) ([32]byte, error) {
	if claim == nil {
		return [32]byte{}, fmt.Errorf("%w: claim is nil", ErrMissingField)
	}
	return canonical.CanonicalHash(claim)
}

// Validate checks that claim is a well-formed envelope: Version is at least
// 1, Schema/Subject/Resource/Issuer are non-empty, the validity window is not
// inverted (NotBefore ≤ NotAfter), and every Evidence entry carries a
// non-zero ContentHash. It returns ErrWrongVersion, ErrMissingField,
// ErrInvalidWindow, or ErrEvidenceHashMissing on the first violation.
//
// Validate checks envelope shape only. It does not dereference evidence URIs,
// verify evidence content (use evidence.VerifyContent), or evaluate the
// domain payload.
func Validate(claim *VersionedClaim) error {
	if claim == nil {
		return fmt.Errorf("%w: claim is nil", ErrMissingField)
	}
	if claim.Version < 1 {
		return fmt.Errorf("%w: got %d, want >= 1", ErrWrongVersion, claim.Version)
	}
	for _, f := range []struct {
		name  string
		value string
	}{
		{"schema", claim.Schema},
		{"subject", claim.Subject},
		{"resource", claim.Resource},
		{"issuer", claim.Issuer},
	} {
		if f.value == "" {
			return fmt.Errorf("%w: %s", ErrMissingField, f.name)
		}
	}
	if claim.NotBefore.After(claim.NotAfter) {
		return fmt.Errorf("%w: notBefore %s is after notAfter %s",
			ErrInvalidWindow, claim.NotBefore, claim.NotAfter)
	}
	var zero [32]byte
	for i, ref := range claim.Evidence {
		if subtle.ConstantTimeCompare(ref.ContentHash[:], zero[:]) == 1 {
			return fmt.Errorf("%w: evidence[%d]", ErrEvidenceHashMissing, i)
		}
	}
	return nil
}
