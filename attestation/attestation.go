package attestation

import (
	"time"

	"github.com/bperin/trust/authority"
	"github.com/bperin/trust/canonical"
	"github.com/bperin/trust/claim"
	"github.com/bperin/trust/evidence"
	"github.com/bperin/trust/signature"
)

// Attestation is an authority-bound, canonically identified statement
// verified by signature and authorization checks together.
type Attestation struct {
	Issuer            string               `json:"issuer"`
	SigningKeyID      string               `json:"signingKeyId"`
	SigningKeyVersion uint64               `json:"signingKeyVersion"`
	AuthorityRef      string               `json:"authorityRef"`
	Capability        authority.Capability `json:"capability"`

	// Named field, never embedded: Claim shares the "issuer" and
	// "validity" JSON tags with the attestation, so embedding would
	// suppress the deeper fields from encoding and the canonical hash.
	Claim claim.Claim `json:"claim"`

	// Sorted strictly ascending by evidence.CanonicalHash; Validate
	// rejects unsorted or duplicated entries rather than normalizing.
	Evidence []evidence.Evidence `json:"evidence"`

	IssuedAt  time.Time           `json:"issuedAt"`
	Validity  authority.Validity  `json:"validity"`
	Status    authority.Status    `json:"status"`
	Algorithm signature.Algorithm `json:"algorithm"`

	// Excluded from the canonical hash; omitted from JSON when unsigned.
	Signature []byte `json:"signature,omitempty"`
}

// CanonicalEncoding declares JSON/JCS as the attestation's canonical
// encoding per canonical.EncodingDeclarer.
func (a *Attestation) CanonicalEncoding() canonical.Encoding {
	return canonical.EncodingJSON
}
