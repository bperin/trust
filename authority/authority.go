package authority

import (
	"time"

	"github.com/bperin/trust/canonical"
	"github.com/bperin/trust/signature"
)

// Authority is a typed grant of power: it binds a subject to a set of
// capabilities, scoped by resource, action, organization, geography,
// channel, time window, quantity, and monetary limits, valid for a
// fixed window, constrained in further delegation, carrying a lifecycle
// status and a cryptographic proof.
//
// A nil Parent marks a root authority — self-asserted by Subject. A
// non-nil Parent references the canonical hash of the delegating
// authority, making this a delegated authority.
type Authority struct {
	// Subject identifies the entity the authority is granted to — a
	// DID. Must be non-empty.
	Subject string `json:"subject"`

	// Parent references the canonical hash of the delegating
	// authority. Nil marks a root authority.
	Parent *string `json:"parent,omitempty"`

	// Capabilities is the set of capabilities granted. The canonical
	// form is sorted ascending by (Namespace, Name); Validate rejects
	// an unsorted slice.
	Capabilities []Capability `json:"capabilities"`

	// Scope narrows where the capabilities may be exercised.
	Scope Scope `json:"scope"`

	// Validity bounds the authority in time.
	Validity Validity `json:"validity"`

	// DelegationConstraints bound further delegation of this
	// authority.
	DelegationConstraints DelegationConstraints `json:"delegationConstraints"`

	// Status is the lifecycle state of the authority.
	Status Status `json:"status"`

	// Proof carries the cryptographic proof over the canonical hash.
	Proof Proof `json:"proof"`
}

// Capability names a grantable power under a namespace. The pair
// (Namespace, Name) is the capability's identity — two capabilities
// are equal iff both fields are equal.
type Capability struct {
	// Namespace is the capability family — e.g. "trust" for the
	// predefined capabilities below.
	Namespace string `json:"namespace"`

	// Name is the capability within the namespace — e.g. "attest".
	Name string `json:"name"`
}

// Predefined capabilities in the "trust" namespace. Consumers may
// define their own capabilities in other namespaces — a Capability is
// an open type, not an enumeration.
var (
	// CapabilityAttest grants the power to issue attestations.
	CapabilityAttest = Capability{Namespace: "trust", Name: "attest"}

	// CapabilityDelegate grants the power to delegate authority to a
	// further subject.
	CapabilityDelegate = Capability{Namespace: "trust", Name: "delegate"}

	// CapabilityRevoke grants the power to revoke an authority.
	CapabilityRevoke = Capability{Namespace: "trust", Name: "revoke"}

	// CapabilitySign grants the power to produce signatures.
	CapabilitySign = Capability{Namespace: "trust", Name: "sign"}
)

// Scope narrows where an authority's capabilities may be exercised.
// Every dimension is optional: a nil/empty dimension is unconstrained,
// and a zero-value Scope serializes to {} via omitempty. Each string
// slice dimension is canonically sorted ascending and dedup-free;
// ValidateScope rejects an unsorted or duplicated slice.
type Scope struct {
	// Resources limits the resources the authority applies to.
	Resources []string `json:"resources,omitempty"`

	// Subjects limits the subjects the authority applies to.
	Subjects []string `json:"subjects,omitempty"`

	// Actions limits the actions the authority applies to.
	Actions []string `json:"actions,omitempty"`

	// Organizations limits the organizations the authority applies to.
	Organizations []string `json:"organizations,omitempty"`

	// Geography limits the geographic regions the authority applies to.
	Geography []string `json:"geography,omitempty"`

	// Channels limits the channels the authority applies to.
	Channels []string `json:"channels,omitempty"`

	// TimeWindow limits the authority to a window within Validity.
	TimeWindow *TimeWindow `json:"timeWindow,omitempty"`

	// Quantity limits the authority to a countable amount.
	Quantity *Quantity `json:"quantity,omitempty"`

	// Monetary limits the authority to a monetary amount.
	Monetary *Monetary `json:"monetary,omitempty"`
}

// TimeWindow is an inclusive time range within which the authority may
// be exercised. Times marshal via the encoding/json default (RFC 3339).
type TimeWindow struct {
	// Start is the beginning of the window.
	Start time.Time `json:"start"`

	// End is the end of the window.
	End time.Time `json:"end"`
}

// Quantity is a countable limit on the exercise of an authority —
// e.g. at most N operations.
type Quantity struct {
	// Unit names what is counted — e.g. "operations", "documents".
	Unit string `json:"unit"`

	// Limit is the maximum count.
	Limit int64 `json:"limit"`
}

// Monetary is a monetary limit on the exercise of an authority.
type Monetary struct {
	// Currency is the ISO 4217 currency code — e.g. "USD".
	Currency string `json:"currency"`

	// Limit is the maximum amount in that currency.
	Limit float64 `json:"limit"`
}

// Validity bounds an authority in time. Times marshal via the
// encoding/json default (RFC 3339).
type Validity struct {
	// NotBefore is the start of the authority's validity window.
	NotBefore time.Time `json:"notBefore"`

	// NotAfter is the end of the authority's validity window.
	NotAfter time.Time `json:"notAfter"`
}

// DelegationConstraints bound further delegation of an authority.
type DelegationConstraints struct {
	// MaxDepth is the maximum delegation depth below this authority.
	// Nil means unconstrained by this field.
	MaxDepth *int `json:"maxDepth,omitempty"`
}

// Status is the lifecycle state of an Authority. It is an int type
// that serializes as a plain JSON number via the encoding/json
// default — deliberately without a custom marshaler:
//
//	StatusActive     = 1
//	StatusRevoked    = 2
//	StatusSuperseded = 3
//	StatusExpired    = 4
type Status int

// Status constants for the authority lifecycle. The numeric values are
// the wire form: 1, 2, 3, 4.
const (
	// StatusActive marks an authority currently in force.
	StatusActive Status = 1

	// StatusRevoked marks an authority explicitly revoked before its
	// NotAfter.
	StatusRevoked Status = 2

	// StatusSuperseded marks an authority replaced by a newer one.
	StatusSuperseded Status = 3

	// StatusExpired marks an authority past its NotAfter.
	StatusExpired Status = 4
)

// Proof carries the cryptographic proof over an authority's canonical
// hash. Algorithm and KeyID are part of the hashed bytes; Signature is
// excluded from the canonical hash so the authority's identity is
// stable across signing.
type Proof struct {
	// Algorithm is the signature.Algorithm that produced Signature.
	Algorithm signature.Algorithm `json:"algorithm"`

	// KeyID references the key that produced Signature. It is an
	// application lookup key, not interpreted here.
	KeyID string `json:"keyId"`

	// Signature is the proof value over the canonical hash of the
	// unsigned authority. It is omitted from the canonical hash and
	// from the JSON of an unsigned authority via omitempty.
	Signature []byte `json:"signature,omitempty"`
}

// CanonicalEncoding declares the authority's canonical byte encoding
// per the canonical.EncodingDeclarer interface: canonical.EncodingJSON,
// the JSON Canonicalization Scheme (JCS) per [RFC 8785]. CanonicalHash
// consults this declaration so the encoding selection stays in one
// place.
func (a *Authority) CanonicalEncoding() canonical.Encoding {
	return canonical.EncodingJSON
}
