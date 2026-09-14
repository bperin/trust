package verification

import (
	"encoding/json"
	"fmt"

	"github.com/bperin/trust/canonical"
)

// NodeKind identifies the kind of object a provenance Link references.
type NodeKind int

const (
	// NodeAttestation marks the attestation node that anchors the chain.
	NodeAttestation NodeKind = 1
	// NodeClaim marks the claim node carried by the attestation.
	NodeClaim NodeKind = 2
	// NodeSigningKey marks the leaf signing-key node.
	NodeSigningKey NodeKind = 3
	// NodeAuthority marks an intermediate authority node.
	NodeAuthority NodeKind = 4
	// NodeDelegation marks a delegation edge between authority nodes.
	NodeDelegation NodeKind = 5
	// NodeRootAuthority marks the self-issued root authority node.
	NodeRootAuthority NodeKind = 6
	// NodeIdentity marks the resolved identity node at the chain's end.
	NodeIdentity NodeKind = 7
)

// Link is one node of the provenance chain.
type Link struct {
	// Kind identifies the kind of object Ref points at.
	Kind NodeKind `json:"kind"`
	// Ref is the node identity: canonical-hash hex, key ID, or DID by Kind.
	Ref string `json:"ref"`
	// Subject is the node's subject identifier.
	Subject string `json:"subject"`
	// KeyID is the verification-method identifier bound to the node.
	KeyID string `json:"keyId"`
	// Parent is the canonical-hash hex of the node's parent.
	Parent string `json:"parent"`
}

// Provenance is the ordered chain of Links resolved along the trust path.
type Provenance struct {
	// Links holds the chain nodes; nil and empty are equivalent.
	Links []Link `json:"links,omitempty"`
}

// CanonicalEncoding implements canonical.EncodingDeclarer selecting JCS.
func (p *Provenance) CanonicalEncoding() canonical.Encoding {
	return canonical.EncodingJSON
}

// CanonicalHash returns the [FIPS 180-4] SHA-256 digest of the JCS encoding of p.
func CanonicalHash(p *Provenance) ([32]byte, error) {
	if p == nil {
		return [32]byte{}, ErrNilProvenance
	}
	return canonical.CanonicalHash(p)
}

// MarshalProvenance returns the [RFC 8785] JCS-canonical bytes of p.
func MarshalProvenance(p *Provenance) ([]byte, error) {
	if p == nil {
		return nil, ErrNilProvenance
	}
	b, err := canonical.Marshal(p, canonical.EncodingJSON)
	if err != nil {
		return nil, fmt.Errorf("verification: marshal provenance: %w", err)
	}
	return b, nil
}

// UnmarshalProvenance decodes the bytes MarshalProvenance produced.
func UnmarshalProvenance(b []byte) (*Provenance, error) {
	var p Provenance
	if err := json.Unmarshal(b, &p); err != nil {
		return nil, fmt.Errorf("verification: unmarshal provenance: %w", err)
	}
	return &p, nil
}
