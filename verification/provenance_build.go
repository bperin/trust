package verification

import (
	"encoding/hex"
	"fmt"

	"github.com/bperin/trust/attestation"
	"github.com/bperin/trust/authority"
	"github.com/bperin/trust/claim"
)

// BuildProvenance emits the ordered leaf→root provenance link graph
// for the inputs with no verification: attestation, claim, signing
// key, one authority link per hop leaf→root, one delegation link per
// adjacent pair, the root authority, and — only when an identity
// resolver is configured — the root subject's identity link. The
// output is deterministic; refs are canonical-hash hex.
func BuildProvenance(in Inputs) (*Provenance, error) {
	if in.Attestation == nil {
		return nil, ErrNilAttestation
	}
	if len(in.Chain) == 0 {
		return nil, ErrEmptyChain
	}

	attRef, err := hashRef(attestation.CanonicalHash(in.Attestation))
	if err != nil {
		return nil, fmt.Errorf("verification: attestation hash: %w", err)
	}
	claimRef, err := hashRef(claim.CanonicalHash(&in.Attestation.Claim))
	if err != nil {
		return nil, fmt.Errorf("verification: claim hash: %w", err)
	}

	hopRefs := make([]string, len(in.Chain))
	for i, hop := range in.Chain {
		ref, err := hashRef(authority.CanonicalHash(hop.Authority))
		if err != nil {
			return nil, fmt.Errorf("verification: hop %d hash: %w", i, err)
		}
		hopRefs[i] = ref
	}

	links := make([]Link, 0, 3+2*len(in.Chain)+1)
	links = append(links,
		Link{Kind: NodeAttestation, Ref: attRef, Subject: in.Attestation.Issuer},
		Link{Kind: NodeClaim, Ref: claimRef, Parent: attRef},
		Link{Kind: NodeSigningKey, KeyID: in.Attestation.SigningKeyID, Parent: attRef},
	)
	for i, hop := range in.Chain {
		parent := ""
		if i+1 < len(in.Chain) {
			parent = hopRefs[i+1]
		}
		links = append(links, Link{
			Kind:    NodeAuthority,
			Ref:     hopRefs[i],
			Subject: hop.Authority.Subject,
			Parent:  parent,
		})
	}
	for i := 0; i+1 < len(in.Chain); i++ {
		links = append(links, Link{Kind: NodeDelegation, Ref: hopRefs[i], Parent: hopRefs[i+1]})
	}
	links = append(links, Link{Kind: NodeRootAuthority, Ref: hopRefs[len(hopRefs)-1]})
	if in.IdentityResolver != nil {
		root := in.Chain[len(in.Chain)-1].Authority
		links = append(links, Link{Kind: NodeIdentity, Ref: root.Subject, Subject: root.Subject})
	}
	return &Provenance{Links: links}, nil
}

// hashRef renders a canonical-hash hex ref.
func hashRef(h [32]byte, err error) (string, error) {
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(h[:]), nil
}
