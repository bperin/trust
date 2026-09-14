package verification

import (
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/bperin/trust/authority"
	"github.com/bperin/trust/delegation"
	"github.com/bperin/trust/identity/did"
)

// CheckAuthorityProof verifies every hop authority's proof against
// that hop's public key.
func checkAuthorityProof(ctx *checkContext) error {
	for i, hop := range ctx.in.Chain {
		if err := authority.VerifyAuthorityProof(hop.Authority, hop.PublicKey); err != nil {
			ctx.hop = i
			return fmt.Errorf("verification: hop %d authority proof: %w: %v", i, ErrAuthorityInvalid, err)
		}
	}
	return nil
}

// CheckChainLink verifies each delegated authority's parent reference
// against the next hop's canonical hash, then verifies the delegation
// is a strict subset of its parent.
func checkChainLink(ctx *checkContext) error {
	for i := 0; i+1 < len(ctx.in.Chain); i++ {
		child, parent := ctx.in.Chain[i].Authority, ctx.in.Chain[i+1].Authority
		ph, err := authority.CanonicalHash(parent)
		if err != nil {
			ctx.hop = i
			return fmt.Errorf("verification: hop %d parent hash: %w", i, err)
		}
		if child.Parent == nil || *child.Parent != hex.EncodeToString(ph[:]) {
			ctx.hop = i
			return fmt.Errorf("verification: hop %d: %w", i, ErrChainBroken)
		}
		if err := delegation.VerifySubset(child, parent); err != nil {
			ctx.hop = i
			return fmt.Errorf("verification: hop %d delegation: %w", i, mapDelegationError(err))
		}
	}
	return nil
}

// mapDelegationError maps a delegation sentinel into the verification
// taxonomy.
func mapDelegationError(err error) error {
	switch {
	case errors.Is(err, delegation.ErrCapabilityEscalation):
		return ErrCapabilityNotGranted
	case errors.Is(err, delegation.ErrScopeEscalation), errors.Is(err, delegation.ErrValidityEscalation):
		return ErrScopeViolation
	case errors.Is(err, delegation.ErrDepthEscalation):
		return ErrDelegationDepth
	default:
		return err
	}
}

// CheckTemporal verifies the attestation and every hop authority are
// within their validity windows at the verification time. Window
// boundaries are inclusive.
func checkTemporal(ctx *checkContext) error {
	v := ctx.in.Attestation.Validity
	if ctx.now.Before(v.NotBefore) {
		return fmt.Errorf("verification: attestation: %w", ErrNotYetValid)
	}
	if ctx.now.After(v.NotAfter) {
		return fmt.Errorf("verification: attestation: %w", ErrExpired)
	}
	for i, hop := range ctx.in.Chain {
		hv := hop.Authority.Validity
		if ctx.now.Before(hv.NotBefore) {
			ctx.hop = i
			return fmt.Errorf("verification: hop %d: %w", i, ErrNotYetValid)
		}
		if ctx.now.After(hv.NotAfter) {
			ctx.hop = i
			return fmt.Errorf("verification: hop %d: %w", i, ErrExpired)
		}
	}
	return nil
}

// CheckRevocation verifies every hop authority is active.
func checkRevocation(ctx *checkContext) error {
	for i, hop := range ctx.in.Chain {
		switch hop.Authority.Status {
		case authority.StatusActive:
		case authority.StatusRevoked:
			ctx.hop = i
			return fmt.Errorf("verification: hop %d: %w", i, ErrRevoked)
		case authority.StatusSuperseded:
			ctx.hop = i
			return fmt.Errorf("verification: hop %d: %w", i, ErrSuperseded)
		case authority.StatusExpired:
			ctx.hop = i
			return fmt.Errorf("verification: hop %d: %w", i, ErrExpired)
		default:
			ctx.hop = i
			return fmt.Errorf("verification: hop %d: %w: status %d", i, ErrAuthorityInvalid, hop.Authority.Status)
		}
	}
	return nil
}

// CheckIdentity resolves the root authority subject's DID. With no
// identity resolver the check passes — there is nothing to resolve.
func checkIdentity(ctx *checkContext) error {
	if ctx.in.IdentityResolver == nil {
		return nil
	}
	root := ctx.in.Chain[len(ctx.in.Chain)-1].Authority
	d, err := did.Parse(root.Subject)
	if err != nil {
		return fmt.Errorf("verification: identity: %w: %v", ErrIdentityUnresolved, err)
	}
	if _, err := ctx.in.IdentityResolver.Resolve(d); err != nil {
		return fmt.Errorf("verification: identity: %w: %v", ErrIdentityUnresolved, err)
	}
	return nil
}
