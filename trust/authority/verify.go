package authority

import (
	"crypto"
	"crypto/subtle"
	"errors"
	"fmt"

	"github.com/bperin/trust/signature"
)

// Sentinel errors returned by SignLink, BuildChain, and VerifyChain.
// Check them with errors.Is.
var (
	// ErrScopeViolation is returned when a link declares a scope
	// outside its parent's effective scope — a resource,
	// organization, geography, channel, time window, quantity, or
	// monetary bound the parent does not cover.
	ErrScopeViolation = errors.New("authority: scope violation")

	// ErrCapabilityNotCovered is returned when a link declares a
	// capability outside its parent's effective capability set.
	ErrCapabilityNotCovered = errors.New("authority: capability not covered by parent")

	// ErrBrokenSignature is returned when a link's ParentSignature is
	// missing, malformed, or does not verify against the parent key.
	ErrBrokenSignature = errors.New("authority: broken parent signature")

	// ErrKeyVersionNonMonotonic is returned when a link's KeyVersion
	// is lower than the preceding link's — versions must be
	// non-decreasing within a presented chain.
	ErrKeyVersionNonMonotonic = errors.New("authority: key version non-monotonic within chain")

	// ErrStaleKeyVersion is returned when VerifyOptions.LatestVersions
	// records a newer version for a link's KeyID than the chain
	// presents.
	ErrStaleKeyVersion = errors.New("authority: key version below latest known")

	// ErrDepthExceeded is returned when a link's DelegationDepth is
	// smaller than the number of links that follow it.
	ErrDepthExceeded = errors.New("authority: delegation depth exceeded")

	// ErrEmptyChain is returned when a chain contains no links.
	ErrEmptyChain = errors.New("authority: empty delegation chain")

	// ErrChainBroken is returned when a link's ParentAuthorityRef
	// does not match the canonical hash of the preceding link — or,
	// for the first link, is not zero.
	ErrChainBroken = errors.New("authority: delegation chain broken")

	// ErrNilLink is returned when a nil *DelegationLink is passed.
	ErrNilLink = errors.New("authority: nil delegation link")

	// ErrMissingPublicKey is returned when a link carries no
	// delegated public key.
	ErrMissingPublicKey = errors.New("authority: missing public key")

	// ErrMissingRootKey is returned when VerifyChain is called with a
	// nil root public key.
	ErrMissingRootKey = errors.New("authority: missing root public key")

	// ErrMissingSigner is returned when SignLink is called with a nil
	// parent signer.
	ErrMissingSigner = errors.New("authority: missing parent signer")

	// ErrAlgorithmMismatch is returned when a link's declared
	// Algorithm does not match the algorithm derived from the parent
	// key. This prevents algorithm-confusion attacks where a link
	// claims an algorithm the signing key cannot perform.
	ErrAlgorithmMismatch = errors.New("authority: algorithm does not match parent key")
)

// VerifyOptions carries optional verification inputs. All fields are
// advisory: an absent option skips the corresponding check.
type VerifyOptions struct {
	// LatestVersions maps a link's KeyID to the newest KeyVersion the
	// caller knows was issued for that key. When present, a link
	// whose KeyVersion is below the latest known fails with
	// ErrStaleKeyVersion. A nil map skips stale-version detection —
	// freshness is an application concern.
	LatestVersions map[string]uint64
}

// VerifyChain verifies a delegation chain against the root public
// key and returns the effective intersected Scope. It is a pure
// function: no I/O, no lookups, no global state.
//
// For each link, in order:
//
//  1. The parent key is resolved — rootPub for the first link, the
//     preceding link's PublicKey for the rest — and the link's
//     declared Algorithm must match it (ErrAlgorithmMismatch).
//  2. ParentSignature must verify over the canonical hash of the
//     unsigned link payload under the parent key
//     (ErrBrokenSignature).
//  3. ParentAuthorityRef must be zero for the first link and equal
//     the canonical hash of the preceding link otherwise, compared
//     in constant time (ErrChainBroken).
//  4. KeyVersion must be non-decreasing across the chain
//     (ErrKeyVersionNonMonotonic); with VerifyOptions.LatestVersions
//     set, a version below the latest known fails with
//     ErrStaleKeyVersion.
//  5. DelegationDepth must cover the number of links that follow
//     (ErrDepthExceeded).
//  6. Every scope dimension is re-intersected into the running
//     effective scope: capabilities (ErrCapabilityNotCovered) and
//     resources, organizations, geographies, channels, time window,
//     quantity, and monetary limits (ErrScopeViolation). An empty
//     child set or nil bound inherits the parent's effective scope;
//     a non-empty declaration must be a subset (or tighter bound) of
//     it — a child can only ever narrow its parent's authority.
//
// The returned Scope is the tightest bound implied by the whole
// chain; it is by construction a subset of every ancestor's
// declared scope.
func VerifyChain(chain DelegationChain, rootPub crypto.PublicKey, opts ...VerifyOptions) (Scope, error) {
	if len(chain) == 0 {
		return Scope{}, ErrEmptyChain
	}
	if rootPub == nil {
		return Scope{}, ErrMissingRootKey
	}
	rootAlg, err := signature.AlgorithmForPublicKey(rootPub)
	if err != nil {
		return Scope{}, fmt.Errorf("authority verify: %w", err)
	}
	var opt VerifyOptions
	if len(opts) > 0 {
		opt = opts[0]
	}

	var eff Scope
	n := len(chain)
	for i := range chain {
		link := &chain[i]
		if link.PublicKey == nil {
			return Scope{}, fmt.Errorf("%w: link %d", ErrMissingPublicKey, i)
		}

		parentPub := rootPub
		parentAlg := rootAlg
		if i > 0 {
			parentPub = chain[i-1].PublicKey
			if parentAlg, err = signature.AlgorithmForPublicKey(parentPub); err != nil {
				return Scope{}, fmt.Errorf("authority verify: link %d parent key: %w", i, err)
			}
		}
		if link.Algorithm != parentAlg {
			return Scope{}, fmt.Errorf("%w: link %d declares %q, parent key is %q",
				ErrAlgorithmMismatch, i, link.Algorithm.JOSE(), parentAlg.JOSE())
		}

		// Parent signature over the unsigned payload.
		if len(link.ParentSignature) == 0 {
			return Scope{}, fmt.Errorf("%w: link %d has no parent signature", ErrBrokenSignature, i)
		}
		h, err := signingHash(link)
		if err != nil {
			return Scope{}, fmt.Errorf("authority verify: link %d: %w", i, err)
		}
		ok, err := signature.Verify(link.Algorithm, parentPub, link.ParentSignature, h[:])
		if err != nil {
			return Scope{}, fmt.Errorf("%w: link %d: %w", ErrBrokenSignature, i, err)
		}
		if !ok {
			return Scope{}, fmt.Errorf("%w: link %d", ErrBrokenSignature, i)
		}

		// Chain structure: the ref binds the link to its declared
		// parent and is part of the signed payload.
		if i == 0 {
			if link.ParentAuthorityRef != ([32]byte{}) {
				return Scope{}, fmt.Errorf("%w: link 0 must have a zero parent authority ref", ErrChainBroken)
			}
		} else {
			ph, err := CanonicalHash(&chain[i-1])
			if err != nil {
				return Scope{}, fmt.Errorf("authority verify: link %d: %w", i, err)
			}
			if subtle.ConstantTimeCompare(link.ParentAuthorityRef[:], ph[:]) != 1 {
				return Scope{}, fmt.Errorf("%w: link %d parent authority ref does not match link %d",
					ErrChainBroken, i, i-1)
			}
		}

		// Key version monotonicity and optional stale detection.
		if i > 0 && link.KeyVersion < chain[i-1].KeyVersion {
			return Scope{}, fmt.Errorf("%w: link %d version %d is below link %d version %d",
				ErrKeyVersionNonMonotonic, i, link.KeyVersion, i-1, chain[i-1].KeyVersion)
		}
		if opt.LatestVersions != nil {
			if latest, ok := opt.LatestVersions[link.KeyID]; ok && link.KeyVersion < latest {
				return Scope{}, fmt.Errorf("%w: link %d key %q at version %d, latest known %d",
					ErrStaleKeyVersion, i, link.KeyID, link.KeyVersion, latest)
			}
		}

		// Delegation depth: the declared depth must cover every link
		// that follows; the effective depth is the tightest
		// remaining headroom.
		if link.DelegationDepth != nil {
			descendants := n - 1 - i
			if uint64(descendants) > uint64(*link.DelegationDepth) {
				return Scope{}, fmt.Errorf("%w: link %d allows %d further delegations, %d follow",
					ErrDepthExceeded, i, *link.DelegationDepth, descendants)
			}
			remaining := *link.DelegationDepth - uint(descendants)
			if eff.DelegationDepth == nil || remaining < *eff.DelegationDepth {
				eff.DelegationDepth = uintPtr(remaining)
			}
		}

		// Scope intersection across all nine dimensions.
		if eff.Actions, err = intersectSet(eff.Actions, []string(link.Capabilities),
			ErrCapabilityNotCovered, i, "capability"); err != nil {
			return Scope{}, err
		}
		if eff.Resources, err = intersectSet(eff.Resources, link.ResourceScope,
			ErrScopeViolation, i, "resource"); err != nil {
			return Scope{}, err
		}
		if eff.Organizations, err = intersectSet(eff.Organizations, link.OrganizationScope,
			ErrScopeViolation, i, "organization"); err != nil {
			return Scope{}, err
		}
		if eff.Geographies, err = intersectSet(eff.Geographies, link.GeographicScope,
			ErrScopeViolation, i, "geography"); err != nil {
			return Scope{}, err
		}
		if eff.Channels, err = intersectSet(eff.Channels, link.ChannelScope,
			ErrScopeViolation, i, "channel"); err != nil {
			return Scope{}, err
		}
		if eff.TimeWindow, err = intersectWindow(eff.TimeWindow, link.TemporalScope, i); err != nil {
			return Scope{}, err
		}
		if eff.QuantityLimit, err = intersectQuantity(eff.QuantityLimit, link.QuantityLimit, i); err != nil {
			return Scope{}, err
		}
		if eff.MonetaryLimit, err = intersectMonetary(eff.MonetaryLimit, link.MonetaryLimit, i); err != nil {
			return Scope{}, err
		}
	}
	return eff, nil
}

// uintPtr returns a pointer to a copy of v.
func uintPtr(v uint) *uint { return &v }
