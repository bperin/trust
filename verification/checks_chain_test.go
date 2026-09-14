package verification

import (
	"errors"
	"testing"
	"time"

	"context"

	"github.com/bperin/trust/authority"

	"github.com/bperin/trust/delegation"
	"github.com/bperin/trust/identity/did"
)

func TestCheckAuthorityProof_Pass(t *testing.T) {
	t.Parallel()
	f := buildFixture(t)
	if _, err := runSingleCheck(t, f, checkAuthorityProof); err != nil {
		t.Errorf("valid chain failed authority proof: %v", err)
	}
}

func TestCheckAuthorityProof_BadProof(t *testing.T) {
	t.Parallel()
	f := buildFixture(t)
	f.chain[1].PublicKey = f.rootPub
	ctx, err := runSingleCheck(t, f, checkAuthorityProof)
	if !errors.Is(err, ErrAuthorityInvalid) {
		t.Errorf("err = %v, want ErrAuthorityInvalid", err)
	}
	if ctx.hop != 1 {
		t.Errorf("Hop = %d, want 1", ctx.hop)
	}
}

func TestCheckChainLink_Pass(t *testing.T) {
	t.Parallel()
	f := buildFixture(t)
	if _, err := runSingleCheck(t, f, checkChainLink); err != nil {
		t.Errorf("valid chain failed chain link: %v", err)
	}
}

func TestCheckChainLink_SplicedParent(t *testing.T) {
	t.Parallel()
	f := buildFixture(t)
	// Point the leaf's parent at the root, skipping the mid hop.
	rootRef, err := hashRef(authority.CanonicalHash(f.chain[2].Authority))
	if err != nil {
		t.Fatalf("root hash: %v", err)
	}
	f.chain[0].Authority.Parent = &rootRef
	ctx, err := runSingleCheck(t, f, checkChainLink)
	if !errors.Is(err, ErrChainBroken) {
		t.Errorf("err = %v, want ErrChainBroken", err)
	}
	if ctx.hop != 0 {
		t.Errorf("Hop = %d, want 0", ctx.hop)
	}
}

func TestCheckChainLink_NilParent(t *testing.T) {
	t.Parallel()
	f := buildFixture(t)
	f.chain[0].Authority.Parent = nil
	if _, err := runSingleCheck(t, f, checkChainLink); !errors.Is(err, ErrChainBroken) {
		t.Errorf("err = %v, want ErrChainBroken", err)
	}
}

func TestCheckChainLink_DepthExceeded(t *testing.T) {
	t.Parallel()
	f := buildFixture(t)
	// Mid declares MaxDepth 1; root allows 2 — child not strictly below.
	depth := 2
	f.chain[1].Authority.DelegationConstraints.MaxDepth = &depth
	depthRoot := 2
	f.chain[2].Authority.DelegationConstraints.MaxDepth = &depthRoot
	// Mutating mid changes its canonical hash; re-link leaf.Parent.
	if err := setParentFromHash(f.chain[0].Authority, f.chain[1].Authority); err != nil {
		t.Fatalf("re-link leaf: %v", err)
	}
	_, err := runSingleCheck(t, f, checkChainLink)
	if !errors.Is(err, ErrDelegationDepth) {
		t.Errorf("err = %v, want ErrDelegationDepth", err)
	}
}

func TestCheckChainLink_CapabilityEscalation(t *testing.T) {
	t.Parallel()
	f := buildFixture(t)
	// Leaf claims revoke, mid does not grant it; mid's hash is
	// untouched so the parent reference stays valid.
	f.chain[0].Authority.Capabilities = append(f.chain[0].Authority.Capabilities, authority.CapabilityRevoke)
	_, err := runSingleCheck(t, f, checkChainLink)
	if !errors.Is(err, ErrCapabilityNotGranted) {
		t.Errorf("err = %v, want ErrCapabilityNotGranted", err)
	}
	var _ = delegation.ErrCapabilityEscalation
}

func TestCheckChainLink_ScopeEscalation(t *testing.T) {
	t.Parallel()
	f := buildFixture(t)
	// Mid narrows resources; leaf keeps them unconstrained — a
	// widening. Re-link leaf.Parent to mid's new canonical hash.
	f.chain[1].Authority.Scope.Resources = []string{"res-a"}
	if err := setParentFromHash(f.chain[0].Authority, f.chain[1].Authority); err != nil {
		t.Fatalf("re-link leaf: %v", err)
	}
	_, err := runSingleCheck(t, f, checkChainLink)
	if !errors.Is(err, ErrScopeViolation) {
		t.Errorf("err = %v, want ErrScopeViolation", err)
	}
}

func TestCheckChainLink_SingleHopVacuous(t *testing.T) {
	t.Parallel()
	f := buildFixture(t)
	in := f.inputs()
	in.Chain = in.Chain[len(in.Chain)-1:]
	prov, _ := BuildProvenance(in)
	ctx := &checkContext{in: in, now: f.now, prov: prov, e: NewEngine(), hop: -1}
	if err := checkChainLink(ctx); err != nil {
		t.Errorf("single-hop chain link should pass vacuously, got %v", err)
	}
}

func TestCheckTemporal_Pass(t *testing.T) {
	t.Parallel()
	f := buildFixture(t)
	if _, err := runSingleCheck(t, f, checkTemporal); err != nil {
		t.Errorf("valid windows failed temporal: %v", err)
	}
}

func TestCheckTemporal_NotYetValid(t *testing.T) {
	t.Parallel()
	f := buildFixture(t)
	in := f.inputs()
	in.Now = f.now.Add(-2 * time.Hour)
	prov, _ := BuildProvenance(in)
	ctx := &checkContext{in: in, now: in.Now, prov: prov, e: NewEngine(), hop: -1}
	err := checkTemporal(ctx)
	if !errors.Is(err, ErrNotYetValid) {
		t.Errorf("err = %v, want ErrNotYetValid", err)
	}
}

func TestCheckTemporal_Expired(t *testing.T) {
	t.Parallel()
	f := buildFixture(t)
	in := f.inputs()
	in.Now = f.now.Add(2 * time.Hour)
	prov, _ := BuildProvenance(in)
	ctx := &checkContext{in: in, now: in.Now, prov: prov, e: NewEngine(), hop: -1}
	err := checkTemporal(ctx)
	if !errors.Is(err, ErrExpired) {
		t.Errorf("err = %v, want ErrExpired", err)
	}
}

func TestCheckTemporal_HopExpired(t *testing.T) {
	t.Parallel()
	f := buildFixture(t)
	// Mid authority's window ends before now; re-sign so its proof stays valid.
	notAfter := f.now.Add(-time.Minute)
	f.chain[1].Authority.Validity.NotAfter = notAfter
	if err := authority.SignAuthority(context.Background(), f.chain[1].Authority, mustSigner(t, f.midPriv), "mid-key"); err != nil {
		t.Fatalf("re-sign mid: %v", err)
	}
	// The leaf's parent ref still matches (hash unchanged by validity? No—) rebuild.
	in := f.inputs()
	prov, err := BuildProvenance(in)
	if err != nil {
		t.Fatalf("BuildProvenance: %v", err)
	}
	ctx := &checkContext{in: in, now: f.now, prov: prov, e: NewEngine(), hop: -1}
	err = checkTemporal(ctx)
	if !errors.Is(err, ErrExpired) {
		t.Errorf("err = %v, want ErrExpired", err)
	}
	if ctx.hop != 1 {
		t.Errorf("Hop = %d, want 1", ctx.hop)
	}
}

func TestCheckTemporal_BoundariesInclusive(t *testing.T) {
	t.Parallel()
	f := buildFixture(t)
	in := f.inputs()
	in.Now = f.att.Validity.NotBefore
	prov, _ := BuildProvenance(in)
	ctx := &checkContext{in: in, now: in.Now, prov: prov, e: NewEngine(), hop: -1}
	if err := checkTemporal(ctx); err != nil {
		t.Errorf("now == NotBefore should pass, got %v", err)
	}
	in.Now = f.now.Add(time.Hour)
	ctx = &checkContext{in: in, now: in.Now, prov: prov, e: NewEngine(), hop: -1}
	if err := checkTemporal(ctx); err != nil {
		t.Errorf("now == NotAfter should pass, got %v", err)
	}
}

func TestCheckRevocation_Pass(t *testing.T) {
	t.Parallel()
	f := buildFixture(t)
	if _, err := runSingleCheck(t, f, checkRevocation); err != nil {
		t.Errorf("active chain failed revocation: %v", err)
	}
}

func TestCheckRevocation_Revoked(t *testing.T) {
	t.Parallel()
	f := buildFixture(t)
	f.chain[1].Authority.Status = authority.StatusRevoked
	ctx, err := runSingleCheck(t, f, checkRevocation)
	if !errors.Is(err, ErrRevoked) {
		t.Errorf("err = %v, want ErrRevoked", err)
	}
	if ctx.hop != 1 {
		t.Errorf("Hop = %d, want 1", ctx.hop)
	}
}

func TestCheckRevocation_Superseded(t *testing.T) {
	t.Parallel()
	f := buildFixture(t)
	f.chain[1].Authority.Status = authority.StatusSuperseded
	_, err := runSingleCheck(t, f, checkRevocation)
	if !errors.Is(err, ErrSuperseded) {
		t.Errorf("err = %v, want ErrSuperseded", err)
	}
}

func TestCheckRevocation_ExpiredStatus(t *testing.T) {
	t.Parallel()
	f := buildFixture(t)
	f.chain[1].Authority.Status = authority.StatusExpired
	_, err := runSingleCheck(t, f, checkRevocation)
	if !errors.Is(err, ErrExpired) {
		t.Errorf("err = %v, want ErrExpired", err)
	}
}

func TestCheckIdentity_Pass(t *testing.T) {
	t.Parallel()
	f := buildFixture(t)
	if _, err := runSingleCheck(t, f, checkIdentity); err != nil {
		t.Errorf("identity check failed: %v", err)
	}
}

func TestCheckIdentity_Unresolved(t *testing.T) {
	t.Parallel()
	f := buildFixture(t)
	f.resolver.docs = map[string]*did.Document{}
	_, err := runSingleCheck(t, f, checkIdentity)
	if !errors.Is(err, ErrIdentityUnresolved) {
		t.Errorf("err = %v, want ErrIdentityUnresolved", err)
	}
}

func TestCheckIdentity_NoResolverPasses(t *testing.T) {
	t.Parallel()
	f := buildFixture(t)
	in := f.inputs()
	in.IdentityResolver = nil
	prov, _ := BuildProvenance(in)
	ctx := &checkContext{in: in, now: f.now, prov: prov, e: NewEngine(), hop: -1}
	if err := checkIdentity(ctx); err != nil {
		t.Errorf("identity without resolver should pass, got %v", err)
	}
}
