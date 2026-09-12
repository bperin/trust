package authority

import (
	"fmt"
	"time"
)

// Capabilities is a set of canonical capability strings delegated to
// a child key (e.g., "product.attest", "inventory.attest",
// "pricing.attest", "revoke", "delegate"). Capabilities are a fixed
// vocabulary — not a free-form grammar — and a child may only hold
// capabilities covered by its parent's effective set.
type Capabilities []string

// Monetary is a monetary limit expressed as an integer amount in a
// named currency. The amount is denominated in the currency's
// smallest unit; the currency is an ISO 4217-style code carried as
// an opaque canonical string.
type Monetary struct {
	// Amount is the limit in the currency's smallest unit.
	Amount uint64 `json:"amount"`

	// Currency is the currency identifier (e.g., "USD").
	Currency string `json:"currency"`
}

// TimeWindow bounds the validity period of a delegation. A zero
// NotBefore means no lower bound; a zero NotAfter means no upper
// bound. A child window must lie entirely within its parent's.
type TimeWindow struct {
	// NotBefore is the earliest instant the delegation is valid.
	NotBefore time.Time

	// NotAfter is the latest instant the delegation is valid.
	NotAfter time.Time
}

// Scope is the effective delegated authority produced by
// intersecting a delegation chain. Every dimension is a bound: an
// empty slice or nil pointer means unrestricted on that dimension.
// VerifyChain returns the tightest Scope implied by the chain — a
// subset of every ancestor's declared bounds.
type Scope struct {
	// Resources is the set of resource identifiers the leaf may act
	// on. Empty means unrestricted.
	Resources []string

	// Actions is the effective capability set — the intersection of
	// every link's declared Capabilities. Empty means unrestricted.
	Actions []string

	// Organizations is the set of organizations the leaf may act
	// for. Empty means unrestricted.
	Organizations []string

	// Geographies is the set of geographic regions in scope. Empty
	// means unrestricted.
	Geographies []string

	// Channels is the set of channels (e.g., "online", "retail") in
	// scope. Empty means unrestricted.
	Channels []string

	// TimeWindow is the effective validity window — the latest
	// NotBefore and earliest NotAfter across the chain. Nil means
	// unbounded.
	TimeWindow *TimeWindow

	// QuantityLimit is the smallest quantity limit declared along
	// the chain. Nil means unlimited.
	QuantityLimit *uint64

	// MonetaryLimit is the smallest monetary limit declared along
	// the chain (per currency). Nil means unlimited.
	MonetaryLimit *Monetary

	// DelegationDepth is the remaining further-delegation headroom:
	// the minimum over the chain of each link's declared depth minus
	// the links that follow it. Nil means unbounded.
	DelegationDepth *uint
}

// dedupStrings returns a copy of in with duplicates removed, order
// preserved.
func dedupStrings(in []string) []string {
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}

// intersectSet intersects one set-valued scope dimension. An empty
// child set inherits the parent's effective set; an empty parent set
// is unrestricted and the child's declared set becomes the bound.
// When both are non-empty every child entry must appear in the
// parent — otherwise the child exceeds its parent's scope and the
// given sentinel is returned.
func intersectSet(parent, child []string, sentinel error, idx int, dim string) ([]string, error) {
	if len(child) == 0 {
		return parent, nil
	}
	if len(parent) == 0 {
		return dedupStrings(child), nil
	}
	allowed := make(map[string]struct{}, len(parent))
	for _, p := range parent {
		allowed[p] = struct{}{}
	}
	for _, c := range child {
		if _, ok := allowed[c]; !ok {
			return nil, fmt.Errorf("%w: link %d %s %q not in parent scope", sentinel, idx, dim, c)
		}
	}
	return dedupStrings(child), nil
}

// intersectWindow intersects the temporal scope dimension. A nil
// child inherits the parent window; a zero child endpoint inherits
// that endpoint. The resolved child window must lie entirely within
// the parent's and must be non-empty.
func intersectWindow(parent, child *TimeWindow, idx int) (*TimeWindow, error) {
	if child == nil {
		return parent, nil
	}
	eff := &TimeWindow{NotBefore: child.NotBefore, NotAfter: child.NotAfter}
	if parent != nil {
		if eff.NotBefore.IsZero() {
			eff.NotBefore = parent.NotBefore
		}
		if eff.NotAfter.IsZero() {
			eff.NotAfter = parent.NotAfter
		}
		if !parent.NotBefore.IsZero() && eff.NotBefore.Before(parent.NotBefore) {
			return nil, fmt.Errorf("%w: link %d notBefore %s precedes parent %s",
				ErrScopeViolation, idx, eff.NotBefore, parent.NotBefore)
		}
		if !parent.NotAfter.IsZero() && eff.NotAfter.After(parent.NotAfter) {
			return nil, fmt.Errorf("%w: link %d notAfter %s exceeds parent %s",
				ErrScopeViolation, idx, eff.NotAfter, parent.NotAfter)
		}
	}
	if !eff.NotBefore.IsZero() && !eff.NotAfter.IsZero() && eff.NotBefore.After(eff.NotAfter) {
		return nil, fmt.Errorf("%w: link %d window %s..%s is empty",
			ErrScopeViolation, idx, eff.NotBefore, eff.NotAfter)
	}
	return eff, nil
}

// intersectQuantity intersects the quantity limit dimension: a nil
// child inherits the parent's bound, and a declared child limit must
// not exceed the parent's.
func intersectQuantity(parent, child *uint64, idx int) (*uint64, error) {
	if child == nil {
		return parent, nil
	}
	if parent == nil {
		c := *child
		return &c, nil
	}
	if *child > *parent {
		return nil, fmt.Errorf("%w: link %d quantity limit %d exceeds parent %d",
			ErrScopeViolation, idx, *child, *parent)
	}
	c := *child
	return &c, nil
}

// intersectMonetary intersects the monetary limit dimension: a nil
// child inherits the parent's bound, and a declared child limit must
// share the parent's currency and not exceed its amount.
func intersectMonetary(parent, child *Monetary, idx int) (*Monetary, error) {
	if child == nil {
		return parent, nil
	}
	if parent == nil {
		c := *child
		return &c, nil
	}
	if child.Currency != parent.Currency {
		return nil, fmt.Errorf("%w: link %d currency %q outside parent %q",
			ErrScopeViolation, idx, child.Currency, parent.Currency)
	}
	if child.Amount > parent.Amount {
		return nil, fmt.Errorf("%w: link %d monetary limit %d %s exceeds parent %d",
			ErrScopeViolation, idx, child.Amount, child.Currency, parent.Amount)
	}
	c := *child
	return &c, nil
}
