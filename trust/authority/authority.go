package authority

import (
	"crypto"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"time"

	"github.com/bperin/trust/canonical"
	jwkutil "github.com/bperin/trust/identity/jwk"
	"github.com/bperin/trust/signature"
)

// Status values for DelegationLink.Status. Status is signed metadata
// carried for the application; VerifyChain does not gate on it —
// revocation is expressed through key versions and the optional
// VerifyOptions.LatestVersions map.
const (
	// StatusActive marks a link whose key may exercise the delegated
	// scope.
	StatusActive = "active"

	// StatusRevoked marks a link the issuer has withdrawn.
	// Applications should treat revoked links as unusable even when
	// the chain cryptographically verifies.
	StatusRevoked = "revoked"
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

// DelegationLink is one signed delegation in a chain. The parent
// key — the root anchor for the first link, the preceding link's
// PublicKey otherwise — signs the canonical hash of every field
// except ParentSignature. The signature and Algorithm fields are
// the PARENT's: Algorithm is the algorithm of the signing parent
// key, resolved via signature.AlgorithmForPrivateKey at SignLink
// time.
type DelegationLink struct {
	// KeyID identifies the delegated key. Applications use it as the
	// lookup key for VerifyOptions.LatestVersions.
	KeyID string

	// ParentAuthorityRef is the canonical hash of the preceding link
	// — the complete, signed parent. It is zero for the link issued
	// directly by the root anchor.
	ParentAuthorityRef [32]byte

	// PublicKey is the delegated child key — a trust public key type
	// (*ed25519.PublicKey, *secp256k1.PublicKey, *ecdsa.PublicKey,
	// *rsa.PSSPublicKey, or *rsa.PKCS1PublicKey).
	PublicKey crypto.PublicKey

	// Algorithm is the signature.Algorithm of the parent key that
	// produced ParentSignature. SignLink derives it from the signer;
	// VerifyChain requires it to match the parent key's algorithm.
	Algorithm signature.Algorithm

	// Capabilities is the canonical capability set delegated to this
	// key — the action/capability scope dimension.
	Capabilities Capabilities

	// ResourceScope bounds the resources this key may act on. Empty
	// inherits the parent's effective resource scope.
	ResourceScope []string

	// OrganizationScope bounds the organizations this key may act
	// for. Empty inherits the parent's effective organization scope.
	OrganizationScope []string

	// GeographicScope bounds the geographies this key may act in.
	// Empty inherits the parent's effective geographic scope.
	GeographicScope []string

	// TemporalScope bounds the validity window. Nil inherits the
	// parent's effective window; a zero endpoint inherits that
	// endpoint from the parent.
	TemporalScope *TimeWindow

	// ChannelScope bounds the channels this key may act through.
	// Empty inherits the parent's effective channel scope.
	ChannelScope []string

	// QuantityLimit caps the quantity this key may act on. Nil
	// inherits the parent's effective limit; a declared limit must
	// not exceed it.
	QuantityLimit *uint64

	// MonetaryLimit caps the monetary amount this key may act on.
	// Nil inherits the parent's effective limit; a declared limit
	// must share the parent's currency and not exceed its amount.
	MonetaryLimit *Monetary

	// DelegationDepth caps how many further links may follow this
	// one. Nil means no additional constraint.
	DelegationDepth *uint

	// Status is the link's lifecycle state (StatusActive or
	// StatusRevoked). It is signed metadata; VerifyChain carries it
	// but does not gate on it.
	Status string

	// KeyVersion is the version of this delegated key. Versions must
	// be non-decreasing within a presented chain.
	KeyVersion uint64

	// ParentSignature is the parent key's signature over the
	// canonical hash of the unsigned link payload, produced by
	// SignLink.
	ParentSignature []byte
}

// DelegationChain is an ordered sequence of delegation links from
// the root-issued link (index 0) to the leaf signing key. Build a
// chain with BuildChain; verify it with VerifyChain.
type DelegationChain []DelegationLink

// linkWire is the canonical projection of a DelegationLink for
// hashing. The public key serializes as an [RFC 7517] JWK object,
// the algorithm as an [RFC 7518] JOSE name, the parent authority
// reference as base64url, and the temporal scope as RFC 3339
// strings normalized to UTC so equivalent instants hash
// identically.
type linkWire struct {
	KeyID              string          `json:"keyId"`
	ParentAuthorityRef string          `json:"parentAuthorityRef"`
	PublicKey          map[string]any  `json:"publicKey"`
	Algorithm          string          `json:"algorithm"`
	Capabilities       []string        `json:"capabilities"`
	ResourceScope      []string        `json:"resourceScope,omitempty"`
	OrganizationScope  []string        `json:"organizationScope,omitempty"`
	GeographicScope    []string        `json:"geographicScope,omitempty"`
	TemporalScope      *timeWindowWire `json:"temporalScope,omitempty"`
	ChannelScope       []string        `json:"channelScope,omitempty"`
	QuantityLimit      *uint64         `json:"quantityLimit,omitempty"`
	MonetaryLimit      *Monetary       `json:"monetaryLimit,omitempty"`
	DelegationDepth    *uint           `json:"delegationDepth,omitempty"`
	Status             string          `json:"status"`
	KeyVersion         uint64          `json:"keyVersion"`
	ParentSignature    []byte          `json:"parentSignature,omitempty"`
}

// timeWindowWire is the canonical projection of a TimeWindow:
// RFC 3339 strings in UTC. Zero times serialize as the zero-year
// instant, which is deterministic.
type timeWindowWire struct {
	NotBefore string `json:"notBefore"`
	NotAfter  string `json:"notAfter"`
}

// formatTime renders t in UTC RFC 3339 (nanosecond) form for the
// canonical wire projection.
func formatTime(t time.Time) string {
	return t.UTC().Format(time.RFC3339Nano)
}

// wire projects a link to its canonical form. When signed is false
// the projection omits ParentSignature — the payload the parent
// signs; when true it includes the signature — the link's complete
// content identity.
func (l *DelegationLink) wire(signed bool) (*linkWire, error) {
	if l.PublicKey == nil {
		return nil, ErrMissingPublicKey
	}
	jwk, err := jwkutil.Marshal(l.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("authority: marshal public key: %w", err)
	}
	w := &linkWire{
		KeyID:              l.KeyID,
		ParentAuthorityRef: base64.RawURLEncoding.EncodeToString(l.ParentAuthorityRef[:]),
		PublicKey:          jwk,
		Algorithm:          l.Algorithm.JOSE(),
		Capabilities:       []string(l.Capabilities),
		ResourceScope:      l.ResourceScope,
		OrganizationScope:  l.OrganizationScope,
		GeographicScope:    l.GeographicScope,
		ChannelScope:       l.ChannelScope,
		QuantityLimit:      l.QuantityLimit,
		MonetaryLimit:      l.MonetaryLimit,
		DelegationDepth:    l.DelegationDepth,
		Status:             l.Status,
		KeyVersion:         l.KeyVersion,
	}
	if l.TemporalScope != nil {
		w.TemporalScope = &timeWindowWire{
			NotBefore: formatTime(l.TemporalScope.NotBefore),
			NotAfter:  formatTime(l.TemporalScope.NotAfter),
		}
	}
	if signed {
		w.ParentSignature = l.ParentSignature
	}
	return w, nil
}

// signingHash returns the [FIPS 180-4] SHA-256 canonical hash of the
// unsigned link payload — the digest the parent signs in
// ParentSignature.
func signingHash(l *DelegationLink) ([32]byte, error) {
	w, err := l.wire(false)
	if err != nil {
		return [32]byte{}, err
	}
	return canonical.CanonicalHash(w)
}

// CanonicalHash returns the [FIPS 180-4] SHA-256 digest of the
// [RFC 8785] canonical form of the complete, signed link — the
// link's content identity. This is the value a child link carries in
// ParentAuthorityRef and the value bound into proofs and Merkle
// leaves downstream.
func CanonicalHash(l *DelegationLink) ([32]byte, error) {
	if l == nil {
		return [32]byte{}, ErrNilLink
	}
	w, err := l.wire(true)
	if err != nil {
		return [32]byte{}, err
	}
	return canonical.CanonicalHash(w)
}

// SignLink signs l with the parent private key: it derives the
// signature algorithm from the signer via
// signature.AlgorithmForPrivateKey, canonicalizes the unsigned link
// (ParentSignature excluded), signs the canonical hash via
// signature.Sign, and stores the result in l.ParentSignature.
//
// parentSigner is a trust private key (crypto.PrivateKey — the same
// parameter convention as identity.Sign; the trust key types
// deliberately do not implement crypto.Signer). For the first link
// it is the root key; for later links it is the preceding link's
// private key. The package takes no custody of the key.
//
// Callers set l.ParentAuthorityRef — the canonical hash of the
// signed parent link, or zero for a root-issued link — before
// signing; the signature covers it.
func SignLink(l *DelegationLink, parentSigner crypto.PrivateKey) error {
	if l == nil {
		return ErrNilLink
	}
	if l.PublicKey == nil {
		return ErrMissingPublicKey
	}
	if parentSigner == nil {
		return ErrMissingSigner
	}
	alg, err := signature.AlgorithmForPrivateKey(parentSigner)
	if err != nil {
		return fmt.Errorf("authority sign: %w", err)
	}
	l.Algorithm = alg
	l.ParentSignature = nil
	h, err := signingHash(l)
	if err != nil {
		return fmt.Errorf("authority sign: %w", err)
	}
	sig, err := signature.Sign(alg, parentSigner, h[:])
	if err != nil {
		return fmt.Errorf("authority sign: %w", err)
	}
	l.ParentSignature = sig
	return nil
}

// BuildChain assembles an ordered DelegationChain from signed links
// and validates its structure: the first link must have a zero
// ParentAuthorityRef (it is issued directly by the root anchor),
// every link must carry a ParentSignature, and each subsequent
// link's ParentAuthorityRef must equal the canonical hash of the
// preceding link — compared in constant time. BuildChain does not
// verify signatures; that is VerifyChain's job, which also needs the
// root public key.
func BuildChain(links ...DelegationLink) (DelegationChain, error) {
	if len(links) == 0 {
		return nil, ErrEmptyChain
	}
	if links[0].ParentAuthorityRef != ([32]byte{}) {
		return nil, fmt.Errorf("%w: link 0 has a non-zero parent authority ref", ErrChainBroken)
	}
	for i := range links {
		if len(links[i].ParentSignature) == 0 {
			return nil, fmt.Errorf("%w: link %d is unsigned", ErrBrokenSignature, i)
		}
		if i == 0 {
			continue
		}
		h, err := CanonicalHash(&links[i-1])
		if err != nil {
			return nil, fmt.Errorf("authority build: %w", err)
		}
		if subtle.ConstantTimeCompare(links[i].ParentAuthorityRef[:], h[:]) != 1 {
			return nil, fmt.Errorf("%w: link %d parent authority ref does not match link %d",
				ErrChainBroken, i, i-1)
		}
	}
	chain := make(DelegationChain, len(links))
	copy(chain, links)
	return chain, nil
}
