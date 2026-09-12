// Package identity binds a stable organization identifier (a DID or
// UUID) to a customer-controlled root public key and supports
// authorized rotation of that root key.
//
// An Organization document is self-verifying: Signature is produced
// by the root private key over the [FIPS 180-4] SHA-256 canonical
// hash of the unsigned document, where the canonical form is the
// [RFC 8785] JSON Canonicalization Scheme applied to a projection
// that serializes public keys as [RFC 7517] JWKs and algorithms as
// [RFC 7518] JOSE names. A Rotation record embedded in the document
// proves that the prior root authorized the current root:
// PreviousRootSignature is the prior root's signature over the
// canonical rotation record.
//
// Signing and verification dispatch through trust/signature, so all
// registered algorithms are supported: Ed25519 [RFC 8032], secp256k1
// [SEC 2 v2]; [RFC 6979]; [EIP-2], ECDSA P-256 and P-384
// [FIPS 186-4], and RSA-PSS / RSA PKCS#1 v1.5 [RFC 8017].
//
// The package holds no private key material and no state. Sign and
// ApplyRotation take the caller's crypto.PrivateKey (the trust key
// types — consistent with jws.Sign, CoseSign, and
// attestation.Issue), and Verify is a pure function of the
// document: no I/O, no lookups, no global state.
package identity

import (
	"crypto"
	"crypto/subtle"
	"errors"
	"fmt"

	"github.com/bperin/trust/canonical"
	jwkutil "github.com/bperin/trust/identity/jwk"
	"github.com/bperin/trust/signature"
)

// Sentinel errors returned by Sign, Verify, and ApplyRotation. Check
// them with errors.Is.
var (
	// ErrNilDocument is returned when a nil *Organization is passed.
	ErrNilDocument = errors.New("identity: nil document")

	// ErrMissingRootKey is returned when a document or rotation
	// record carries no public key where one is required.
	ErrMissingRootKey = errors.New("identity: missing root public key")

	// ErrMissingSignature is returned by Verify when the document
	// carries no root signature.
	ErrMissingSignature = errors.New("identity: missing signature")

	// ErrInvalidSignature is returned when a signature does not
	// verify against the bound key, or when Sign is asked to sign
	// with a key that does not control the document's root.
	ErrInvalidSignature = errors.New("identity: invalid root signature")

	// ErrAlgorithmMismatch is returned when a declared
	// signature.Algorithm does not match the algorithm derived from
	// the corresponding key. This prevents algorithm-confusion
	// attacks where a document claims an algorithm its key cannot
	// perform.
	ErrAlgorithmMismatch = errors.New("identity: algorithm does not match key")

	// ErrRotationSequence is returned when a rotation sequence
	// number is zero or not greater than the sequence of the
	// rotation already recorded on the document.
	ErrRotationSequence = errors.New("identity: non-monotonic rotation sequence")

	// ErrRotationUnauthorized is returned when a rotation's
	// PreviousRootSignature does not verify against the prior root
	// key — the rotation was not authorized by the key it claims.
	ErrRotationUnauthorized = errors.New("identity: rotation not authorized by prior root")

	// ErrRotationInconsistent is returned when a rotation record is
	// internally inconsistent with the document that carries it —
	// for example, the rotation's new root key differs from the
	// document's root key.
	ErrRotationInconsistent = errors.New("identity: rotation record inconsistent with document")
)

// Organization is an identity document binding a stable identifier
// to a customer-controlled root public key. The document is signed
// by the root private key: Signature covers the SHA-256 canonical
// hash of every field except Signature itself.
//
// Root keys never sign attestations directly — they only sign this
// document and child-key issuance (enforced by callers downstream).
// This constrains root compromise to key-issuability, which is
// detectable and rollable through ApplyRotation.
type Organization struct {
	// ID is the stable organization identifier — a DID or UUID. It
	// is carried inside the signed payload and therefore cannot be
	// changed without invalidating the signature.
	ID string

	// RootPublicKey is the current root key — a trust public key
	// type (*ed25519.PublicKey, *secp256k1.PublicKey,
	// *ecdsa.PublicKey, *rsa.PSSPublicKey, or *rsa.PKCS1PublicKey).
	RootPublicKey crypto.PublicKey

	// RootAlgorithm is the signature.Algorithm bound to
	// RootPublicKey. It must equal the algorithm derived from the
	// key; Verify rejects documents where the two disagree.
	RootAlgorithm signature.Algorithm

	// Rotation, when non-nil, is the record of the most recent root
	// rotation — proof that the prior root authorized the current
	// root at a monotonically increasing sequence number.
	Rotation *Rotation

	// Signature is the root signature over the canonical hash of
	// the unsigned document, produced by Sign. For a rotated
	// document it is produced by the NEW root key.
	Signature []byte
}

// Rotation records a single authorized root-key rotation. The prior
// root signs the canonical rotation record (everything except
// PreviousRootSignature) to authorize the new root. The record is
// embedded in the signed document, so the current root attests to
// its own authorization chain one step back. Earlier history is
// application state — the document carries only the latest rotation.
type Rotation struct {
	// Sequence is a monotonically increasing rotation counter. The
	// first rotation is sequence 1; each subsequent rotation must
	// exceed the sequence recorded on the document being rotated.
	Sequence uint64

	// NewRootPublicKey is the root key established by this
	// rotation. On a verified document it always equals
	// Organization.RootPublicKey.
	NewRootPublicKey crypto.PublicKey

	// NewRootAlgorithm is the signature.Algorithm bound to
	// NewRootPublicKey.
	NewRootAlgorithm signature.Algorithm

	// PreviousRootPublicKey is the root key that authorized this
	// rotation — the document's root before the rotation was
	// applied. ApplyRotation fills it from the document's current
	// root; it is never caller-supplied there.
	PreviousRootPublicKey crypto.PublicKey

	// PreviousRootAlgorithm is the signature.Algorithm bound to
	// PreviousRootPublicKey.
	PreviousRootAlgorithm signature.Algorithm

	// PreviousRootSignature is the prior root's signature over the
	// canonical hash of the rotation record (all fields above). It
	// is the authorization proof for the rotation.
	PreviousRootSignature []byte
}

// organizationWire is the canonical projection of an Organization
// for hashing. Public keys serialize as [RFC 7517] JWK objects and
// algorithms as [RFC 7518] JOSE names; the Signature field is
// intentionally absent — the hash covers the unsigned document.
type organizationWire struct {
	ID            string         `json:"id"`
	RootPublicKey map[string]any `json:"rootPublicKey"`
	RootAlgorithm string         `json:"rootAlgorithm"`
	Rotation      *rotationWire  `json:"rotation,omitempty"`
}

// rotationWire is the canonical projection of a Rotation. For the
// rotation payload signed by the prior root, PreviousRootSignature
// is nil and omitted; for the document payload it is present, so the
// current root's signature also covers the authorization proof.
type rotationWire struct {
	Sequence              uint64         `json:"sequence"`
	NewRootPublicKey      map[string]any `json:"newRootPublicKey"`
	NewRootAlgorithm      string         `json:"newRootAlgorithm"`
	PreviousRootPublicKey map[string]any `json:"previousRootPublicKey"`
	PreviousRootAlgorithm string         `json:"previousRootAlgorithm"`
	PreviousRootSignature []byte         `json:"previousRootSignature,omitempty"`
}

// CanonicalHash returns the [FIPS 180-4] SHA-256 digest of the
// [RFC 8785] canonical form of the unsigned document — the identity
// of the trust object. This is the value bound into proofs and
// Merkle leaves downstream.
func CanonicalHash(doc *Organization) ([32]byte, error) {
	if doc == nil {
		return [32]byte{}, ErrNilDocument
	}
	w, err := docWire(doc)
	if err != nil {
		return [32]byte{}, err
	}
	return canonical.CanonicalHash(w)
}

// Sign signs doc with the root private key: it canonicalizes the
// unsigned document, signs the canonical hash via signature.Sign,
// and stores the result in doc.Signature.
//
// rootSigner is a trust private key (crypto.PrivateKey — the same
// parameter convention as jws.Sign and attestation.Issue; the trust
// key types deliberately do not implement crypto.Signer). The
// package takes no custody of the key.
//
// The signer must control doc.RootPublicKey: Sign derives the
// algorithm from the bound root key, requires the signer's algorithm
// to match, and verifies the produced signature against the root key
// before storing it — a signer that is not the bound root fails with
// ErrInvalidSignature rather than producing an unverifiable
// document.
func Sign(doc *Organization, rootSigner crypto.PrivateKey) error {
	if doc == nil {
		return ErrNilDocument
	}
	if doc.RootPublicKey == nil {
		return ErrMissingRootKey
	}
	rootAlg, err := signature.AlgorithmForPublicKey(doc.RootPublicKey)
	if err != nil {
		return fmt.Errorf("identity sign: %w", err)
	}
	if doc.RootAlgorithm != 0 && doc.RootAlgorithm != rootAlg {
		return fmt.Errorf("identity sign: %w: document declares %q, root key is %q",
			ErrAlgorithmMismatch, doc.RootAlgorithm.JOSE(), rootAlg.JOSE())
	}
	signerAlg, err := signature.AlgorithmForPrivateKey(rootSigner)
	if err != nil {
		return fmt.Errorf("identity sign: %w", err)
	}
	if signerAlg != rootAlg {
		return fmt.Errorf("identity sign: %w: signer is %q, root key is %q",
			ErrAlgorithmMismatch, signerAlg.JOSE(), rootAlg.JOSE())
	}
	doc.RootAlgorithm = rootAlg
	h, err := CanonicalHash(doc)
	if err != nil {
		return fmt.Errorf("identity sign: %w", err)
	}
	sig, err := signature.Sign(signerAlg, rootSigner, h[:])
	if err != nil {
		return fmt.Errorf("identity sign: %w", err)
	}
	ok, err := signature.Verify(rootAlg, doc.RootPublicKey, sig, h[:])
	if err != nil {
		return fmt.Errorf("identity sign: %w", err)
	}
	if !ok {
		return fmt.Errorf("identity sign: %w: signer does not control the root key", ErrInvalidSignature)
	}
	doc.Signature = sig
	return nil
}

// Verify checks doc's root signature against doc.RootPublicKey and,
// when a Rotation is present, checks that the rotation was
// authorized by the prior root and carries a positive sequence
// number. It is a pure function: no I/O, no lookups, no state.
//
// The check order is: structural requirements (non-nil document,
// root key, signature), algorithm/key consistency, the document
// signature over the canonical hash, then the rotation record —
// sequence, agreement between the rotation's new root and the
// document's root (compared in constant time on their canonical JWK
// encodings), and PreviousRootSignature over the canonical rotation
// record verified against the prior root carried in the record.
func Verify(doc *Organization) error {
	if doc == nil {
		return ErrNilDocument
	}
	if doc.RootPublicKey == nil {
		return ErrMissingRootKey
	}
	if len(doc.Signature) == 0 {
		return ErrMissingSignature
	}
	rootAlg, err := signature.AlgorithmForPublicKey(doc.RootPublicKey)
	if err != nil {
		return fmt.Errorf("identity verify: %w", err)
	}
	if doc.RootAlgorithm != rootAlg {
		return fmt.Errorf("identity verify: %w: document declares %q, root key is %q",
			ErrAlgorithmMismatch, doc.RootAlgorithm.JOSE(), rootAlg.JOSE())
	}
	if doc.Rotation != nil {
		if err := checkRotationStructure(doc.Rotation); err != nil {
			return err
		}
	}
	h, err := CanonicalHash(doc)
	if err != nil {
		return fmt.Errorf("identity verify: %w", err)
	}
	ok, err := signature.Verify(doc.RootAlgorithm, doc.RootPublicKey, doc.Signature, h[:])
	if err != nil {
		return fmt.Errorf("identity verify: %w", err)
	}
	if !ok {
		return ErrInvalidSignature
	}
	if doc.Rotation != nil {
		if err := verifyRotation(doc, rootAlg); err != nil {
			return err
		}
	}
	return nil
}

// checkRotationStructure validates the rotation record's required
// fields before any cryptographic work: a positive sequence, both
// keys present, and a prior-root signature to verify. A rotation
// missing any of these can never be valid.
func checkRotationStructure(r *Rotation) error {
	if r.Sequence == 0 {
		return fmt.Errorf("identity verify: %w: sequence is 0", ErrRotationSequence)
	}
	if r.NewRootPublicKey == nil {
		return fmt.Errorf("identity verify: %w: new root", ErrMissingRootKey)
	}
	if r.PreviousRootPublicKey == nil {
		return fmt.Errorf("identity verify: %w: prior root", ErrMissingRootKey)
	}
	if len(r.PreviousRootSignature) == 0 {
		return fmt.Errorf("identity verify: %w: missing prior root signature", ErrRotationUnauthorized)
	}
	return nil
}

// ApplyRotation produces a new Organization document whose root key
// is rot.NewRootPublicKey, authorized by the document's current
// root. The rotation record's PreviousRootPublicKey is filled from
// the document's current root and PreviousRootSignature is the old
// root's signature over the canonical rotation record — the
// authorization proof.
//
// oldRootSigner is a trust private key (crypto.PrivateKey) that must
// control doc.RootPublicKey. ApplyRotation proves this by verifying
// the rotation signature it just produced against the bound root —
// a signer that does not control the current root fails with
// ErrRotationUnauthorized. The package takes no custody of the key.
//
// rot.Sequence must exceed the sequence of the rotation already on
// the document (zero if none): the first rotation is sequence 1 or
// greater. A non-monotonic sequence fails with ErrRotationSequence.
//
// The returned document is unsigned: only the new root can bind
// itself to the rotated state, and this function holds no new-root
// key material. Complete the rotation by calling Sign on the
// returned document with the new root key.
func ApplyRotation(doc *Organization, rot Rotation, oldRootSigner crypto.PrivateKey) (*Organization, error) {
	if doc == nil {
		return nil, ErrNilDocument
	}
	if doc.RootPublicKey == nil {
		return nil, ErrMissingRootKey
	}
	prevAlg, err := signature.AlgorithmForPublicKey(doc.RootPublicKey)
	if err != nil {
		return nil, fmt.Errorf("identity rotate: %w", err)
	}
	if doc.RootAlgorithm != 0 && doc.RootAlgorithm != prevAlg {
		return nil, fmt.Errorf("identity rotate: %w: document declares %q, root key is %q",
			ErrAlgorithmMismatch, doc.RootAlgorithm.JOSE(), prevAlg.JOSE())
	}
	var priorSeq uint64
	if doc.Rotation != nil {
		priorSeq = doc.Rotation.Sequence
	}
	if rot.Sequence <= priorSeq {
		return nil, fmt.Errorf("identity rotate: %w: sequence %d must exceed %d",
			ErrRotationSequence, rot.Sequence, priorSeq)
	}
	if rot.NewRootPublicKey == nil {
		return nil, fmt.Errorf("identity rotate: %w: new root", ErrMissingRootKey)
	}
	newAlg, err := signature.AlgorithmForPublicKey(rot.NewRootPublicKey)
	if err != nil {
		return nil, fmt.Errorf("identity rotate: %w", err)
	}
	if rot.NewRootAlgorithm != 0 && rot.NewRootAlgorithm != newAlg {
		return nil, fmt.Errorf("identity rotate: %w: rotation declares %q, new root key is %q",
			ErrAlgorithmMismatch, rot.NewRootAlgorithm.JOSE(), newAlg.JOSE())
	}

	// Build the authoritative rotation record: the prior root is the
	// document's current root — never caller-supplied data.
	rot.NewRootAlgorithm = newAlg
	rot.PreviousRootPublicKey = doc.RootPublicKey
	rot.PreviousRootAlgorithm = prevAlg
	rot.PreviousRootSignature = nil
	rh, err := rotationHash(&rot)
	if err != nil {
		return nil, fmt.Errorf("identity rotate: %w", err)
	}
	prevSig, err := signature.Sign(prevAlg, oldRootSigner, rh[:])
	if err != nil {
		return nil, fmt.Errorf("identity rotate: %w", err)
	}
	ok, err := signature.Verify(prevAlg, doc.RootPublicKey, prevSig, rh[:])
	if err != nil {
		return nil, fmt.Errorf("identity rotate: %w", err)
	}
	if !ok {
		return nil, fmt.Errorf("identity rotate: %w: signer does not control the current root", ErrRotationUnauthorized)
	}
	rot.PreviousRootSignature = prevSig

	return &Organization{
		ID:            doc.ID,
		RootPublicKey: rot.NewRootPublicKey,
		RootAlgorithm: newAlg,
		Rotation:      &rot,
	}, nil
}

// verifyRotation checks the rotation record of an already
// signature-verified document: the rotation's new root is the
// document's current root (compared in constant time on canonical
// JWK encodings), and the prior root's signature over the canonical
// rotation record verifies. Structural requirements were already
// checked by checkRotationStructure.
func verifyRotation(doc *Organization, rootAlg signature.Algorithm) error {
	r := doc.Rotation
	newAlg, err := signature.AlgorithmForPublicKey(r.NewRootPublicKey)
	if err != nil {
		return fmt.Errorf("identity verify: %w", err)
	}
	if r.NewRootAlgorithm != newAlg {
		return fmt.Errorf("identity verify: %w: rotation declares %q, new root key is %q",
			ErrAlgorithmMismatch, r.NewRootAlgorithm.JOSE(), newAlg.JOSE())
	}
	if newAlg != rootAlg || !publicKeyEqual(r.NewRootPublicKey, doc.RootPublicKey) {
		return fmt.Errorf("identity verify: %w: rotation new root differs from document root", ErrRotationInconsistent)
	}
	prevAlg, err := signature.AlgorithmForPublicKey(r.PreviousRootPublicKey)
	if err != nil {
		return fmt.Errorf("identity verify: %w", err)
	}
	if r.PreviousRootAlgorithm != prevAlg {
		return fmt.Errorf("identity verify: %w: rotation declares %q, prior root key is %q",
			ErrAlgorithmMismatch, r.PreviousRootAlgorithm.JOSE(), prevAlg.JOSE())
	}
	rh, err := rotationHash(r)
	if err != nil {
		return fmt.Errorf("identity verify: %w", err)
	}
	ok, err := signature.Verify(prevAlg, r.PreviousRootPublicKey, r.PreviousRootSignature, rh[:])
	if err != nil {
		return fmt.Errorf("identity verify: %w", err)
	}
	if !ok {
		return ErrRotationUnauthorized
	}
	return nil
}

// docWire projects an Organization to its canonical wire form.
func docWire(doc *Organization) (*organizationWire, error) {
	rootJWK, err := jwkutil.Marshal(doc.RootPublicKey)
	if err != nil {
		return nil, fmt.Errorf("identity: marshal root key: %w", err)
	}
	w := &organizationWire{
		ID:            doc.ID,
		RootPublicKey: rootJWK,
		RootAlgorithm: doc.RootAlgorithm.JOSE(),
	}
	if doc.Rotation != nil {
		rw, err := rotationWireOf(doc.Rotation)
		if err != nil {
			return nil, err
		}
		w.Rotation = rw
	}
	return w, nil
}

// rotationWireOf projects a Rotation to its canonical wire form.
func rotationWireOf(r *Rotation) (*rotationWire, error) {
	newJWK, err := jwkutil.Marshal(r.NewRootPublicKey)
	if err != nil {
		return nil, fmt.Errorf("identity: marshal new root key: %w", err)
	}
	prevJWK, err := jwkutil.Marshal(r.PreviousRootPublicKey)
	if err != nil {
		return nil, fmt.Errorf("identity: marshal prior root key: %w", err)
	}
	return &rotationWire{
		Sequence:              r.Sequence,
		NewRootPublicKey:      newJWK,
		NewRootAlgorithm:      r.NewRootAlgorithm.JOSE(),
		PreviousRootPublicKey: prevJWK,
		PreviousRootAlgorithm: r.PreviousRootAlgorithm.JOSE(),
		PreviousRootSignature: r.PreviousRootSignature,
	}, nil
}

// rotationHash returns the canonical hash of the unsigned rotation
// record — the payload the prior root signs in
// Rotation.PreviousRootSignature.
func rotationHash(r *Rotation) ([32]byte, error) {
	unsigned := *r
	unsigned.PreviousRootSignature = nil
	w, err := rotationWireOf(&unsigned)
	if err != nil {
		return [32]byte{}, err
	}
	return canonical.CanonicalHash(w)
}

// publicKeyEqual reports whether two trust public keys are the same
// key by comparing their canonical [RFC 7517] JWK encodings in
// constant time.
func publicKeyEqual(a, b crypto.PublicKey) bool {
	aj, err := jwkutil.Marshal(a)
	if err != nil {
		return false
	}
	bj, err := jwkutil.Marshal(b)
	if err != nil {
		return false
	}
	ab, err := canonical.Marshal(aj, canonical.EncodingJSON)
	if err != nil {
		return false
	}
	bb, err := canonical.Marshal(bj, canonical.EncodingJSON)
	if err != nil {
		return false
	}
	return subtle.ConstantTimeCompare(ab, bb) == 1
}
