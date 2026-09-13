// Package jwkutil provides [RFC 7517] JSON Web Key marshal and unmarshal
// for the trust concrete key types. The public API is map[string]any-based:
// [Marshal] and [MarshalPrivate] serialize trust keys to JWK maps;
// [Unmarshal] and [UnmarshalPrivate] parse JWK maps into trust keys.
//
// # Adapter strategy
//
// OKP (Ed25519/X25519), EC (P-256/P-384), and RSA marshal/unmarshal delegate
// to [github.com/lestrrat-go/jwx/v3/jwk]. The adapter converts between
// trust concrete key types and the stdlib raw key types that jwx consumes,
// then delegates serialization/deserialization to jwx. No jwx types leak
// through the public API — the adapter is the only file that imports jwx.
//
// # secp256k1 gap (PARTIAL-REPLACE)
//
// secp256k1 is NOT delegated to jwx. jwx registers secp256k1 only when
// compiled with the jwx_es256k build tag
// (//go:build jwx_es256k). Without the tag — the default build —
// jwk.ParseKey and jwk.Import reject crv "secp256k1" with "invalid
// elliptic curve". Relying on a build tag is fragile: CI, IDE, and
// go test must all pass -tags jwx_es256k, and forgetting it silently
// breaks secp256k1 JWK parsing. The existing hand-rolled secp256k1
// marshal/unmarshal is correct, tested, and uses the same
// decred/dcrd library jwx would use behind the tag. Keeping it
// avoids build-tag fragility and is a small amount of code.
//
// The adapter dispatches on kty/crv: standard curves (OKP, EC P-256,
// P-384, RSA) go to jwx; secp256k1 goes to the hand-rolled path.
//
// [RFC 7517]: https://www.rfc-editor.org/rfc/rfc7517
package jwkutil

import (
	"bytes"
	"crypto"
	"crypto/ecdh"
	stdecdsa "crypto/ecdsa"
	stded25519 "crypto/ed25519"
	"crypto/elliptic"
	stdrsa "crypto/rsa"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"

	"github.com/bperin/trust/crypto/ecdsa"
	"github.com/bperin/trust/crypto/ed25519"
	"github.com/bperin/trust/crypto/rsa"
	"github.com/bperin/trust/crypto/secp256k1"
	"github.com/bperin/trust/crypto/x25519"
	"github.com/bperin/trust/signature"
	dcrdsecp "github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/lestrrat-go/jwx/v3/jwk"
)

// Sentinel errors returned by marshal and unmarshal. Check with errors.Is.
var (
	// ErrAlgNone is returned when a JWK carries "alg":"none", which is
	// always rejected per the project security rules.
	ErrAlgNone = errors.New("jwkutil: alg \"none\" is not allowed")
	// ErrAlgMismatch is returned when the "alg" member does not match
	// the key type derived from "kty" and "crv".
	ErrAlgMismatch = errors.New("jwkutil: alg does not match key type")
	// ErrAlgRequired is returned when "alg" is required to construct the
	// key (e.g. RSA, where it selects PSS vs PKCS1v1.5) but is absent.
	ErrAlgRequired = errors.New("jwkutil: alg required for this key type")
	// ErrDuplicateMember is returned when a JWK object contains the same
	// member name more than once.
	ErrDuplicateMember = errors.New("jwkutil: duplicate member name")
	// ErrUnsupportedKty is returned when the "kty" value is not one of
	// OKP, EC, or RSA.
	ErrUnsupportedKty = errors.New("jwkutil: unsupported kty")
	// ErrUnsupportedCrv is returned when the "crv" value is not a
	// supported curve for the key type.
	ErrUnsupportedCrv = errors.New("jwkutil: unsupported crv")
	// ErrUnsupportedKeyType is returned when Marshal is given a key type
	// this package does not know how to serialize.
	ErrUnsupportedKeyType = errors.New("jwkutil: unsupported key type")
	// ErrMissingMember is returned when a required JWK member is absent.
	ErrMissingMember = errors.New("jwkutil: missing member")
	// ErrInvalidMember is returned when a JWK member is present but
	// malformed (wrong type, bad base64url, wrong length, off-curve
	// point, or a private "d" in a public JWK).
	ErrInvalidMember = errors.New("jwkutil: invalid member")
	// ErrKeyInconsistent is returned when the public material in a
	// private JWK does not match the private key (e.g. the "x" derived
	// from "d" differs from the supplied "x").
	ErrKeyInconsistent = errors.New("jwkutil: private key inconsistent with public material")
)

// JWKS is a [RFC 7517] §5 JSON Web Key Set. Keys is the list of JWK
// objects in the "keys" array.
type JWKS struct {
	// Keys holds the JWK objects in the set.
	Keys []map[string]any `json:"keys"`
}

// Marshal serializes a trust public key to a [RFC 7517] JWK object
// represented as a map. The "alg" member is set from the key type and
// (for RSA) the bound hash. The returned map does not include a
// private "d" member. Use [MarshalPrivate] for private keys.
//
// OKP (Ed25519/X25519), EC (P-256/P-384), and RSA are serialized by
// delegating to jwx/v3/jwk. secp256k1 is serialized by the hand-rolled
// path (see the package-level secp256k1 gap documentation).
//
// The argument is a trust concrete key type
// (*ed25519.PublicKey, *secp256k1.PublicKey, *ecdsa.PublicKey,
// *rsa.PSSPublicKey, *rsa.PKCS1PublicKey, *x25519.PublicKey).
func Marshal(k crypto.PublicKey) (map[string]any, error) {
	switch kk := k.(type) {
	case *ed25519.PublicKey:
		b := kk.Bytes()
		raw := stded25519.PublicKey(append([]byte(nil), b[:]...))
		return marshalViaJWX(raw, "EdDSA")
	case *x25519.PublicKey:
		b := kk.Bytes()
		raw, err := ecdh.X25519().NewPublicKey(append([]byte(nil), b[:]...))
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrInvalidMember, err)
		}
		return marshalViaJWX(raw, "")
	case *secp256k1.PublicKey:
		return marshalSecp256k1Public(kk)
	case *ecdsa.PublicKey:
		raw := &stdecdsa.PublicKey{
			Curve: kk.Curve(),
			X:     kk.X(),
			Y:     kk.Y(),
		}
		alg, err := signature.AlgorithmForPublicKey(kk)
		if err != nil {
			return nil, err
		}
		return marshalViaJWX(raw, alg.JOSE())
	case *rsa.PSSPublicKey:
		raw := &stdrsa.PublicKey{N: kk.N(), E: kk.E()}
		alg, err := signature.AlgorithmForPublicKey(kk)
		if err != nil {
			return nil, err
		}
		return marshalViaJWX(raw, alg.JOSE())
	case *rsa.PKCS1PublicKey:
		raw := &stdrsa.PublicKey{N: kk.N(), E: kk.E()}
		alg, err := signature.AlgorithmForPublicKey(kk)
		if err != nil {
			return nil, err
		}
		return marshalViaJWX(raw, alg.JOSE())
	default:
		return nil, fmt.Errorf("%w: %T", ErrUnsupportedKeyType, k)
	}
}

// MarshalPrivate serializes a trust private key to a [RFC 7517] JWK
// object including the private "d" member. The public members ("x",
// "y", "n", "e") are derived from the key's Public() so the JWK is
// self-consistent. The returned map contains secret material — the
// caller must handle it securely and must never log it.
//
// OKP (Ed25519/X25519), EC (P-256/P-384), and RSA are serialized by
// delegating to jwx/v3/jwk. secp256k1 is serialized by the hand-rolled
// path (see the package-level secp256k1 gap documentation).
//
// The argument is a trust concrete private key type
// (*ed25519.PrivateKey, *secp256k1.PrivateKey, *ecdsa.PrivateKey,
// *rsa.PSSPrivateKey, *rsa.PKCS1PrivateKey, *x25519.PrivateKey).
func MarshalPrivate(k crypto.PrivateKey) (map[string]any, error) {
	switch kk := k.(type) {
	case *ed25519.PrivateKey:
		raw := stded25519.NewKeyFromSeed(kk.Seed())
		return marshalViaJWX(raw, "EdDSA")
	case *x25519.PrivateKey:
		b := kk.Bytes()
		raw, err := ecdh.X25519().NewPrivateKey(append([]byte(nil), b[:]...))
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrInvalidMember, err)
		}
		return marshalViaJWX(raw, "")
	case *secp256k1.PrivateKey:
		return marshalSecp256k1Private(kk)
	case *ecdsa.PrivateKey:
		pub := kk.Public()
		raw := &stdecdsa.PrivateKey{
			PublicKey: stdecdsa.PublicKey{
				Curve: pub.Curve(),
				X:     pub.X(),
				Y:     pub.Y(),
			},
			D: kk.D(),
		}
		alg, err := signature.AlgorithmForPublicKey(kk.Public())
		if err != nil {
			return nil, err
		}
		return marshalViaJWX(raw, alg.JOSE())
	case *rsa.PSSPrivateKey:
		pub := kk.Public()
		raw := &stdrsa.PrivateKey{
			PublicKey: stdrsa.PublicKey{N: pub.N(), E: pub.E()},
			D:         kk.D(),
		}
		alg, err := signature.AlgorithmForPublicKey(kk.Public())
		if err != nil {
			return nil, err
		}
		return marshalViaJWX(raw, alg.JOSE())
	case *rsa.PKCS1PrivateKey:
		pub := kk.Public()
		raw := &stdrsa.PrivateKey{
			PublicKey: stdrsa.PublicKey{N: pub.N(), E: pub.E()},
			D:         kk.D(),
		}
		alg, err := signature.AlgorithmForPublicKey(kk.Public())
		if err != nil {
			return nil, err
		}
		return marshalViaJWX(raw, alg.JOSE())
	default:
		return nil, fmt.Errorf("%w: %T", ErrUnsupportedKeyType, k)
	}
}

// Unmarshal parses a [RFC 7517] JWK object (as a map) into a trust
// public key. The key type is determined solely from "kty" and "crv";
// the "alg" member, if present, is validated against a per-key-type
// whitelist and "alg":"none" is rejected. A private "d" member in a
// public JWK is rejected. The returned value is a trust concrete key
// type (e.g. *ed25519.PublicKey); type-assert to access it.
//
// OKP (Ed25519/X25519), EC (P-256/P-384), and RSA are parsed by
// delegating to jwx/v3/jwk. secp256k1 is parsed by the hand-rolled
// path (see the package-level secp256k1 gap documentation).
func Unmarshal(m map[string]any) (crypto.PublicKey, error) {
	if m == nil {
		return nil, fmt.Errorf("%w: nil JWK", ErrInvalidMember)
	}
	kty, err := reqString(m, "kty")
	if err != nil {
		return nil, err
	}
	// A public JWK must not carry a private "d".
	if _, hasD := m["d"]; hasD {
		return nil, fmt.Errorf("%w: \"d\" present in public JWK", ErrInvalidMember)
	}
	alg := optString(m, "alg")
	if alg == "none" {
		return nil, ErrAlgNone
	}
	switch kty {
	case "OKP":
		return unmarshalOKPPublic(m, alg)
	case "EC":
		crv := optString(m, "crv")
		if crv == "secp256k1" {
			return unmarshalSecp256k1Public(m, alg)
		}
		return unmarshalECPublic(m, alg)
	case "RSA":
		return unmarshalRSAPublic(m, alg)
	default:
		return nil, fmt.Errorf("%w: %q", ErrUnsupportedKty, kty)
	}
}

// UnmarshalPrivate parses a [RFC 7517] JWK object (as a map) into a
// trust private key. The "d" member is required. The public members
// are validated for consistency with the private material where a
// cheap check exists (Ed25519, X25519, secp256k1, EC P-256/P-384).
// "alg":"none" is rejected and "alg" is validated against the key
// type. The returned value is a trust concrete private key type.
//
// OKP (Ed25519/X25519), EC (P-256/P-384), and RSA are parsed by
// delegating to jwx/v3/jwk. secp256k1 is parsed by the hand-rolled
// path (see the package-level secp256k1 gap documentation).
func UnmarshalPrivate(m map[string]any) (crypto.PrivateKey, error) {
	if m == nil {
		return nil, fmt.Errorf("%w: nil JWK", ErrInvalidMember)
	}
	kty, err := reqString(m, "kty")
	if err != nil {
		return nil, err
	}
	alg := optString(m, "alg")
	if alg == "none" {
		return nil, ErrAlgNone
	}
	dStr, err := reqString(m, "d")
	if err != nil {
		return nil, err
	}
	switch kty {
	case "OKP":
		return unmarshalOKPPrivate(m, alg, dStr)
	case "EC":
		crv := optString(m, "crv")
		if crv == "secp256k1" {
			return unmarshalSecp256k1Private(m, alg, dStr)
		}
		return unmarshalECPrivate(m, alg, dStr)
	case "RSA":
		return unmarshalRSAPrivate(m, alg, dStr)
	default:
		return nil, fmt.Errorf("%w: %q", ErrUnsupportedKty, kty)
	}
}

// PublicFromJWK parses a JSON-encoded [RFC 7517] JWK object into a
// trust public key. It rejects duplicate member names before parsing.
func PublicFromJWK(data []byte) (crypto.PublicKey, error) {
	if err := checkDuplicateMembers(data); err != nil {
		return nil, err
	}
	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidMember, err)
	}
	return Unmarshal(m)
}

// PrivateFromJWK parses a JSON-encoded [RFC 7517] JWK object into a
// trust private key. It rejects duplicate member names before parsing.
func PrivateFromJWK(data []byte) (crypto.PrivateKey, error) {
	if err := checkDuplicateMembers(data); err != nil {
		return nil, err
	}
	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidMember, err)
	}
	return UnmarshalPrivate(m)
}

// ToJWK serializes a trust public key to canonical JSON bytes per
// [RFC 7517]. It is a convenience wrapper around [Marshal].
func ToJWK(k crypto.PublicKey) ([]byte, error) {
	m, err := Marshal(k)
	if err != nil {
		return nil, err
	}
	return json.Marshal(m)
}

// ToJWKS serializes a slice of trust public keys to a [RFC 7517] §5
// JWK Set (a JSON object with a "keys" array).
func ToJWKS(keys []crypto.PublicKey) ([]byte, error) {
	set := JWKS{Keys: make([]map[string]any, 0, len(keys))}
	for _, k := range keys {
		m, err := Marshal(k)
		if err != nil {
			return nil, err
		}
		set.Keys = append(set.Keys, m)
	}
	return json.Marshal(set)
}

// --- jwx adapter ---

// marshalViaJWX converts a raw stdlib key to a JWK map by delegating
// serialization to jwx/v3/jwk. The alg parameter is set as the "alg"
// member if non-empty (empty means omit "alg", used for X25519 which
// has no signing algorithm). No jwx types leak — the result is a
// plain map[string]any.
func marshalViaJWX(rawKey any, alg string) (map[string]any, error) {
	key, err := jwk.Import(rawKey)
	if err != nil {
		return nil, fmt.Errorf("%w: jwk.Import: %v", ErrInvalidMember, err)
	}
	if alg != "" {
		if err := key.Set("alg", alg); err != nil {
			return nil, fmt.Errorf("%w: set alg: %v", ErrInvalidMember, err)
		}
	}
	data, err := json.Marshal(key)
	if err != nil {
		return nil, fmt.Errorf("%w: MarshalJSON: %v", ErrInvalidMember, err)
	}
	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidMember, err)
	}
	return m, nil
}

// parseViaJWX converts a JWK map to a jwk.Key by delegating parsing to
// jwx/v3/jwk. The map is re-serialized to JSON and fed to jwk.ParseKey.
// The caller is responsible for exporting the raw key and converting
// to a trust concrete type.
func parseViaJWX(m map[string]any) (jwk.Key, error) {
	data, err := json.Marshal(m)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidMember, err)
	}
	key, err := jwk.ParseKey(data)
	if err != nil {
		return nil, fmt.Errorf("%w: jwk.ParseKey: %v", ErrInvalidMember, err)
	}
	return key, nil
}

// exportRawKey exports the raw stdlib key from a jwk.Key. The
// destination is a pointer to an empty interface so jwx dynamically
// creates the correct concrete type.
func exportRawKey(key jwk.Key) (any, error) {
	var raw any
	if err := jwk.Export(key, &raw); err != nil {
		return nil, fmt.Errorf("%w: jwk.Export: %v", ErrInvalidMember, err)
	}
	return raw, nil
}

// --- OKP (Ed25519, X25519) ---

func unmarshalOKPPublic(m map[string]any, alg string) (crypto.PublicKey, error) {
	crv, err := reqString(m, "crv")
	if err != nil {
		return nil, err
	}
	if _, err := reqString(m, "x"); err != nil {
		return nil, err
	}
	switch crv {
	case "Ed25519":
		if alg != "" && alg != "EdDSA" {
			return nil, fmt.Errorf("%w: got %q, want EdDSA", ErrAlgMismatch, alg)
		}
	case "X25519":
		if alg != "" && !strings.HasPrefix(alg, "ECDH-ES") {
			return nil, fmt.Errorf("%w: got %q, want ECDH-ES* for X25519", ErrAlgMismatch, alg)
		}
	default:
		return nil, fmt.Errorf("%w: %q", ErrUnsupportedCrv, crv)
	}
	key, err := parseViaJWX(m)
	if err != nil {
		return nil, err
	}
	raw, err := exportRawKey(key)
	if err != nil {
		return nil, err
	}
	switch r := raw.(type) {
	case stded25519.PublicKey:
		return ed25519.NewPublicKey(r)
	case *ecdh.PublicKey:
		return x25519.NewPublicKey(r.Bytes())
	default:
		return nil, fmt.Errorf("%w: unexpected OKP public key type %T", ErrInvalidMember, raw)
	}
}

func unmarshalOKPPrivate(m map[string]any, alg, dStr string) (crypto.PrivateKey, error) {
	crv, err := reqString(m, "crv")
	if err != nil {
		return nil, err
	}
	xStr, err := reqString(m, "x")
	if err != nil {
		return nil, err
	}
	switch crv {
	case "Ed25519":
		if alg != "" && alg != "EdDSA" {
			return nil, fmt.Errorf("%w: got %q, want EdDSA", ErrAlgMismatch, alg)
		}
		// Consistency check before jwx: derive the public key from
		// the seed (d) and verify it matches the supplied "x" in
		// constant time. jwx also checks this during Export, but we
		// check first to produce ErrKeyInconsistent.
		seed, err := decodeBytes(dStr, stded25519.SeedSize)
		if err != nil {
			return nil, err
		}
		x, err := decodeBytes(xStr, stded25519.PublicKeySize)
		if err != nil {
			return nil, err
		}
		full := stded25519.NewKeyFromSeed(seed)
		px := full.Public().(stded25519.PublicKey)
		if subtle.ConstantTimeCompare(px, x) != 1 {
			return nil, ErrKeyInconsistent
		}
		key, err := parseViaJWX(m)
		if err != nil {
			return nil, err
		}
		raw, err := exportRawKey(key)
		if err != nil {
			return nil, err
		}
		rp, ok := raw.(stded25519.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("%w: unexpected OKP private key type %T", ErrInvalidMember, raw)
		}
		return ed25519.NewPrivateKey(rp)
	case "X25519":
		if alg != "" && !strings.HasPrefix(alg, "ECDH-ES") {
			return nil, fmt.Errorf("%w: got %q, want ECDH-ES* for X25519", ErrAlgMismatch, alg)
		}
		// Consistency check before jwx: derive the public key from
		// the private scalar (d) and verify it matches the supplied
		// "x" in constant time.
		d, err := decodeBytes(dStr, 32)
		if err != nil {
			return nil, err
		}
		x, err := decodeBytes(xStr, 32)
		if err != nil {
			return nil, err
		}
		xpriv, err := x25519.NewPrivateKey(d)
		if err != nil {
			return nil, err
		}
		px := xpriv.Public().Bytes()
		if subtle.ConstantTimeCompare(px[:], x) != 1 {
			return nil, ErrKeyInconsistent
		}
		key, err := parseViaJWX(m)
		if err != nil {
			return nil, err
		}
		raw, err := exportRawKey(key)
		if err != nil {
			return nil, err
		}
		rp, ok := raw.(*ecdh.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("%w: unexpected OKP private key type %T", ErrInvalidMember, raw)
		}
		return x25519.NewPrivateKey(rp.Bytes())
	default:
		return nil, fmt.Errorf("%w: %q", ErrUnsupportedCrv, crv)
	}
}

// --- EC (P-256, P-384) via jwx; secp256k1 hand-rolled ---

// ecCurveParams maps a stdlib elliptic.Curve to its JWK crv name, the
// expected "alg", and the field size in bytes (for fixed-length
// coordinate encoding). Used by the secp256k1 hand-rolled path.
func ecCurveParams(curve elliptic.Curve) (crv, alg string, size int, ok bool) {
	switch curve {
	case elliptic.P256():
		return "P-256", "ES256", 32, true
	case elliptic.P384():
		return "P-384", "ES384", 48, true
	default:
		return "", "", 0, false
	}
}

func unmarshalECPublic(m map[string]any, alg string) (crypto.PublicKey, error) {
	crv, err := reqString(m, "crv")
	if err != nil {
		return nil, err
	}
	if _, err := reqString(m, "x"); err != nil {
		return nil, err
	}
	if _, err := reqString(m, "y"); err != nil {
		return nil, err
	}
	switch crv {
	case "P-256":
		if alg != "" && alg != "ES256" {
			return nil, fmt.Errorf("%w: got %q, want ES256", ErrAlgMismatch, alg)
		}
	case "P-384":
		if alg != "" && alg != "ES384" {
			return nil, fmt.Errorf("%w: got %q, want ES384", ErrAlgMismatch, alg)
		}
	default:
		return nil, fmt.Errorf("%w: %q", ErrUnsupportedCrv, crv)
	}
	key, err := parseViaJWX(m)
	if err != nil {
		return nil, err
	}
	raw, err := exportRawKey(key)
	if err != nil {
		return nil, err
	}
	stdpub, ok := raw.(*stdecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("%w: unexpected EC public key type %T", ErrInvalidMember, raw)
	}
	switch crv {
	case "P-256":
		return ecdsa.NewPublicKey(stdpub, crypto.SHA256)
	case "P-384":
		return ecdsa.NewPublicKey(stdpub, crypto.SHA384)
	default:
		return nil, fmt.Errorf("%w: %q", ErrUnsupportedCrv, crv)
	}
}

func unmarshalECPrivate(m map[string]any, alg, dStr string) (crypto.PrivateKey, error) {
	crv, err := reqString(m, "crv")
	if err != nil {
		return nil, err
	}
	if _, err := reqString(m, "x"); err != nil {
		return nil, err
	}
	if _, err := reqString(m, "y"); err != nil {
		return nil, err
	}
	switch crv {
	case "P-256":
		if alg != "" && alg != "ES256" {
			return nil, fmt.Errorf("%w: got %q, want ES256", ErrAlgMismatch, alg)
		}
	case "P-384":
		if alg != "" && alg != "ES384" {
			return nil, fmt.Errorf("%w: got %q, want ES384", ErrAlgMismatch, alg)
		}
	default:
		return nil, fmt.Errorf("%w: %q", ErrUnsupportedCrv, crv)
	}
	key, err := parseViaJWX(m)
	if err != nil {
		return nil, err
	}
	raw, err := exportRawKey(key)
	if err != nil {
		return nil, err
	}
	stdpriv, ok := raw.(*stdecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("%w: unexpected EC private key type %T", ErrInvalidMember, raw)
	}
	// Verify the private scalar maps to the supplied public point.
	// jwx validates the point is on the curve, but we re-check the
	// scalar-to-point consistency to produce ErrKeyInconsistent.
	switch crv {
	case "P-256":
		if err := validateECScalar(elliptic.P256(), stdpriv.D, stdpriv.X, stdpriv.Y, 32); err != nil {
			return nil, err
		}
		return ecdsa.NewPrivateKey(stdpriv, crypto.SHA256)
	case "P-384":
		if err := validateECScalar(elliptic.P384(), stdpriv.D, stdpriv.X, stdpriv.Y, 48); err != nil {
			return nil, err
		}
		return ecdsa.NewPrivateKey(stdpriv, crypto.SHA384)
	default:
		return nil, fmt.Errorf("%w: %q", ErrUnsupportedCrv, crv)
	}
}

// --- secp256k1 (hand-rolled, PARTIAL-REPLACE) ---

func marshalSecp256k1Public(k *secp256k1.PublicKey) (map[string]any, error) {
	compressed := k.Bytes()
	parsed, err := dcrdsecp.ParsePubKey(compressed)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to decompress secp256k1 public key: %v", ErrInvalidMember, err)
	}
	uncompressed := parsed.SerializeUncompressed()
	if len(uncompressed) != 65 || uncompressed[0] != 0x04 {
		return nil, fmt.Errorf("%w: malformed uncompressed secp256k1 point", ErrInvalidMember)
	}
	x := new(big.Int).SetBytes(uncompressed[1:33])
	y := new(big.Int).SetBytes(uncompressed[33:65])
	alg, err := signature.AlgorithmForPublicKey(k)
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"kty": "EC",
		"crv": "secp256k1",
		"alg": alg.JOSE(),
		"x":   encodeFixedInt(x, 32),
		"y":   encodeFixedInt(y, 32),
	}, nil
}

func marshalSecp256k1Private(k *secp256k1.PrivateKey) (map[string]any, error) {
	m, err := marshalSecp256k1Public(k.Public())
	if err != nil {
		return nil, err
	}
	m["d"] = encodeFixedInt(new(big.Int).SetBytes(k.Bytes()), 32)
	return m, nil
}

func unmarshalSecp256k1Public(m map[string]any, alg string) (crypto.PublicKey, error) {
	xStr, err := reqString(m, "x")
	if err != nil {
		return nil, err
	}
	yStr, err := reqString(m, "y")
	if err != nil {
		return nil, err
	}
	if alg != "" && alg != "ES256K" {
		return nil, fmt.Errorf("%w: got %q, want ES256K", ErrAlgMismatch, alg)
	}
	x, err := decodeInt(xStr)
	if err != nil {
		return nil, err
	}
	y, err := decodeInt(yStr)
	if err != nil {
		return nil, err
	}
	compressed := elliptic.MarshalCompressed(dcrdsecp.S256(), x, y)
	return secp256k1.NewPublicKey(compressed)
}

func unmarshalSecp256k1Private(m map[string]any, alg, dStr string) (crypto.PrivateKey, error) {
	xStr, err := reqString(m, "x")
	if err != nil {
		return nil, err
	}
	yStr, err := reqString(m, "y")
	if err != nil {
		return nil, err
	}
	if alg != "" && alg != "ES256K" {
		return nil, fmt.Errorf("%w: got %q, want ES256K", ErrAlgMismatch, alg)
	}
	x, err := decodeInt(xStr)
	if err != nil {
		return nil, err
	}
	y, err := decodeInt(yStr)
	if err != nil {
		return nil, err
	}
	d, err := decodeInt(dStr)
	if err != nil {
		return nil, err
	}
	compressed := elliptic.MarshalCompressed(dcrdsecp.S256(), x, y)
	pub, err := secp256k1.NewPublicKey(compressed)
	if err != nil {
		return nil, err
	}
	dBytes := fixedBytes(d, 32)
	priv, err := secp256k1.NewPrivateKey(dBytes)
	if err != nil {
		return nil, err
	}
	// Verify the public key derived from "d" matches the supplied
	// (x, y) in constant time.
	if !priv.Public().Equal(pub) {
		return nil, ErrKeyInconsistent
	}
	return priv, nil
}

// validateECPoint rejects points that are not on the curve or are the
// point at infinity. Uses the stdlib on-curve check.
func validateECPoint(curve elliptic.Curve, x, y *big.Int) error {
	if x == nil || y == nil {
		return fmt.Errorf("%w: nil coordinate", ErrInvalidMember)
	}
	if x.Sign() < 0 || y.Sign() < 0 {
		return fmt.Errorf("%w: negative coordinate", ErrInvalidMember)
	}
	if x.Cmp(curve.Params().P) >= 0 || y.Cmp(curve.Params().P) >= 0 {
		return fmt.Errorf("%w: coordinate out of range", ErrInvalidMember)
	}
	if !curve.IsOnCurve(x, y) {
		return fmt.Errorf("%w: point not on curve", ErrInvalidMember)
	}
	return nil
}

// validateECScalar verifies that the private scalar d maps to the
// public point (x, y) via scalar base-point multiplication. This
// catches JWKs where "d" and the public material are inconsistent.
func validateECScalar(curve elliptic.Curve, d, x, y *big.Int, size int) error {
	if d.Sign() <= 0 {
		return fmt.Errorf("%w: non-positive private scalar", ErrInvalidMember)
	}
	if d.Cmp(curve.Params().N) >= 0 {
		return fmt.Errorf("%w: private scalar out of range", ErrInvalidMember)
	}
	dBytes := fixedBytes(d, size)
	dx, dy := curve.ScalarBaseMult(dBytes)
	if dx.Cmp(x) != 0 || dy.Cmp(y) != 0 {
		return ErrKeyInconsistent
	}
	return nil
}

// --- RSA ---

// rsaAlgParams parses an RSA "alg" into its scheme prefix ("PS" for
// PSS, "RS" for PKCS1v1.5) and bound hash.
func rsaAlgParams(alg string) (scheme string, hash crypto.Hash, ok bool) {
	switch alg {
	case "PS256":
		return "PS", crypto.SHA256, true
	case "PS384":
		return "PS", crypto.SHA384, true
	case "PS512":
		return "PS", crypto.SHA512, true
	case "RS256":
		return "RS", crypto.SHA256, true
	case "RS384":
		return "RS", crypto.SHA384, true
	case "RS512":
		return "RS", crypto.SHA512, true
	default:
		return "", 0, false
	}
}

func unmarshalRSAPublic(m map[string]any, alg string) (crypto.PublicKey, error) {
	if alg == "" {
		return nil, fmt.Errorf("%w: RSA requires alg to select PSS or PKCS1v1.5", ErrAlgRequired)
	}
	scheme, hash, ok := rsaAlgParams(alg)
	if !ok {
		return nil, fmt.Errorf("%w: %q is not a valid RSA alg", ErrAlgMismatch, alg)
	}
	if _, err := reqString(m, "n"); err != nil {
		return nil, err
	}
	if _, err := reqString(m, "e"); err != nil {
		return nil, err
	}
	key, err := parseViaJWX(m)
	if err != nil {
		return nil, err
	}
	raw, err := exportRawKey(key)
	if err != nil {
		return nil, err
	}
	stdpub, ok := raw.(*stdrsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("%w: unexpected RSA public key type %T", ErrInvalidMember, raw)
	}
	switch scheme {
	case "PS":
		return rsa.NewPSSPublicKey(stdpub, hash)
	case "RS":
		return rsa.NewPKCS1PublicKey(stdpub, hash)
	default:
		return nil, fmt.Errorf("%w: %q", ErrAlgMismatch, alg)
	}
}

func unmarshalRSAPrivate(m map[string]any, alg, dStr string) (crypto.PrivateKey, error) {
	if alg == "" {
		return nil, fmt.Errorf("%w: RSA requires alg to select PSS or PKCS1v1.5", ErrAlgRequired)
	}
	scheme, hash, ok := rsaAlgParams(alg)
	if !ok {
		return nil, fmt.Errorf("%w: %q is not a valid RSA alg", ErrAlgMismatch, alg)
	}
	if _, err := reqString(m, "n"); err != nil {
		return nil, err
	}
	if _, err := reqString(m, "e"); err != nil {
		return nil, err
	}
	d, err := decodeInt(dStr)
	if err != nil {
		return nil, err
	}
	// jwx's RSA private key export requires p and q, which our JWKs
	// do not include (we only serialize n, e, d). Parse the full JWK
	// with jwx, then export only the public key part and attach d
	// manually.
	key, err := parseViaJWX(m)
	if err != nil {
		return nil, err
	}
	pubKey, err := key.PublicKey()
	if err != nil {
		return nil, fmt.Errorf("%w: PublicKey: %v", ErrInvalidMember, err)
	}
	raw, err := exportRawKey(pubKey)
	if err != nil {
		return nil, err
	}
	stdpub, ok := raw.(*stdrsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("%w: unexpected RSA public key type %T", ErrInvalidMember, raw)
	}
	stdpriv := &stdrsa.PrivateKey{
		PublicKey: *stdpub,
		D:         d,
	}
	switch scheme {
	case "PS":
		return rsa.NewPSSPrivateKey(stdpriv, hash)
	case "RS":
		return rsa.NewPKCS1PrivateKey(stdpriv, hash)
	default:
		return nil, fmt.Errorf("%w: %q", ErrAlgMismatch, alg)
	}
}

// --- encoding helpers (used by secp256k1 hand-rolled path) ---

// encodeBytes base64url-encodes b without padding per [RFC 7515] §2.
func encodeBytes(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}

// decodeBytes base64url-decodes s without padding. If want > 0 the
// decoded length must equal want.
func decodeBytes(s string, want int) ([]byte, error) {
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("%w: bad base64url: %v", ErrInvalidMember, err)
	}
	if want > 0 && len(b) != want {
		return nil, fmt.Errorf("%w: got %d bytes, want %d", ErrInvalidMember, len(b), want)
	}
	return b, nil
}

// encodeInt base64url-encodes the big-endian unsigned bytes of i.
func encodeInt(i *big.Int) string {
	return base64.RawURLEncoding.EncodeToString(i.Bytes())
}

// encodeFixedInt base64url-encodes i left-padded to size bytes, so
// leading zeros are preserved (required for EC coordinates per
// [RFC 7518] §6.2.1 and secp256k1 per [RFC 8812] §3.1).
func encodeFixedInt(i *big.Int, size int) string {
	b := make([]byte, size)
	ib := i.Bytes()
	copy(b[size-len(ib):], ib)
	return base64.RawURLEncoding.EncodeToString(b)
}

// decodeInt base64url-decodes s into a big.Int.
func decodeInt(s string) (*big.Int, error) {
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("%w: bad base64url: %v", ErrInvalidMember, err)
	}
	return new(big.Int).SetBytes(b), nil
}

// fixedBytes returns the big-endian bytes of i left-padded to size.
func fixedBytes(i *big.Int, size int) []byte {
	b := make([]byte, size)
	ib := i.Bytes()
	copy(b[size-len(ib):], ib)
	return b
}

// reqString returns a required string member, erroring if absent or
// not a string.
func reqString(m map[string]any, key string) (string, error) {
	v, ok := m[key]
	if !ok {
		return "", fmt.Errorf("%w: %q", ErrMissingMember, key)
	}
	s, ok := v.(string)
	if !ok {
		return "", fmt.Errorf("%w: %q is not a string", ErrInvalidMember, key)
	}
	return s, nil
}

// optString returns a string member or "" if absent. A non-string
// value is treated as absent (returns "").
func optString(m map[string]any, key string) string {
	v, ok := m[key]
	if !ok {
		return ""
	}
	s, _ := v.(string)
	return s
}

// checkDuplicateMembers parses a JSON object and returns
// ErrDuplicateMember if any top-level member name appears more than
// once. It also validates that the input is a single JSON object.
// Nested values are consumed with json.Decoder.Decode so the full
// value is skipped; only top-level keys are checked for duplicates
// (JWK members are top-level).
func checkDuplicateMembers(data []byte) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	t, err := dec.Token()
	if err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidMember, err)
	}
	d, ok := t.(json.Delim)
	if !ok || d != '{' {
		return fmt.Errorf("%w: expected JSON object", ErrInvalidMember)
	}
	seen := make(map[string]bool)
	for dec.More() {
		t, err := dec.Token()
		if err != nil {
			return fmt.Errorf("%w: %v", ErrInvalidMember, err)
		}
		key, ok := t.(string)
		if !ok {
			return fmt.Errorf("%w: expected string member name", ErrInvalidMember)
		}
		if seen[key] {
			return fmt.Errorf("%w: %q", ErrDuplicateMember, key)
		}
		seen[key] = true
		var v any
		if err := dec.Decode(&v); err != nil {
			return fmt.Errorf("%w: %v", ErrInvalidMember, err)
		}
	}
	if _, err := dec.Token(); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidMember, err)
	}
	return nil
}
