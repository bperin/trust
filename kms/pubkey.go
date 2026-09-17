package kms

import (
	"crypto"
	stdecdsa "crypto/ecdsa"
	"crypto/elliptic"
	"crypto/subtle"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"

	"github.com/bperin/trust/crypto/ecdsa"
	"github.com/bperin/trust/crypto/ed25519"
	"github.com/bperin/trust/crypto/secp256k1"
)

// ErrInvalidPublicKeyDER is returned when a DER-encoded X.509
// SubjectPublicKeyInfo cannot be parsed or names an unsupported key.
var ErrInvalidPublicKeyDER = errors.New("kms: invalid public key DER")

// Algorithm and named-curve OIDs accepted by ParsePublicKeyDER.
var (
	oidECPublicKey = asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1}    // [RFC 5480] §2.1.1
	oidEd25519     = asn1.ObjectIdentifier{1, 3, 101, 112}            // [RFC 8410] §4
	oidP256        = asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 7} // [RFC 5480] §A.1
	oidSecp256k1   = asn1.ObjectIdentifier{1, 3, 132, 0, 10}          // [SEC 2 v2] §2.4.1
	oidP384        = asn1.ObjectIdentifier{1, 3, 132, 0, 34}          // [SEC 2 v2] §2.5.1
	ed25519KeySize = 32                                               // [RFC 8032] §5.1.5
)

// subjectPublicKeyInfo is the [RFC 5280] §4.1 SubjectPublicKeyInfo
// structure. The Algorithm field is captured as a raw ASN.1 value so
// the inner AlgorithmIdentifier can be parsed element-by-element with
// a strict no-trailing-bytes check.
type subjectPublicKeyInfo struct {
	Algorithm        asn1.RawValue
	SubjectPublicKey asn1.BitString
}

// ParsePublicKeyDER parses a DER-encoded X.509 SubjectPublicKeyInfo per
// [RFC 5280] §4.1 and returns the trust public key it names: an
// *ed25519.PublicKey, an *ecdsa.PublicKey on P-256 or P-384, or a
// *secp256k1.PublicKey. Cloud KMS providers return public keys in this
// format; the stdlib x509 parser is unusable here because it rejects
// secp256k1 and cannot bind the trust wrappers. Every rejection wraps
// ErrInvalidPublicKeyDER.
func ParsePublicKeyDER(derBytes []byte) (crypto.PublicKey, error) {
	if len(derBytes) == 0 {
		return nil, fmt.Errorf("%w: empty input", ErrInvalidPublicKeyDER)
	}

	var spki subjectPublicKeyInfo
	rest, err := asn1.Unmarshal(derBytes, &spki)
	if err != nil {
		return nil, fmt.Errorf("%w: asn1 parse failed: %v", ErrInvalidPublicKeyDER, err)
	}
	if len(rest) != 0 {
		return nil, fmt.Errorf("%w: trailing bytes after SPKI (%d)", ErrInvalidPublicKeyDER, len(rest))
	}

	// The Algorithm element must be a SEQUENCE ([RFC 5280]
	// §4.1.1.2 AlgorithmIdentifier).
	if spki.Algorithm.Class != asn1.ClassUniversal ||
		spki.Algorithm.Tag != asn1.TagSequence ||
		!spki.Algorithm.IsCompound {
		return nil, fmt.Errorf("%w: AlgorithmIdentifier is not a SEQUENCE (class %d, tag %d)",
			ErrInvalidPublicKeyDER, spki.Algorithm.Class, spki.Algorithm.Tag)
	}

	// A key is a whole number of bytes, so a non-zero unused-bits count
	// in the BIT STRING is a malformed or deliberately shortened encoding.
	if spki.SubjectPublicKey.BitLength != len(spki.SubjectPublicKey.Bytes)*8 {
		return nil, fmt.Errorf("%w: BIT STRING declares %d bits for %d content bytes",
			ErrInvalidPublicKeyDER, spki.SubjectPublicKey.BitLength, len(spki.SubjectPublicKey.Bytes))
	}

	// Parse the AlgorithmIdentifier element-by-element: an algorithm OID
	// and then, for the id-ecPublicKey family only, a named-curve OID.
	// Parsing into a struct would silently ignore surplus elements.
	var algOID asn1.ObjectIdentifier
	algRest, err := asn1.Unmarshal(spki.Algorithm.Bytes, &algOID)
	if err != nil {
		return nil, fmt.Errorf("%w: algorithm OID parse failed: %v", ErrInvalidPublicKeyDER, err)
	}

	point := spki.SubjectPublicKey.Bytes

	switch {
	case algOID.Equal(oidEd25519):
		// [RFC 8410] §3 requires the parameters field to be absent for
		// EdDSA.
		if len(algRest) != 0 {
			return nil, fmt.Errorf("%w: Ed25519 AlgorithmIdentifier must omit parameters, got %d surplus bytes",
				ErrInvalidPublicKeyDER, len(algRest))
		}
		return parseEd25519PublicKey(point)
	case algOID.Equal(oidECPublicKey):
		var curveOID asn1.ObjectIdentifier
		paramsRest, err := asn1.Unmarshal(algRest, &curveOID)
		if err != nil {
			return nil, fmt.Errorf("%w: curve OID parse failed: %v", ErrInvalidPublicKeyDER, err)
		}
		if len(paramsRest) != 0 {
			return nil, fmt.Errorf("%w: trailing bytes in AlgorithmIdentifier (%d)", ErrInvalidPublicKeyDER, len(paramsRest))
		}
		return parseECPublicKey(curveOID, point)
	default:
		return nil, fmt.Errorf("%w: unsupported algorithm OID %v", ErrInvalidPublicKeyDER, algOID)
	}
}

// parseEd25519PublicKey decodes the raw key octet string carried in an
// Ed25519 SubjectPublicKey BIT STRING [RFC 8410] §4.
func parseEd25519PublicKey(point []byte) (crypto.PublicKey, error) {
	if len(point) != ed25519KeySize {
		return nil, fmt.Errorf("%w: want %d-byte Ed25519 key, got %d",
			ErrInvalidPublicKeyDER, ed25519KeySize, len(point))
	}
	pub, err := ed25519.NewPublicKey(point)
	if err != nil {
		return nil, fmt.Errorf("%w: ed25519 key parse failed: %v", ErrInvalidPublicKeyDER, err)
	}
	return pub, nil
}

// parseECPublicKey dispatches on the named-curve OID carried in the
// AlgorithmIdentifier parameters field.
func parseECPublicKey(curveOID asn1.ObjectIdentifier, point []byte) (crypto.PublicKey, error) {
	switch {
	case curveOID.Equal(oidSecp256k1):
		return parseSecp256k1PublicKey(point)
	case curveOID.Equal(oidP256):
		return parseNISTPublicKey(elliptic.P256(), crypto.SHA256, point)
	case curveOID.Equal(oidP384):
		return parseNISTPublicKey(elliptic.P384(), crypto.SHA384, point)
	default:
		return nil, fmt.Errorf("%w: unsupported curve OID %v", ErrInvalidPublicKeyDER, curveOID)
	}
}

// parseNISTPublicKey decodes a 0x04 || X || Y point on a NIST prime curve
// and binds the wrapper to the hash that curve mandates ([FIPS 186-4]
// §6.4: SHA-256 for P-256, SHA-384 for P-384).
func parseNISTPublicKey(curve elliptic.Curve, hash crypto.Hash, point []byte) (crypto.PublicKey, error) {
	size := (curve.Params().BitSize + 7) / 8
	if len(point) != 1+2*size {
		return nil, fmt.Errorf("%w: want %d-byte uncompressed point for %s, got %d",
			ErrInvalidPublicKeyDER, 1+2*size, curve.Params().Name, len(point))
	}
	if point[0] != 0x04 {
		return nil, fmt.Errorf("%w: want 0x04 uncompressed prefix, got 0x%02x", ErrInvalidPublicKeyDER, point[0])
	}

	x := new(big.Int).SetBytes(point[1 : 1+size])
	y := new(big.Int).SetBytes(point[1+size:])
	if x.Cmp(curve.Params().P) >= 0 || y.Cmp(curve.Params().P) >= 0 {
		return nil, fmt.Errorf("%w: %s coordinate not reduced below p", ErrInvalidPublicKeyDER, curve.Params().Name)
	}
	if !curve.IsOnCurve(x, y) {
		return nil, fmt.Errorf("%w: point not on curve %s", ErrInvalidPublicKeyDER, curve.Params().Name)
	}

	pub, err := ecdsa.NewPublicKey(&stdecdsa.PublicKey{Curve: curve, X: x, Y: y}, hash)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidPublicKeyDER, err)
	}
	return pub, nil
}

// parseSecp256k1PublicKey decodes a 0x04 || X || Y point through the
// 33-byte compressed form secp256k1 accepts, rejecting any (X, Y) pair
// that is not the curve point for X.
func parseSecp256k1PublicKey(point []byte) (crypto.PublicKey, error) {
	if len(point) != 65 {
		return nil, fmt.Errorf("%w: want 65-byte uncompressed point, got %d", ErrInvalidPublicKeyDER, len(point))
	}
	if point[0] != 0x04 {
		return nil, fmt.Errorf("%w: want 0x04 uncompressed prefix, got 0x%02x", ErrInvalidPublicKeyDER, point[0])
	}

	x := point[1:33]
	y := point[33:65]

	// Compress: prefix 0x02 if y is even, 0x03 if y is odd. The parity
	// is determined by the least-significant bit of Y.
	var prefix byte
	if y[31]&1 == 0 {
		prefix = 0x02
	} else {
		prefix = 0x03
	}
	compressed := make([]byte, 33)
	compressed[0] = prefix
	copy(compressed[1:], x)

	pub, err := secp256k1.NewPublicKey(compressed)
	if err != nil {
		return nil, fmt.Errorf("%w: compressed point parse failed: %v", ErrInvalidPublicKeyDER, err)
	}
	// Compression keeps only Y's parity, so re-encode and require the
	// supplied coordinates to survive the round trip unchanged. This
	// rejects an (X, Y) pair that is not the curve point for X.
	if subtle.ConstantTimeCompare(pub.BytesUncompressed(), point) != 1 {
		return nil, fmt.Errorf("%w: point is not on curve secp256k1", ErrInvalidPublicKeyDER)
	}
	return pub, nil
}
