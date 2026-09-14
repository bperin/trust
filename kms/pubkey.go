package kms

import (
	"encoding/asn1"
	"errors"
	"fmt"

	"github.com/bperin/trust/trust/crypto/secp256k1"
)

// ErrInvalidPublicKeyDER is returned when a DER-encoded X.509
// SubjectPublicKeyInfo cannot be parsed or does not contain a valid
// secp256k1 uncompressed EC point.
var ErrInvalidPublicKeyDER = errors.New("kms: invalid public key DER")

// oidECPublicKey is the id-ecPublicKey algorithm OID per [RFC 5480]
// §2.1.1: 1.2.840.10045.2.1. The SPKI algorithm field must equal this
// OID exactly — any other algorithm (RSA, Ed25519, an ECDSA signature
// algorithm) is rejected.
var oidECPublicKey = asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1}

// oidSecp256k1 is the secp256k1 named-curve OID per [SEC 2 v2] §2.4.1:
// 1.3.132.0.10. The SPKI parameters field must carry this OID — any
// other curve (P-256, P-384) or a missing parameter is rejected.
var oidSecp256k1 = asn1.ObjectIdentifier{1, 3, 132, 0, 10}

// subjectPublicKeyInfo is the [RFC 5280] §4.1 SubjectPublicKeyInfo
// structure. The SubjectPublicKey is a BIT STRING whose content (after
// the unused-bits byte) is the raw EC point.
//
// The Algorithm field is captured as a raw ASN.1 value so the inner
// AlgorithmIdentifier SEQUENCE can be parsed element-by-element with a
// strict no-trailing-bytes check — the stdlib asn1 struct parser
// silently ignores surplus elements inside a SEQUENCE, which would let
// a malformed AlgorithmIdentifier slip through.
type subjectPublicKeyInfo struct {
	Algorithm        asn1.RawValue
	SubjectPublicKey asn1.BitString
}

// ParsePublicKeyDER parses a DER-encoded X.509 SubjectPublicKeyInfo
// ([RFC 5280] §4.1) and returns the secp256k1 public key it carries.
//
// AWS KMS GetPublicKey and GCP KMS GetPublicKey return the public key
// in X.509 SubjectPublicKeyInfo DER. The stdlib crypto/x509.ParsePKIXPublicKey
// must NOT be used here: stdlib ECDSA binds to elliptic.P256()/P384(),
// not secp256k1, so it will not natively parse a secp256k1 SPKI. Instead
// the SPKI is parsed structurally to extract the subjectPublicKey BIT
// STRING, the uncompressed EC point (0x04 || X || Y) is read from it,
// and the point is compressed to a 33-byte compressed point
// (0x02/0x03 prefix based on y-parity) for secp256k1.NewPublicKey,
// which accepts only 33-byte compressed keys.
//
// The AlgorithmIdentifier is strictly validated before the point is
// touched: the algorithm OID must be id-ecPublicKey ([RFC 5480]
// §2.1.1) and the parameters must be the secp256k1 named-curve OID
// ([SEC 2 v2] §2.4.1). A wrong algorithm OID, wrong or missing curve
// OID, or a malformed AlgorithmIdentifier is rejected — a P-256 point
// must never be interpreted as secp256k1.
//
// Returns an error wrapping ErrInvalidPublicKeyDER for malformed DER,
// a wrong algorithm or curve OID, a missing or wrong-length EC point,
// or a point that does not parse as a secp256k1 public key.
//
// Reference: [RFC 5280] §4.1 (SubjectPublicKeyInfo), [RFC 5480] §2.1.1
// (id-ecPublicKey), [SEC 2 v2] §2.4.1 (secp256k1 OID), [SEC 1 v2]
// §2.3.4 (point encodings).
func ParsePublicKeyDER(derBytes []byte) (*secp256k1.PublicKey, error) {
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

	// Parse the SEQUENCE contents element-by-element: an algorithm
	// OID, then a parameters OID, then nothing. Parsing into a struct
	// would silently ignore surplus elements.
	var algOID, curveOID asn1.ObjectIdentifier
	algRest, err := asn1.Unmarshal(spki.Algorithm.Bytes, &algOID)
	if err != nil {
		return nil, fmt.Errorf("%w: algorithm OID parse failed: %v", ErrInvalidPublicKeyDER, err)
	}
	algRest, err = asn1.Unmarshal(algRest, &curveOID)
	if err != nil {
		return nil, fmt.Errorf("%w: curve OID parse failed: %v", ErrInvalidPublicKeyDER, err)
	}
	if len(algRest) != 0 {
		return nil, fmt.Errorf("%w: trailing bytes in AlgorithmIdentifier (%d)", ErrInvalidPublicKeyDER, len(algRest))
	}

	// Strict OID validation: [RFC 5480] §2.1.1 requires
	// id-ecPublicKey; [SEC 2 v2] §2.4.1 names secp256k1 as
	// 1.3.132.0.10.
	if !algOID.Equal(oidECPublicKey) {
		return nil, fmt.Errorf("%w: algorithm OID %v, want id-ecPublicKey %v", ErrInvalidPublicKeyDER, algOID, oidECPublicKey)
	}
	if !curveOID.Equal(oidSecp256k1) {
		return nil, fmt.Errorf("%w: curve OID %v, want secp256k1 %v", ErrInvalidPublicKeyDER, curveOID, oidSecp256k1)
	}

	// The BIT STRING content (asn1.BitString.Bytes) excludes the
	// leading unused-bits byte. For an EC point it must be the
	// uncompressed encoding 0x04 || X(32) || Y(32) = 65 bytes.
	point := spki.SubjectPublicKey.Bytes
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
	return pub, nil
}
