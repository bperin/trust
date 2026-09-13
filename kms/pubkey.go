package kms

import (
	"encoding/asn1"
	"errors"
	"fmt"

	"github.com/bperin/trust/crypto/secp256k1"
)

// ErrInvalidPublicKeyDER is returned when a DER-encoded X.509
// SubjectPublicKeyInfo cannot be parsed or does not contain a valid
// secp256k1 uncompressed EC point.
var ErrInvalidPublicKeyDER = errors.New("kms: invalid public key DER")

// algorithmIdentifier is the [RFC 5280] AlgorithmIdentifier
// structure, parsed only for its structure — no ECDSA-specific logic
// is applied. The Parameters field is captured as a raw ASN.1 value
// so any curve OID is accepted without interpretation.
type algorithmIdentifier struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters asn1.RawValue `asn1:"optional"`
}

// subjectPublicKeyInfo is the [RFC 5280] §4.1 SubjectPublicKeyInfo
// structure. The SubjectPublicKey is a BIT STRING whose content (after
// the unused-bits byte) is the raw EC point.
type subjectPublicKeyInfo struct {
	Algorithm        algorithmIdentifier
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
// Returns an error wrapping ErrInvalidPublicKeyDER for malformed DER,
// a missing or wrong-length EC point, or a point that does not parse
// as a secp256k1 public key.
//
// Reference: [RFC 5280] §4.1 (SubjectPublicKeyInfo), [SEC 1 v2] §2.3.4
// (point encodings), [SEC 2 v2] §2.4 (secp256k1 parameters).
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
