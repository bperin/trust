package kms

import (
	"crypto"
	stdecdsa "crypto/ecdsa"
	stded25519 "crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/subtle"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"math/big"
	"os"
	"reflect"
	"testing"

	"github.com/bperin/trust/crypto/ecdsa"
	"github.com/bperin/trust/crypto/ed25519"
	"github.com/bperin/trust/crypto/secp256k1"
)

// readVector loads a committed testdata file, failing rather than skipping.
func readVector(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatalf("read testdata/%s: %v (committed vector missing)", name, err)
	}
	return data
}

// marshalDERSeq wraps content in a DER SEQUENCE ([X.690] §8.10).
func marshalDERSeq(t *testing.T, content []byte) []byte {
	t.Helper()
	b, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSequence,
		IsCompound: true,
		Bytes:      content,
	})
	if err != nil {
		t.Fatalf("marshal SEQUENCE: %v", err)
	}
	return b
}

// marshalOID ASN.1-encodes an object identifier.
func marshalOID(t *testing.T, oid asn1.ObjectIdentifier) []byte {
	t.Helper()
	b, err := asn1.Marshal(oid)
	if err != nil {
		t.Fatalf("marshal OID %v: %v", oid, err)
	}
	return b
}

// marshalAlgID builds an AlgorithmIdentifier ([RFC 5280] §4.1.1.2) from an
// algorithm OID and an optional named-curve OID.
func marshalAlgID(t *testing.T, algOID, curveOID asn1.ObjectIdentifier) []byte {
	t.Helper()
	body := marshalOID(t, algOID)
	if curveOID != nil {
		body = append(body, marshalOID(t, curveOID)...)
	}
	return marshalDERSeq(t, body)
}

// marshalSPKI builds a SubjectPublicKeyInfo ([RFC 5280] §4.1) from a raw
// AlgorithmIdentifier and a raw subjectPublicKey element.
func marshalSPKI(t *testing.T, algFullBytes []byte, pubKey asn1.RawValue) []byte {
	t.Helper()
	b, err := asn1.Marshal(struct {
		Algorithm        asn1.RawValue
		SubjectPublicKey asn1.RawValue
	}{
		Algorithm:        asn1.RawValue{FullBytes: algFullBytes},
		SubjectPublicKey: pubKey,
	})
	if err != nil {
		t.Fatalf("marshal SPKI: %v", err)
	}
	return b
}

// bitString encodes point as a DER BIT STRING with zero unused bits.
func bitString(point []byte) asn1.RawValue {
	return asn1.RawValue{
		Class: asn1.ClassUniversal,
		Tag:   asn1.TagBitString,
		Bytes: append([]byte{0x00}, point...),
	}
}

// spkiForPoint builds an EC SubjectPublicKeyInfo for a curve OID and point.
func spkiForPoint(t *testing.T, curveOID asn1.ObjectIdentifier, point []byte) []byte {
	t.Helper()
	return marshalSPKI(t, marshalAlgID(t, oidECPublicKey, curveOID), bitString(point))
}

// spkiForEd25519 builds an Ed25519 SubjectPublicKeyInfo over a raw key.
func spkiForEd25519(t *testing.T, key []byte) []byte {
	t.Helper()
	return marshalSPKI(t, marshalAlgID(t, oidEd25519, nil), bitString(key))
}

// fixedPoint returns the 0x04 || X || Y encoding of a point, padding each
// coordinate to size bytes.
func fixedPoint(size int, x, y *big.Int) []byte {
	point := make([]byte, 1+2*size)
	point[0] = 0x04
	xBytes, yBytes := x.Bytes(), y.Bytes()
	copy(point[1+size-len(xBytes):1+size], xBytes)
	copy(point[1+2*size-len(yBytes):], yBytes)
	return point
}

// uncompressedPoint returns the 0x04 || X || Y encoding of a NIST curve point.
func uncompressedPoint(curve elliptic.Curve, x, y *big.Int) []byte {
	return fixedPoint((curve.Params().BitSize+7)/8, x, y)
}

// pointFromSPKI extracts the subjectPublicKey octets with the stdlib
// decoder so tests can assert against independently decoded bytes.
func pointFromSPKI(derBytes []byte) ([]byte, error) {
	var parsed struct {
		Algorithm        asn1.RawValue
		SubjectPublicKey asn1.BitString
	}
	rest, err := asn1.Unmarshal(derBytes, &parsed)
	if err != nil {
		return nil, err
	}
	if len(rest) != 0 {
		return nil, errors.New("trailing bytes after SPKI")
	}
	return parsed.SubjectPublicKey.Bytes, nil
}

// mustPoint returns the subjectPublicKey octets of a committed vector.
func mustPoint(t *testing.T, name string) []byte {
	t.Helper()
	point, err := pointFromSPKI(readVector(t, name))
	if err != nil {
		t.Fatalf("pointFromSPKI(testdata/%s): %v", name, err)
	}
	return point
}

// mustGenerateECDSA generates a stdlib ECDSA key on the given curve.
func mustGenerateECDSA(t *testing.T, curve elliptic.Curve) *stdecdsa.PrivateKey {
	t.Helper()
	key, err := stdecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatalf("stdlib ecdsa.GenerateKey(%s): %v", curve.Params().Name, err)
	}
	return key
}

// mustMarshalPKIX encodes a public key as a DER SubjectPublicKeyInfo.
func mustMarshalPKIX(t *testing.T, key crypto.PublicKey) []byte {
	t.Helper()
	derBytes, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		t.Fatalf("x509.MarshalPKIXPublicKey: %v", err)
	}
	return derBytes
}

// checkEd25519Bytes asserts the parsed key carries the expected raw bytes.
func checkEd25519Bytes(want []byte) func(t *testing.T, got crypto.PublicKey) {
	return func(t *testing.T, got crypto.PublicKey) {
		t.Helper()
		gotBytes := got.(*ed25519.PublicKey).Bytes()
		if subtle.ConstantTimeCompare(gotBytes[:], want) != 1 {
			t.Errorf("ed25519 key = %x, want %x", gotBytes[:], want)
		}
	}
}

// checkECPoint asserts the parsed key carries a known curve point.
func checkECPoint(want *stdecdsa.PublicKey) func(t *testing.T, got crypto.PublicKey) {
	return func(t *testing.T, got crypto.PublicKey) {
		t.Helper()
		pub := got.(*ecdsa.PublicKey)
		if pub.Curve() != want.Curve {
			t.Errorf("curve = %v, want %v", pub.Curve(), want.Curve)
		}
		if pub.X().Cmp(want.X) != 0 || pub.Y().Cmp(want.Y) != 0 {
			t.Errorf("point = (%x, %x), want (%x, %x)", pub.X(), pub.Y(), want.X, want.Y)
		}
	}
}

// checkECMatchesStdlib parses the same DER with crypto/x509 and requires both
// decoders to agree on the key.
func checkECMatchesStdlib(derBytes []byte) func(t *testing.T, got crypto.PublicKey) {
	return func(t *testing.T, got crypto.PublicKey) {
		t.Helper()
		parsed, err := x509.ParsePKIXPublicKey(derBytes)
		if err != nil {
			t.Fatalf("x509.ParsePKIXPublicKey: %v", err)
		}
		stdWant, ok := parsed.(*stdecdsa.PublicKey)
		if !ok {
			t.Fatalf("x509 parser returned %T, want *crypto/ecdsa.PublicKey", parsed)
		}
		checkECPoint(stdWant)(t, got)
	}
}

// checkPointBytes asserts the parsed secp256k1 key re-encodes to a known point.
func checkPointBytes(want []byte) func(t *testing.T, got crypto.PublicKey) {
	return func(t *testing.T, got crypto.PublicKey) {
		t.Helper()
		pub := got.(*secp256k1.PublicKey)
		if subtle.ConstantTimeCompare(pub.BytesUncompressed(), want) != 1 {
			t.Errorf("secp256k1 point = %x, want %x", pub.BytesUncompressed(), want)
		}
	}
}

// sameKey compares two parsed trust public keys in constant time.
func sameKey(a, b crypto.PublicKey) bool {
	switch x := a.(type) {
	case *ed25519.PublicKey:
		y, ok := b.(*ed25519.PublicKey)
		return ok && x.Equal(y)
	case *ecdsa.PublicKey:
		y, ok := b.(*ecdsa.PublicKey)
		return ok && x.Equal(y)
	case *secp256k1.PublicKey:
		y, ok := b.(*secp256k1.PublicKey)
		return ok && x.Equal(y)
	default:
		return false
	}
}

func TestParsePublicKeyDER(t *testing.T) {
	t.Parallel()

	kmsEdDER := readVector(t, "kms_ed25519_pubkey")
	kmsP384DER := readVector(t, "kms_p384_der_pubkey")
	kmsP256DER := readVector(t, "kms_p256_der_pubkey")
	kmsK256DER := readVector(t, "kms_es256k_der_pubkey")

	_, k256Pub, err := secp256k1.GenerateKey()
	if err != nil {
		t.Fatalf("secp256k1.GenerateKey: %v", err)
	}
	stdEdPub, _, err := stded25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("stdlib ed25519.GenerateKey: %v", err)
	}
	stdP256 := mustGenerateECDSA(t, elliptic.P256())
	stdP384 := mustGenerateECDSA(t, elliptic.P384())

	tests := []struct {
		name     string
		in       []byte
		wantType any
		check    func(t *testing.T, got crypto.PublicKey)
	}{
		{
			name:     "recorded_kms_ed25519_spki",
			in:       kmsEdDER,
			wantType: (*ed25519.PublicKey)(nil),
			check:    checkEd25519Bytes(mustPoint(t, "kms_ed25519_pubkey")),
		},
		{
			name:     "recorded_kms_p384_spki",
			in:       kmsP384DER,
			wantType: (*ecdsa.PublicKey)(nil),
			check:    checkECMatchesStdlib(kmsP384DER),
		},
		{
			name:     "recorded_synthetic_p256_spki",
			in:       kmsP256DER,
			wantType: (*ecdsa.PublicKey)(nil),
			check:    checkECMatchesStdlib(kmsP256DER),
		},
		{
			name:     "recorded_synthetic_secp256k1_spki",
			in:       kmsK256DER,
			wantType: (*secp256k1.PublicKey)(nil),
			check:    checkPointBytes(mustPoint(t, "kms_es256k_der_pubkey")),
		},
		{
			name:     "stdlib_generated_ed25519_spki",
			in:       mustMarshalPKIX(t, stdEdPub),
			wantType: (*ed25519.PublicKey)(nil),
			check:    checkEd25519Bytes([]byte(stdEdPub)),
		},
		{
			name:     "stdlib_generated_p256_spki",
			in:       mustMarshalPKIX(t, &stdP256.PublicKey),
			wantType: (*ecdsa.PublicKey)(nil),
			check:    checkECPoint(&stdP256.PublicKey),
		},
		{
			name:     "stdlib_generated_p384_spki",
			in:       mustMarshalPKIX(t, &stdP384.PublicKey),
			wantType: (*ecdsa.PublicKey)(nil),
			check:    checkECPoint(&stdP384.PublicKey),
		},
		{
			name:     "hand_built_secp256k1_spki",
			in:       spkiForPoint(t, oidSecp256k1, k256Pub.BytesUncompressed()),
			wantType: (*secp256k1.PublicKey)(nil),
			check: func(t *testing.T, got crypto.PublicKey) {
				t.Helper()
				if !got.(*secp256k1.PublicKey).Equal(k256Pub) {
					t.Errorf("secp256k1 key = %s, want %s",
						got.(*secp256k1.PublicKey).Redact(), k256Pub.Redact())
				}
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := ParsePublicKeyDER(tc.in)
			if err != nil {
				t.Fatalf("ParsePublicKeyDER(%d bytes): got error %v, want nil", len(tc.in), err)
			}
			if got == nil {
				t.Fatalf("ParsePublicKeyDER(%d bytes): got nil key, want non-nil", len(tc.in))
			}
			if want := reflect.TypeOf(tc.wantType); reflect.TypeOf(got) != want {
				t.Fatalf("key type = %T, want %v", got, want)
			}
			tc.check(t, got)

			again, err := ParsePublicKeyDER(tc.in)
			if err != nil {
				t.Fatalf("ParsePublicKeyDER reparse: got error %v, want nil", err)
			}
			if !sameKey(got, again) {
				t.Errorf("parsing the same DER twice produced different keys: %T vs %T", got, again)
			}
		})
	}
}

func TestParsePublicKeyDER_Negatives(t *testing.T) {
	t.Parallel()

	kmsEdDER := readVector(t, "kms_ed25519_pubkey")
	kmsP256DER := readVector(t, "kms_p256_der_pubkey")
	edPoint := mustPoint(t, "kms_ed25519_pubkey")
	p256Point := mustPoint(t, "kms_p256_der_pubkey")
	p384Point := mustPoint(t, "kms_p384_der_pubkey")
	k256Point := mustPoint(t, "kms_es256k_der_pubkey")

	p256Params := elliptic.P256().Params()
	edAlgWithParams := marshalDERSeq(t, append(marshalOID(t, oidEd25519), 0x05, 0x00))
	rsaAlg := marshalAlgID(t, asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}, nil)
	ecAlgNoParams := marshalDERSeq(t, marshalOID(t, oidECPublicKey))
	notASequence, err := asn1.Marshal(asn1.RawValue{
		Class: asn1.ClassUniversal,
		Tag:   asn1.TagInteger,
		Bytes: []byte{0x01},
	})
	if err != nil {
		t.Fatalf("marshal non-SEQUENCE AlgorithmIdentifier: %v", err)
	}

	tests := []struct {
		name string
		in   []byte
	}{
		{"empty_input", nil},
		{"garbage_bytes", []byte{0x00, 0x01, 0x02}},
		{"truncated_sequence", kmsP256DER[:len(kmsP256DER)/2]},
		{"trailing_bytes_after_spki", append(append([]byte{}, kmsEdDER...), 0x00, 0x00)},
		{"algorithm_identifier_not_sequence", marshalSPKI(t, notASequence, bitString(edPoint))},
		{"unsupported_algorithm_oid", marshalSPKI(t, rsaAlg, bitString(edPoint))},
		{"ec_public_key_without_curve_oid", marshalSPKI(t, ecAlgNoParams, bitString(p256Point))},
		{"unsupported_curve_oid_p521", spkiForPoint(t, asn1.ObjectIdentifier{1, 3, 132, 0, 35}, p256Point)},
		{"ed25519_with_parameters", marshalSPKI(t, edAlgWithParams, bitString(edPoint))},
		{"bit_string_unused_bits_nonzero", marshalSPKI(t, marshalAlgID(t, oidEd25519, nil), asn1.RawValue{
			Class: asn1.ClassUniversal,
			Tag:   asn1.TagBitString,
			Bytes: append([]byte{0x01}, edPoint...),
		})},
		{"ed25519_key_one_byte_short", spkiForEd25519(t, edPoint[:31])},
		{"ed25519_key_one_byte_long", spkiForEd25519(t, append(append([]byte{}, edPoint...), 0x00))},
		{"p256_point_one_byte_short", spkiForPoint(t, oidP256, p256Point[:64])},
		{"p256_point_one_byte_long", spkiForPoint(t, oidP256, append(append([]byte{}, p256Point...), 0x00))},
		{"p256_point_compressed_prefix", spkiForPoint(t, oidP256,
			append([]byte{0x02}, p256Point[1:]...))},
		{"p256_point_not_on_curve", spkiForPoint(t, oidP256,
			uncompressedPoint(p256Params, big.NewInt(1), big.NewInt(1)))},
		{"p256_coordinate_not_below_p", spkiForPoint(t, oidP256,
			uncompressedPoint(p256Params, p256Params.P, big.NewInt(3)))},
		{"p384_point_one_byte_short", spkiForPoint(t, oidP384, p384Point[:96])},
		{"p384_point_one_byte_long", spkiForPoint(t, oidP384, append(append([]byte{}, p384Point...), 0x00))},
		{"secp256k1_point_one_byte_short", spkiForPoint(t, oidSecp256k1, k256Point[:64])},
		{"secp256k1_point_compressed_prefix", spkiForPoint(t, oidSecp256k1,
			append([]byte{0x02}, k256Point[1:]...))},
		{"secp256k1_point_not_on_curve", spkiForPoint(t, oidSecp256k1,
			fixedPoint(32, big.NewInt(1), big.NewInt(1)))},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := ParsePublicKeyDER(tc.in)
			if err == nil {
				t.Fatalf("ParsePublicKeyDER(%s): got %T with nil error, want error wrapping ErrInvalidPublicKeyDER", tc.name, got)
			}
			if got != nil {
				t.Errorf("ParsePublicKeyDER(%s): returned non-nil key %T alongside error", tc.name, got)
			}
			if !errors.Is(err, ErrInvalidPublicKeyDER) {
				t.Errorf("ParsePublicKeyDER(%s): err = %v, want errors.Is(err, ErrInvalidPublicKeyDER)", tc.name, err)
			}
		})
	}
}
