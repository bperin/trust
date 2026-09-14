package kms

import (
	"encoding/asn1"
	"errors"
	"testing"

	"github.com/bperin/trust/crypto/secp256k1"
)

// secp256k1OID is the named-curve OID for secp256k1 per [SEC 2 v2]
// §2.4: 1.3.132.0.10.
var secp256k1OID = asn1.ObjectIdentifier{1, 3, 132, 0, 10}

// ecPublicKeyOID is the id-ecPublicKey algorithm OID per [RFC 5480]:
// 1.2.840.10045.2.1.
var ecPublicKeyOID = asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1}

// algorithmIdentifierDER is the [RFC 5280] AlgorithmIdentifier for an
// EC public key on secp256k1, used to build SPKI test vectors.
type algorithmIdentifierDER struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters asn1.ObjectIdentifier
}

// spkiDER is the [RFC 5280] §4.1 SubjectPublicKeyInfo test vector.
type spkiDER struct {
	Algorithm        algorithmIdentifierDER
	SubjectPublicKey asn1.BitString
}

// buildSPKI builds a DER-encoded X.509 SubjectPublicKeyInfo for a
// secp256k1 public key from its uncompressed point. Used to build
// test vectors for ParsePublicKeyDER.
func buildSPKI(t *testing.T, pub *secp256k1.PublicKey) []byte {
	t.Helper()
	uncompressed := pub.BytesUncompressed()
	spki := spkiDER{
		Algorithm: algorithmIdentifierDER{
			Algorithm:  ecPublicKeyOID,
			Parameters: secp256k1OID,
		},
		SubjectPublicKey: asn1.BitString{
			Bytes:     uncompressed,
			BitLength: len(uncompressed) * 8,
		},
	}
	b, err := asn1.Marshal(spki)
	if err != nil {
		t.Fatalf("asn1.Marshal SPKI: %v", err)
	}
	return b
}

// mustDER marshals v to DER, failing the test on marshal error.
func mustDER(t *testing.T, v any) []byte {
	t.Helper()
	b, err := asn1.Marshal(v)
	if err != nil {
		t.Fatalf("asn1.Marshal(%T): %v", v, err)
	}
	return b
}

// buildSPKIRaw builds a DER-encoded SubjectPublicKeyInfo with an
// arbitrary algorithm OID, an arbitrary DER-encoded parameters element
// (nil omits the parameters field entirely), and an arbitrary
// public-key BIT STRING payload. It hand-rolls the SEQUENCE wrappers
// so known-bad AlgorithmIdentifier contents can be expressed — the
// struct-based buildSPKI can only produce well-formed vectors.
func buildSPKIRaw(t *testing.T, algOID asn1.ObjectIdentifier, paramsDER, point []byte) []byte {
	t.Helper()
	algBody := append(mustDER(t, algOID), paramsDER...)
	if len(algBody) > 127 {
		t.Fatalf("buildSPKIRaw: AlgorithmIdentifier body %d bytes exceeds short-form length", len(algBody))
	}
	algSeq := append([]byte{0x30, byte(len(algBody))}, algBody...)
	bitString := mustDER(t, asn1.BitString{Bytes: point, BitLength: len(point) * 8})
	body := append(algSeq, bitString...)
	if len(body) > 127 {
		t.Fatalf("buildSPKIRaw: SPKI body %d bytes exceeds short-form length", len(body))
	}
	return append([]byte{0x30, byte(len(body))}, body...)
}

// TestParsePublicKeyDER_RoundTrip verifies that an SPKI built from a
// generated secp256k1 key parses back to the same compressed key.
func TestParsePublicKeyDER_RoundTrip(t *testing.T) {
	t.Parallel()
	for i := 0; i < 4; i++ {
		_, pub, err := secp256k1.GenerateKey()
		if err != nil {
			t.Fatalf("GenerateKey: %v", err)
		}
		spki := buildSPKI(t, pub)

		got, err := ParsePublicKeyDER(spki)
		if err != nil {
			t.Fatalf("ParsePublicKeyDER: %v", err)
		}
		if !got.Equal(pub) {
			t.Fatalf("parsed key mismatch: got %s, want %s",
				got.Redact(), pub.Redact())
		}
	}
}

// TestParsePublicKeyDER_NegativeCases verifies malformed SPKI is
// rejected.
func TestParsePublicKeyDER_NegativeCases(t *testing.T) {
	t.Parallel()
	_, pub, err := secp256k1.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	valid := buildSPKI(t, pub)

	cases := []struct {
		name string
		in   []byte
	}{
		{"empty", nil},
		{"garbage", []byte{0x30, 0x02, 0x00, 0x00}},
		{"truncated", valid[:10]},
		{"trailing", append(valid, 0x00)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := ParsePublicKeyDER(tc.in)
			if err == nil {
				t.Fatalf("ParsePublicKeyDER(%s): want error, got nil", tc.name)
			}
			if !errors.Is(err, ErrInvalidPublicKeyDER) {
				t.Fatalf("error does not wrap ErrInvalidPublicKeyDER: %v", err)
			}
		})
	}
}

// TestParsePublicKeyDER_WrongPointPrefix verifies an EC point that is
// not uncompressed (0x04) is rejected.
func TestParsePublicKeyDER_WrongPointPrefix(t *testing.T) {
	t.Parallel()
	_, pub, err := secp256k1.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	// Tamper the uncompressed point prefix to 0x02 (compressed).
	uncompressed := pub.BytesUncompressed()
	bad := make([]byte, len(uncompressed))
	copy(bad, uncompressed)
	bad[0] = 0x02
	spki := spkiDER{
		Algorithm: algorithmIdentifierDER{
			Algorithm:  ecPublicKeyOID,
			Parameters: secp256k1OID,
		},
		SubjectPublicKey: asn1.BitString{Bytes: bad, BitLength: len(bad) * 8},
	}
	b, err := asn1.Marshal(spki)
	if err != nil {
		t.Fatalf("asn1.Marshal: %v", err)
	}
	_, err = ParsePublicKeyDER(b)
	if err == nil {
		t.Fatalf("ParsePublicKeyDER with 0x02 prefix: want error, got nil")
	}
}

// TestParsePublicKeyDER_A12OIDValidation exercises audit finding A12:
// ParsePublicKeyDER must strictly validate the SPKI AlgorithmIdentifier
// — the algorithm OID must be id-ecPublicKey ([RFC 5480] §2.1.1) and
// the curve OID must be secp256k1 ([SEC 2 v2] §2.4.1). Wrong algorithm
// OIDs, wrong or missing curve OIDs, non-OID parameters, and malformed
// SPKI are rejected with an error wrapping ErrInvalidPublicKeyDER and
// must never panic.
//
// Vectors: [RFC 5480] §2.1.1 id-ecPublicKey OID, [SEC 2 v2] §2.4.1
// secp256k1 OID 1.3.132.0.10, [RFC 3279] §2.3.5 rsaEncryption OID,
// [RFC 5480] §A.1 secp256r1 OID.
func TestParsePublicKeyDER_A12OIDValidation(t *testing.T) {
	t.Parallel()
	_, pub, err := secp256k1.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	uncompressed := pub.BytesUncompressed()
	valid := buildSPKI(t, pub)

	// Wrong-algorithm OIDs.
	rsaEncryptionOID := asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}  // [RFC 3279] §2.3.5
	ecdsaWithSHA256OID := asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2} // signature alg, not key alg
	// Wrong-curve OIDs.
	secp256r1OID := asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 7} // P-256, [RFC 5480] §A.1
	secp384r1OID := asn1.ObjectIdentifier{1, 3, 132, 0, 34}          // P-384, [SEC 2 v2] §2.5.1
	bogusOID := asn1.ObjectIdentifier{1, 2, 3, 4}

	cases := []struct {
		name    string
		in      []byte
		wantErr bool
	}{
		// Known-good vector: ecPublicKey + secp256k1 OID.
		{"A12_known_good", valid, false},
		// Wrong algorithm OID.
		{"A12_wrong_alg_rsa", buildSPKIRaw(t, rsaEncryptionOID, mustDER(t, secp256k1OID), uncompressed), true},
		{"A12_wrong_alg_ecdsa_sha256", buildSPKIRaw(t, ecdsaWithSHA256OID, mustDER(t, secp256k1OID), uncompressed), true},
		{"A12_wrong_alg_bogus", buildSPKIRaw(t, bogusOID, mustDER(t, secp256k1OID), uncompressed), true},
		// Wrong curve OID.
		{"A12_wrong_curve_p256", buildSPKIRaw(t, ecPublicKeyOID, mustDER(t, secp256r1OID), uncompressed), true},
		{"A12_wrong_curve_p384", buildSPKIRaw(t, ecPublicKeyOID, mustDER(t, secp384r1OID), uncompressed), true},
		{"A12_wrong_curve_bogus", buildSPKIRaw(t, ecPublicKeyOID, mustDER(t, bogusOID), uncompressed), true},
		// Missing or malformed parameters.
		{"A12_missing_curve_oid", buildSPKIRaw(t, ecPublicKeyOID, nil, uncompressed), true},
		{"A12_params_null", buildSPKIRaw(t, ecPublicKeyOID, []byte{0x05, 0x00}, uncompressed), true},
		{"A12_params_integer", buildSPKIRaw(t, ecPublicKeyOID, mustDER(t, 42), uncompressed), true},
		// Surplus element inside the AlgorithmIdentifier SEQUENCE —
		// the strict inner no-trailing-bytes check must reject it.
		{"A12_alg_trailing_element", buildSPKIRaw(t, ecPublicKeyOID,
			append(mustDER(t, secp256k1OID), mustDER(t, 42)...), uncompressed), true},
		// Malformed SPKI — must error, never panic.
		{"A12_malformed_garbage", []byte{0x30, 0x03, 0x02, 0x01, 0x01}, true},
		{"A12_malformed_truncated", valid[:10], true},
		{"A12_malformed_empty", nil, true},
		{"A12_malformed_trailing", append(valid, 0x00), true},
		{"A12_alg_not_sequence", func() []byte {
			// SPKI whose algorithm element is a bare OID, not a
			// SEQUENCE.
			bitStr := mustDER(t, asn1.BitString{Bytes: uncompressed, BitLength: len(uncompressed) * 8})
			body := append(mustDER(t, ecPublicKeyOID), bitStr...)
			return append([]byte{0x30, byte(len(body))}, body...)
		}(), true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := ParsePublicKeyDER(tc.in)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("ParsePublicKeyDER(%s): want error, got nil", tc.name)
				}
				if !errors.Is(err, ErrInvalidPublicKeyDER) {
					t.Fatalf("ParsePublicKeyDER(%s): error %v does not wrap ErrInvalidPublicKeyDER", tc.name, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParsePublicKeyDER(%s): unexpected error: %v", tc.name, err)
			}
			if !got.Equal(pub) {
				t.Fatalf("ParsePublicKeyDER(%s): got %s, want %s", tc.name, got.Redact(), pub.Redact())
			}
		})
	}
}

// TestParsePublicKeyDER_Deterministic verifies the same SPKI parses to
// the same key (determinism).
func TestParsePublicKeyDER_Deterministic(t *testing.T) {
	t.Parallel()
	_, pub, err := secp256k1.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	spki := buildSPKI(t, pub)

	a, err := ParsePublicKeyDER(spki)
	if err != nil {
		t.Fatalf("ParsePublicKeyDER (a): %v", err)
	}
	b, err := ParsePublicKeyDER(spki)
	if err != nil {
		t.Fatalf("ParsePublicKeyDER (b): %v", err)
	}
	if !a.Equal(b) {
		t.Fatalf("non-deterministic parse: %s vs %s", a.Redact(), b.Redact())
	}
}
