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
