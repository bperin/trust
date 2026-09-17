package der

import (
	"crypto/subtle"
	"encoding/asn1"
	"errors"
	"math/big"
	"os"
	"testing"

	"github.com/bperin/trust/crypto/secp256k1"
	"github.com/bperin/trust/signature"
)

// readProviderDER loads a committed provider signature vector, failing
// rather than skipping.
func readProviderDER(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile("../testdata/" + name)
	if err != nil {
		t.Fatalf("read testdata/%s: %v (committed vector missing)", name, err)
	}
	return data
}

// decodeScalars decodes an ECDSA-Sig-Value with the stdlib decoder so a test
// can assert against an independently decoded r and s.
func decodeScalars(t *testing.T, derBytes []byte) (*big.Int, *big.Int) {
	t.Helper()
	var v struct{ R, S *big.Int }
	rest, err := asn1.Unmarshal(derBytes, &v)
	if err != nil {
		t.Fatalf("asn1.Unmarshal: %v", err)
	}
	if len(rest) != 0 {
		t.Fatalf("trailing bytes after ECDSA-Sig-Value: %d", len(rest))
	}
	return v.R, v.S
}

// TestParseECDSASignature_CurveWidths pins the scalar width each provider
// signature carries and the range the parser enforces. The parser validates
// against the secp256k1 group order because the r||s form it produces is the
// ES256K wire format; a P-384 signature is 48-byte wide and must not be
// converted there — ES384 keeps DER.
//
// Vector: [SEC 1 v2] §2.3.3, [SEC 2 v2] §2.4.1 (secp256k1 order).
func TestParseECDSASignature_CurveWidths(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		file    string
		width   int
		wantErr bool
	}{
		{name: "secp256k1_32byte_scalars", file: "kms_es256k_signature", width: 32},
		{name: "p256_32byte_scalars", file: "kms_p256_signature", width: 32},
		{name: "p384_48byte_scalars_out_of_range", file: "kms_p384_signature", width: 48, wantErr: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			derBytes := readProviderDER(t, tc.file)
			wantR, wantS := decodeScalars(t, derBytes)

			if got := (wantR.BitLen() + 7) / 8; got > tc.width {
				t.Fatalf("vector r width = %d bytes, test expects at most %d", got, tc.width)
			}
			if got := (wantS.BitLen() + 7) / 8; got > tc.width {
				t.Fatalf("vector s width = %d bytes, test expects at most %d", got, tc.width)
			}

			r, s, err := ParseECDSASignature(derBytes)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("ParseECDSASignature(testdata/%s): got r=%x s=%x, want an error: a %d-byte scalar exceeds the secp256k1 order",
						tc.file, wantR, wantS, tc.width)
				}
				if !errors.Is(err, ErrInvalidDER) {
					t.Fatalf("ParseECDSASignature(testdata/%s): err = %v, want errors.Is(err, ErrInvalidDER)", tc.file, err)
				}
				if wantR.Cmp(secp256k1N) < 0 && wantS.Cmp(secp256k1N) < 0 {
					t.Fatalf("rejecting testdata/%s is not explained by the secp256k1 range check: r<n=%v s<n=%v",
						tc.file, wantR.Cmp(secp256k1N) < 0, wantS.Cmp(secp256k1N) < 0)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseECDSASignature(testdata/%s): %v", tc.file, err)
			}
			if new(big.Int).SetBytes(r).Cmp(wantR) != 0 {
				t.Errorf("r = %x, want %x", r, wantR)
			}
			if new(big.Int).SetBytes(s).Cmp(wantS) != 0 {
				t.Errorf("s = %x, want %x", s, wantS)
			}

			rs := padPair(r, s)
			if len(rs) != 2*tc.width {
				t.Errorf("r||s length = %d, want %d", len(rs), 2*tc.width)
			}
			if subtle.ConstantTimeCompare(rs[tc.width:], leftPad(s, tc.width)) != 1 {
				t.Errorf("r||s s-half = %x, want %x", rs[tc.width:], leftPad(s, tc.width))
			}
		})
	}
}

// padPair returns the fixed-width r||s encoding for secp256k1.
func padPair(r, s []byte) []byte {
	out := make([]byte, 64)
	copy(out[32-len(r):32], r)
	copy(out[64-len(s):], s)
	return out
}

// leftPad widens a big-endian scalar to width bytes.
func leftPad(b []byte, width int) []byte {
	if len(b) >= width {
		return b
	}
	out := make([]byte, width)
	copy(out[width-len(b):], b)
	return out
}

// TestParseECDSASignature_CanonicalDER checks that every non-canonical or
// malformed encoding of ECDSA-Sig-Value is rejected with ErrInvalidDER,
// including the surplus SEQUENCE element that Go's ASN.1 decoder otherwise
// ignores.
//
// Vector: [X.690] §10.1 (DER completeness and minimal encoding), [RFC 3279] §2.2.3.
func TestParseECDSASignature_CanonicalDER(t *testing.T) {
	t.Parallel()

	r := big.NewInt(7)
	s := big.NewInt(9)
	canonical := encodeDER(t, r, s)
	rBytes, err := asn1.Marshal(r)
	if err != nil {
		t.Fatalf("marshal r: %v", err)
	}
	sBytes, err := asn1.Marshal(s)
	if err != nil {
		t.Fatalf("marshal s: %v", err)
	}
	nMinus1 := new(big.Int).Sub(secp256k1N, big.NewInt(1))

	tests := []struct {
		name string
		in   []byte
	}{
		{"empty_input", nil},
		{"garbage", []byte{0x00, 0x01, 0x02}},
		{"truncated_sequence", canonical[:len(canonical)-3]},
		{"trailing_bytes_after_value", append(append([]byte{}, canonical...), 0x00)},
		{"non_minimal_sequence_length", append([]byte{0x30, 0x81, byte(len(canonical) - 2)}, canonical[2:]...)},
		{"non_minimal_integer", []byte{0x30, 0x0c, 0x02, 0x04, 0x00, 0x00, 0x12, 0x34, 0x02, 0x02, 0x56, 0x78}},
		{"surplus_sequence_element", marshalSeq(t, append(append([]byte{}, rBytes...), sBytes...), 0x02, 0x01, 0x0b)},
		{"missing_s_element", marshalSeq(t, rBytes)},
		{"indefinite_length_sequence", []byte{0x30, 0x80, 0x02, 0x01, 0x07, 0x02, 0x01, 0x09, 0x00, 0x00}},
		{"negative_r", []byte{0x30, 0x06, 0x02, 0x01, 0xFF, 0x02, 0x01, 0x09}},
		{"negative_s", []byte{0x30, 0x06, 0x02, 0x01, 0x07, 0x02, 0x01, 0xFF}},
		{"zero_r", []byte{0x30, 0x06, 0x02, 0x01, 0x00, 0x02, 0x01, 0x09}},
		{"zero_s", []byte{0x30, 0x06, 0x02, 0x01, 0x07, 0x02, 0x01, 0x00}},
		{"oversized_r_33_bytes", encodeDER(t, new(big.Int).Lsh(big.NewInt(1), 256), s)},
		{"oversized_s_33_bytes", encodeDER(t, r, new(big.Int).Lsh(big.NewInt(1), 256))},
		{"r_equals_order", encodeDER(t, secp256k1N, s)},
		{"s_equals_order", encodeDER(t, r, secp256k1N)},
		{"s_above_order", encodeDER(t, nMinus1, new(big.Int).Add(secp256k1N, big.NewInt(1)))},
		{"integer_with_empty_content", []byte{0x30, 0x05, 0x02, 0x00, 0x02, 0x01, 0x09}},
		{"sequence_tag_is_integer", []byte{0x02, 0x06, 0x02, 0x01, 0x07, 0x02, 0x01, 0x09}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			gotR, gotS, err := ParseECDSASignature(tc.in)
			if err == nil {
				t.Fatalf("ParseECDSASignature(%x): got r=%x s=%x, want an error wrapping ErrInvalidDER", tc.in, gotR, gotS)
			}
			if gotR != nil || gotS != nil {
				t.Errorf("ParseECDSASignature(%s): got r=%x s=%x alongside error, want nil scalars", tc.name, gotR, gotS)
			}
			if !errors.Is(err, ErrInvalidDER) {
				t.Errorf("ParseECDSASignature(%s): err = %v, want errors.Is(err, ErrInvalidDER)", tc.name, err)
			}
		})
	}
}

// marshalSeq builds a DER SEQUENCE over the first content element followed by
// any literal trailing bytes.
func marshalSeq(t *testing.T, first []byte, more ...byte) []byte {
	t.Helper()
	b, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSequence,
		IsCompound: true,
		Bytes:      append(append([]byte{}, first...), more...),
	})
	if err != nil {
		t.Fatalf("marshal SEQUENCE: %v", err)
	}
	return b
}

// TestNormalizeLowS_Secp256k1Path walks the KMS adapter path end to end: a
// DER signature that is high-s is accepted by the parser, normalized to low-s
// per [EIP-2], and only the low-s form verifies through the dispatch layer.
func TestNormalizeLowS_Secp256k1Path(t *testing.T) {
	t.Parallel()

	msg := []byte("kms der normalization path")
	priv, pub, err := secp256k1.GenerateKey()
	if err != nil {
		t.Fatalf("secp256k1.GenerateKey: %v", err)
	}
	raw, err := signature.Sign(signature.AlgorithmES256K, priv, msg)
	if err != nil {
		t.Fatalf("signature.Sign(ES256K): %v", err)
	}
	if len(raw) != 64 {
		t.Fatalf("signature length = %d, want 64", len(raw))
	}

	lowS := new(big.Int).SetBytes(raw[32:])
	highS := new(big.Int).Sub(secp256k1N, lowS)

	valid := func(sig []byte) bool {
		t.Helper()
		ok, err := signature.Verify(signature.AlgorithmES256K, pub, sig, msg)
		if err != nil {
			t.Fatalf("signature.Verify(ES256K): %v", err)
		}
		return ok
	}

	malleated := padPair(raw[:32], highS.Bytes())
	if valid(malleated) {
		t.Errorf("high-s signature verified through signature.Verify, want rejected per [EIP-2]")
	}

	derBytes := encodeDER(t, new(big.Int).SetBytes(raw[:32]), highS)
	r, s, err := ParseECDSASignature(derBytes)
	if err != nil {
		t.Fatalf("ParseECDSASignature(high-s DER): %v", err)
	}
	if new(big.Int).SetBytes(s).Cmp(secp256k1HalfN) <= 0 {
		t.Fatalf("ParseECDSASignature returned s=%x, want the untouched high-s value", s)
	}
	normalized, flipped := NormalizeLowS(s)
	if !flipped {
		t.Fatalf("NormalizeLowS(high-s) flipped = false, want true")
	}
	if subtle.ConstantTimeCompare(leftPad(normalized, 32), raw[32:]) != 1 {
		t.Errorf("normalized s = %x, want the original low-s %x", normalized, raw[32:])
	}
	if restored := padPair(r, normalized); !valid(restored) {
		t.Errorf("normalized r||s = %x did not verify, want true", restored)
	}

	lowNormalized, lowFlipped := NormalizeLowS(raw[32:])
	if lowFlipped {
		t.Errorf("NormalizeLowS(low-s) flipped = true, want false")
	}
	if subtle.ConstantTimeCompare(lowNormalized, raw[32:]) != 1 {
		t.Errorf("NormalizeLowS changed an already low-s value: got %x, want %x", lowNormalized, raw[32:])
	}
}

// TestNormalizeLowS_BoundaryScalars checks the n/2 boundary and the smallest
// and largest in-range scalars.
func TestNormalizeLowS_BoundaryScalars(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		s           *big.Int
		wantFlipped bool
	}{
		{"one_is_low", big.NewInt(1), false},
		{"exactly_half_n_is_low", new(big.Int).Set(secp256k1HalfN), false},
		{"half_n_plus_one_is_high", new(big.Int).Add(secp256k1HalfN, big.NewInt(1)), true},
		{"n_minus_one_is_high", new(big.Int).Sub(secp256k1N, big.NewInt(1)), true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, flipped := NormalizeLowS(tc.s.Bytes())
			if flipped != tc.wantFlipped {
				t.Fatalf("NormalizeLowS(s=%x): flipped = %v, want %v", tc.s, flipped, tc.wantFlipped)
			}
			gotInt := new(big.Int).SetBytes(got)
			if gotInt.Cmp(secp256k1HalfN) > 0 {
				t.Errorf("result s = %x is above n/2, want low-s", gotInt)
			}
			if tc.wantFlipped && gotInt.Cmp(new(big.Int).Sub(secp256k1N, tc.s)) != 0 {
				t.Errorf("result s = %x, want n-s = %x", gotInt, new(big.Int).Sub(secp256k1N, tc.s))
			}
			if !tc.wantFlipped && subtle.ConstantTimeCompare(got, tc.s.Bytes()) != 1 {
				t.Errorf("low-s input changed: got %x, want %x", got, tc.s)
			}
		})
	}
}
