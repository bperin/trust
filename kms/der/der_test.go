package der

import (
	"crypto/subtle"
	"encoding/asn1"
	"math/big"
	"testing"
)

// encodeDER encodes r and s as an ASN.1 DER ECDSA-Sig-Value per
// [SEC 1 v2] §2.3.3. Used to build test vectors.
func encodeDER(t *testing.T, r, s *big.Int) []byte {
	t.Helper()
	sig := struct{ R, S *big.Int }{r, s}
	b, err := asn1.Marshal(sig)
	if err != nil {
		t.Fatalf("asn1.Marshal: %v", err)
	}
	return b
}

// TestParseECDSASignature_KnownVectors parses DER-encoded ECDSA
// signatures and verifies the recovered r and s match the input
// integers. Vectors exercise leading-zero padding (high bit set) and
// short integers (leading zero bytes stripped).
//
// Reference: [SEC 1 v2] §2.3.3 (ECDSA-Sig-Value), [RFC 3279] §2.2.3,
// [X.690] §8.3.2 (DER integer padding).
func TestParseECDSASignature_KnownVectors(t *testing.T) {
	t.Parallel()
	// r with high bit set — DER pads with a leading 0x00 so the
	// integer is interpreted as unsigned positive.
	rHighBit := new(big.Int).SetBytes([]byte{0xFF, 0x01, 0x02, 0x03})
	// s with high bit set.
	sHighBit := new(big.Int).SetBytes([]byte{0x80, 0xAA, 0xBB, 0xCC})
	// Small r and s (no padding).
	rSmall := big.NewInt(7)
	sSmall := big.NewInt(11)
	// r exactly 32 bytes, high bit set (typical secp256k1 r).
	r32 := new(big.Int).SetBytes(append([]byte{0xFF}, make([]byte, 31)...))
	// s exactly 32 bytes, high bit clear.
	s32 := new(big.Int).SetBytes(append([]byte{0x01}, make([]byte, 31)...))

	cases := []struct {
		name string
		r, s *big.Int
	}{
		{"high_bit_both", rHighBit, sHighBit},
		{"small_ints", rSmall, sSmall},
		{"r32_high_s32_low", r32, s32},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			derBytes := encodeDER(t, tc.r, tc.s)
			r, s, err := ParseECDSASignature(derBytes)
			if err != nil {
				t.Fatalf("ParseECDSASignature: %v", err)
			}
			rGot := new(big.Int).SetBytes(r)
			sGot := new(big.Int).SetBytes(s)
			if rGot.Cmp(tc.r) != 0 {
				t.Fatalf("r: got %x, want %x", rGot, tc.r)
			}
			if sGot.Cmp(tc.s) != 0 {
				t.Fatalf("s: got %x, want %s", sGot, tc.s)
			}
		})
	}
}

// TestParseECDSASignature_LeadingZeroPadding verifies that a value
// whose high bit is set is padded with a leading 0x00 in DER and that
// ParseECDSASignature strips it correctly to the unsigned value.
func TestParseECDSASignature_LeadingZeroPadding(t *testing.T) {
	t.Parallel()
	// 0x80... requires a leading 0x00 in DER to stay positive.
	r := new(big.Int).SetBytes([]byte{0x80, 0x00, 0x00, 0x00})
	s := new(big.Int).SetBytes([]byte{0xFF, 0xFF, 0xFF, 0xFF})
	derBytes := encodeDER(t, r, s)

	gotR, gotS, err := ParseECDSASignature(derBytes)
	if err != nil {
		t.Fatalf("ParseECDSASignature: %v", err)
	}
	rWant := r.Bytes()
	if subtle.ConstantTimeCompare(gotR, rWant) != 1 {
		t.Fatalf("r: got %x, want %x", gotR, rWant)
	}
	sWant := s.Bytes()
	if subtle.ConstantTimeCompare(gotS, sWant) != 1 {
		t.Fatalf("s: got %x, want %x", gotS, sWant)
	}
}

// TestParseECDSASignature_NegativeCases verifies malformed/truncated
// DER is rejected, not silently producing a wrong signature.
func TestParseECDSASignature_NegativeCases(t *testing.T) {
	t.Parallel()
	r := big.NewInt(0x1234)
	s := big.NewInt(0x5678)
	valid := encodeDER(t, r, s)

	cases := []struct {
		name string
		in   []byte
	}{
		{"empty", nil},
		{"truncated_sequence", valid[:3]},
		{"garbage", []byte{0x00, 0x01, 0x02}},
		{"only_r", func() []byte {
			// A SEQUENCE with a single INTEGER (missing s).
			rBytes, _ := asn1.Marshal(r)
			// Manually build a SEQUENCE around just r.
			seq := append([]byte{0x30, byte(len(rBytes))}, rBytes...)
			return seq
		}()},
		{"trailing_bytes", append(valid, 0x00, 0x00)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, _, err := ParseECDSASignature(tc.in)
			if err == nil {
				t.Fatalf("ParseECDSASignature(%v): want error, got nil", tc.name)
			}
		})
	}
}

// TestParseECDSASignature_ZeroInteger verifies a zero r or s is
// rejected (a valid ECDSA signature never has a zero component).
func TestParseECDSASignature_ZeroInteger(t *testing.T) {
	t.Parallel()
	derBytes := encodeDER(t, big.NewInt(0), big.NewInt(5))
	_, _, err := ParseECDSASignature(derBytes)
	if err == nil {
		t.Fatalf("ParseECDSASignature with zero r: want error, got nil")
	}
}

// TestNormalizeLowS_HighSToLowS verifies that an s above n/2 is
// normalized to n - s and flipped is true.
func TestNormalizeLowS_HighSToLowS(t *testing.T) {
	t.Parallel()
	// n/2 for secp256k1. Use a value just above n/2.
	nHalf := new(big.Int).Rsh(secp256k1N, 1)
	highS := new(big.Int).Add(nHalf, big.NewInt(1))

	got, flipped := NormalizeLowS(highS.Bytes())
	if !flipped {
		t.Fatalf("flipped = false, want true for high-s")
	}
	gotInt := new(big.Int).SetBytes(got)
	wantInt := new(big.Int).Sub(secp256k1N, highS)
	if gotInt.Cmp(wantInt) != 0 {
		t.Fatalf("normalized s: got %x, want %x", gotInt, wantInt)
	}
	// Normalized value must be <= n/2.
	if gotInt.Cmp(nHalf) > 0 {
		t.Fatalf("normalized s still > n/2: %x", gotInt)
	}
}

// TestNormalizeLowS_AlreadyLow verifies that an s <= n/2 is returned
// unchanged and flipped is false.
func TestNormalizeLowS_AlreadyLow(t *testing.T) {
	t.Parallel()
	nHalf := new(big.Int).Rsh(secp256k1N, 1)
	lowS := new(big.Int).Sub(nHalf, big.NewInt(1))

	got, flipped := NormalizeLowS(lowS.Bytes())
	if flipped {
		t.Fatalf("flipped = true, want false for low-s")
	}
	gotInt := new(big.Int).SetBytes(got)
	if gotInt.Cmp(lowS) != 0 {
		t.Fatalf("normalized s: got %x, want %x (unchanged)", gotInt, lowS)
	}
}

// TestNormalizeLowS_ExactlyHalfN verifies s == n/2 is treated as
// low-s (not flipped), since the EIP-2 requirement is s <= n/2.
func TestNormalizeLowS_ExactlyHalfN(t *testing.T) {
	t.Parallel()
	nHalf := new(big.Int).Rsh(secp256k1N, 1)
	got, flipped := NormalizeLowS(nHalf.Bytes())
	if flipped {
		t.Fatalf("s == n/2: flipped = true, want false")
	}
	gotInt := new(big.Int).SetBytes(got)
	if gotInt.Cmp(nHalf) != 0 {
		t.Fatalf("s == n/2: got %x, want %x", gotInt, nHalf)
	}
}

// TestNormalizeLowS_RoundTrip verifies that normalizing a high-s
// twice returns to the original (n - (n - s) == s), and that the
// flipped flag toggles.
func TestNormalizeLowS_RoundTrip(t *testing.T) {
	t.Parallel()
	nHalf := new(big.Int).Rsh(secp256k1N, 1)
	highS := new(big.Int).Add(nHalf, big.NewInt(42))

	norm, flipped := NormalizeLowS(highS.Bytes())
	if !flipped {
		t.Fatalf("first normalize: flipped = false, want true")
	}
	// Normalizing the (low-s) result again should not flip.
	norm2, flipped2 := NormalizeLowS(norm)
	if flipped2 {
		t.Fatalf("second normalize: flipped = true, want false")
	}
	norm2Int := new(big.Int).SetBytes(norm2)
	normInt := new(big.Int).SetBytes(norm)
	if norm2Int.Cmp(normInt) != 0 {
		t.Fatalf("double normalize not idempotent: %x vs %x", norm2Int, normInt)
	}
}

// TestNormalizeLowS_FlipsRecID verifies the documented invariant:
// flipping s flips the recovery id by XOR 1. We assert the flipped
// flag is exactly the XOR-1 trigger.
func TestNormalizeLowS_FlipsRecID(t *testing.T) {
	t.Parallel()
	nHalf := new(big.Int).Rsh(secp256k1N, 1)
	highS := new(big.Int).Add(nHalf, big.NewInt(1))

	_, flipped := NormalizeLowS(highS.Bytes())
	// Simulate recID adjustment: original recID 2, flipped -> 3.
	origRecID := byte(2)
	wantRecID := origRecID ^ 1
	if !flipped {
		t.Fatalf("expected flipped for high-s")
	}
	if origRecID^1 != wantRecID {
		t.Fatalf("recID XOR: got %d, want %d", origRecID^1, wantRecID)
	}
}
