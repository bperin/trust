package secp256k1

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/asn1"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math/big"
	"os"
	"strings"
	"testing"
)

// Test vectors from the decred dcrd secp256k1 v4 library — RFC 6979
// deterministic ECDSA on secp256k1. These are the canonical secp256k1
// deterministic nonce test vectors (RFC 6979 itself only covers NIST
// curves; secp256k1 vectors come from the dcrd test suite).
// Source: github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa/signature_test.go

func TestRFC6979_secp256k1_Vector1(t *testing.T) {
	// dcrd test vector: key 0x1, blake256(0x01020304), rfc6979 nonce.
	// Our Sign() takes a pre-computed hash, so the hash algorithm is
	// irrelevant — we pass the 32-byte digest directly.
	// Vector: [RFC 6979] deterministic ECDSA, secp256k1 (dcrd test suite)
	keyHex := "0000000000000000000000000000000000000000000000000000000000000001"
	hashHex := "c301ba9de5d6053caad9f5eb46523f007702add2c62fa39de03146a36b8026b7"
	wantRHex := "c6c4137b0e5fbfc88ae3f293d7e80c8566c43ae20340075d44f75b009c943d09"
	wantSHex := "00ba213513572e35943d5acdd17215561b03f11663192a7252196cc8b2a99560"

	keyBytes, _ := hex.DecodeString(keyHex)
	hashBytes, _ := hex.DecodeString(hashHex)
	wantR, _ := hex.DecodeString(wantRHex)
	wantS, _ := hex.DecodeString(wantSHex)

	priv, err := NewPrivateKey(keyBytes)
	if err != nil {
		t.Fatalf("NewPrivateKey error: %v", err)
	}

	sig, err := priv.Sign(hashBytes)
	if err != nil {
		t.Fatalf("Sign error: %v", err)
	}

	if subtle.ConstantTimeCompare(sig[:32], wantR) != 1 {
		t.Errorf("r = %x, want %s", sig[:32], wantRHex)
	}
	if subtle.ConstantTimeCompare(sig[32:], wantS) != 1 {
		t.Errorf("s = %x, want %s", sig[32:], wantSHex)
	}

	// Verify the signature round-trips.
	pub := priv.Public()
	if !pub.Verify(sig, hashBytes) {
		t.Error("Verify returned false for known-good signature")
	}
}

func TestRFC6979_secp256k1_Vector2(t *testing.T) {
	// dcrd test vector: key 0x2, blake256(0x01020304), rfc6979 nonce.
	keyHex := "0000000000000000000000000000000000000000000000000000000000000002"
	hashHex := "c301ba9de5d6053caad9f5eb46523f007702add2c62fa39de03146a36b8026b7"
	wantRHex := "e6f137b52377250760cc702e19b7aee3c63b0e7d95a91939b14ab3b5c4771e59"
	wantSHex := "44b9bc4620afa158b7efdfea5234ff2d5f2f78b42886f02cf581827ee55318ea"

	keyBytes, _ := hex.DecodeString(keyHex)
	hashBytes, _ := hex.DecodeString(hashHex)
	wantR, _ := hex.DecodeString(wantRHex)
	wantS, _ := hex.DecodeString(wantSHex)

	priv, err := NewPrivateKey(keyBytes)
	if err != nil {
		t.Fatalf("NewPrivateKey error: %v", err)
	}

	sig, err := priv.Sign(hashBytes)
	if err != nil {
		t.Fatalf("Sign error: %v", err)
	}

	if subtle.ConstantTimeCompare(sig[:32], wantR) != 1 {
		t.Errorf("r = %x, want %s", sig[:32], wantRHex)
	}
	if subtle.ConstantTimeCompare(sig[32:], wantS) != 1 {
		t.Errorf("s = %x, want %s", sig[32:], wantSHex)
	}

	pub := priv.Public()
	if !pub.Verify(sig, hashBytes) {
		t.Error("Verify returned false for known-good signature")
	}
}

func TestSign_Deterministic(t *testing.T) {
	// RFC 6979 deterministic nonces — same key + same hash = same signature.
	keyHex := "0000000000000000000000000000000000000000000000000000000000000001"
	hashHex := "c301ba9de5d6053caad9f5eb46523f007702add2c62fa39de03146a36b8026b7"

	keyBytes, _ := hex.DecodeString(keyHex)
	hashBytes, _ := hex.DecodeString(hashHex)

	priv, err := NewPrivateKey(keyBytes)
	if err != nil {
		t.Fatalf("NewPrivateKey error: %v", err)
	}

	sig1, err := priv.Sign(hashBytes)
	if err != nil {
		t.Fatalf("Sign[1] error: %v", err)
	}
	sig2, err := priv.Sign(hashBytes)
	if err != nil {
		t.Fatalf("Sign[2] error: %v", err)
	}

	if subtle.ConstantTimeCompare(sig1, sig2) != 1 {
		t.Fatal("deterministic signing failed: same key + hash produced different signatures")
	}
}

func TestGenerateKey_RoundTrip(t *testing.T) {
	priv, pub, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey error: %v", err)
	}

	msg := []byte("round-trip test")
	hash := sha256.Sum256(msg)

	sig, err := priv.Sign(hash[:])
	if err != nil {
		t.Fatalf("Sign error: %v", err)
	}

	if !pub.Verify(sig, hash[:]) {
		t.Fatal("round-trip failed: Verify returned false for freshly signed hash")
	}

	// Public() must match the key from GenerateKey.
	derivedPub := priv.Public()
	if !pub.Equal(derivedPub) {
		t.Fatal("Public() does not match the public key from GenerateKey")
	}
}

func TestSign_LowS(t *testing.T) {
	// Every signature produced must have s <= n/2 (EIP-2 low-s).
	// dcrd's ecdsa.Sign handles this automatically (BIP0062).
	priv, _, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey error: %v", err)
	}

	for i := 0; i < 100; i++ {
		msg := []byte("low-s test " + string(rune(i)))
		hash := sha256.Sum256(msg)

		sig, err := priv.Sign(hash[:])
		if err != nil {
			t.Fatalf("Sign[%d] error: %v", i, err)
		}

		// Verify must accept our own signatures (they're low-s).
		pub := priv.Public()
		if !pub.Verify(sig, hash[:]) {
			t.Fatalf("Verify[%d] rejected our own low-s signature", i)
		}
	}
}

func TestVerify_HighS_Rejected(t *testing.T) {
	// EIP-2: high-s signatures (s > n/2) must be rejected on verify.
	// Construct a high-s signature by negating s.
	priv, pub, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey error: %v", err)
	}

	msg := []byte("high-s rejection test")
	hash := sha256.Sum256(msg)

	sig, err := priv.Sign(hash[:])
	if err != nil {
		t.Fatalf("Sign error: %v", err)
	}

	// Negate s: high_s = n - low_s. We don't know n directly, but we
	// can construct a high-s by using the dcrd library to negate.
	// Instead, flip the high bit of s to create a different (likely
	// high-s) value. A simpler approach: use the secp256k1 curve order
	// to compute n - s.
	// The secp256k1 order n is:
	//   fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141
	// n/2 is:
	//   7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0
	// We construct high-s = n - s using byte manipulation.
	highSig := make([]byte, 64)
	copy(highSig, sig)
	// Negate s modulo n: high_s = n - low_s
	// n = fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141
	n := []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe, 0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41}
	sLow := highSig[32:]
	sHigh := make([]byte, 32)
	// sHigh = n - sLow (modular subtraction)
	borrow := 0
	for i := 31; i >= 0; i-- {
		diff := int(n[i]) - int(sLow[i]) - borrow
		if diff < 0 {
			diff += 256
			borrow = 1
		} else {
			borrow = 0
		}
		sHigh[i] = byte(diff)
	}
	copy(highSig[32:], sHigh)

	if pub.Verify(highSig, hash[:]) {
		t.Fatal("Verify returned true for high-s signature, want false (EIP-2 rejection)")
	}
}

func TestVerify_RejectsModifiedSignature(t *testing.T) {
	priv, pub, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey error: %v", err)
	}

	msg := []byte("tampered signature test")
	hash := sha256.Sum256(msg)

	sig, err := priv.Sign(hash[:])
	if err != nil {
		t.Fatalf("Sign error: %v", err)
	}

	// Flip a bit in r.
	tampered := make([]byte, len(sig))
	copy(tampered, sig)
	tampered[0] ^= 0x01

	if pub.Verify(tampered, hash[:]) {
		t.Fatal("Verify returned true for modified signature, want false")
	}
}

func TestVerify_RejectsModifiedHash(t *testing.T) {
	priv, pub, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey error: %v", err)
	}

	msg := []byte("original message")
	hash := sha256.Sum256(msg)

	sig, err := priv.Sign(hash[:])
	if err != nil {
		t.Fatalf("Sign error: %v", err)
	}

	modified := sha256.Sum256([]byte("modified message"))
	if pub.Verify(sig, modified[:]) {
		t.Fatal("Verify returned true for modified hash, want false")
	}
}

func TestVerify_RejectsWrongPublicKey(t *testing.T) {
	priv, _, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey error: %v", err)
	}

	msg := []byte("tampered pubkey test")
	hash := sha256.Sum256(msg)

	sig, err := priv.Sign(hash[:])
	if err != nil {
		t.Fatalf("Sign error: %v", err)
	}

	// Tamper the public key.
	tamperedPubBytes := priv.Public().Bytes()
	tamperedPubBytes[0] ^= 0x01
	tamperedPub, err := NewPublicKey(tamperedPubBytes)
	if err != nil {
		// If the tampered key is unparseable, that's also a valid rejection.
		// Force a parseable tampered key by flipping a later byte.
		tamperedPubBytes = priv.Public().Bytes()
		tamperedPubBytes[10] ^= 0x01
		tamperedPub, err = NewPublicKey(tamperedPubBytes)
		if err != nil {
			t.Fatalf("could not construct tampered public key: %v", err)
		}
	}

	if tamperedPub.Verify(sig, hash[:]) {
		t.Fatal("Verify returned true with tampered public key, want false")
	}
}

func TestVerify_RejectsShortSignature(t *testing.T) {
	_, pub, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey error: %v", err)
	}

	hash := sha256.Sum256([]byte("short sig test"))
	shortSig := make([]byte, 63)

	if pub.Verify(shortSig, hash[:]) {
		t.Fatal("Verify returned true for 63-byte signature, want false")
	}
}

func TestVerify_RejectsShortHash(t *testing.T) {
	_, pub, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey error: %v", err)
	}

	sig := make([]byte, 64)
	shortHash := make([]byte, 31)

	if pub.Verify(sig, shortHash) {
		t.Fatal("Verify returned true for 31-byte hash, want false")
	}
}

func TestSign_RejectsShortHash(t *testing.T) {
	priv, _, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey error: %v", err)
	}

	shortHash := make([]byte, 31)
	_, err = priv.Sign(shortHash)
	if err == nil {
		t.Fatal("Sign(31-byte hash) expected error, got nil")
	}
	if !errors.Is(err, ErrInvalidSignature) {
		t.Errorf("error = %v, want ErrInvalidSignature", err)
	}
}

func TestNewPrivateKey_InvalidLength(t *testing.T) {
	tests := []struct {
		name string
		key  []byte
	}{
		{"nil", nil},
		{"empty", []byte{}},
		{"too short", make([]byte, 31)},
		{"too long", make([]byte, 33)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewPrivateKey(tt.key)
			if err == nil {
				t.Error("expected error, got nil")
			}
			if !errors.Is(err, ErrInvalidKey) {
				t.Errorf("error = %v, want ErrInvalidKey", err)
			}
		})
	}
}

func TestNewPublicKey_InvalidLength(t *testing.T) {
	tests := []struct {
		name string
		key  []byte
	}{
		{"nil", nil},
		{"empty", []byte{}},
		{"too short", make([]byte, 32)},
		{"too long", make([]byte, 34)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewPublicKey(tt.key)
			if err == nil {
				t.Error("expected error, got nil")
			}
			if !errors.Is(err, ErrInvalidKey) {
				t.Errorf("error = %v, want ErrInvalidKey", err)
			}
		})
	}
}

func TestNewPublicKey_RejectsUncompressed(t *testing.T) {
	// 65-byte uncompressed public keys must be rejected — only 33-byte
	// compressed keys are accepted.
	uncompressed := make([]byte, 65)
	_, err := NewPublicKey(uncompressed)
	if err == nil {
		t.Fatal("NewPublicKey(65-byte) expected error, got nil")
	}
	if !errors.Is(err, ErrInvalidKey) {
		t.Errorf("error = %v, want ErrInvalidKey", err)
	}
}

func TestPrivateKey_Redact(t *testing.T) {
	priv, _, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey error: %v", err)
	}

	redacted := priv.Redact()

	// Must not contain the full key.
	fullHex := hex.EncodeToString(priv.key.Serialize())
	if strings.Contains(redacted, fullHex) {
		t.Fatal("Redact() exposes full key material")
	}

	// Must not contain any 2+ consecutive raw key bytes.
	rawKey := priv.key.Serialize()
	for i := 0; i+1 < len(rawKey); i++ {
		pairHex := hex.EncodeToString(rawKey[i : i+2])
		if strings.Contains(redacted, pairHex) {
			t.Fatalf("Redact() exposes raw key bytes at offset %d: %q in %q", i, pairHex, redacted)
		}
	}

	// Must end with "...".
	if !strings.HasSuffix(redacted, "...") {
		t.Errorf("Redact() = %q, want suffix '...'", redacted)
	}

	// Must be short (8 hex chars + 3 dots = 11 chars).
	if len(redacted) > 11 {
		t.Errorf("Redact() = %q, length %d, want <= 11", redacted, len(redacted))
	}

	// Must be deterministic.
	if priv.Redact() != redacted {
		t.Error("Redact() is not deterministic")
	}
}

func TestPublicKey_Redact(t *testing.T) {
	_, pub, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey error: %v", err)
	}

	redacted := pub.Redact()
	if !strings.HasSuffix(redacted, "...") {
		t.Errorf("Redact() = %q, want suffix '...'", redacted)
	}
}

func TestPublicKey_Equal(t *testing.T) {
	_, pub1, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey error: %v", err)
	}
	_, pub2, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey error: %v", err)
	}

	if !pub1.Equal(pub1) {
		t.Error("public key not equal to itself")
	}
	if pub1.Equal(pub2) {
		t.Error("different public keys reported equal")
	}
}

func TestPublicKey_Equal_Nil(t *testing.T) {
	_, pub, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey error: %v", err)
	}

	if pub.Equal(nil) {
		t.Fatal("Equal(nil) returned true, want false")
	}
}

// TestVerify_Malleability tests the ECDSA signature malleability
// defense. High-s signatures are rejected per [EIP-2]. Truncated and
// extended signatures are rejected by length check.
func TestVerify_RejectsTrailingByteAppended(t *testing.T) {
	// 65-byte signature (valid sig + trailing 0x00) — must fail.
	priv, pub, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey error: %v", err)
	}

	hash := sha256.Sum256([]byte("trailing byte test"))
	sig, err := priv.Sign(hash[:])
	if err != nil {
		t.Fatalf("Sign error: %v", err)
	}

	appended := append(append([]byte{}, sig...), 0x00)
	if pub.Verify(appended, hash[:]) {
		t.Fatal("Verify returned true for signature with trailing byte, want false")
	}
}

func TestVerify_RejectsTruncatedSignature(t *testing.T) {
	// 63-byte and 62-byte signatures — must fail.
	priv, pub, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey error: %v", err)
	}

	hash := sha256.Sum256([]byte("truncated sig test"))
	sig, err := priv.Sign(hash[:])
	if err != nil {
		t.Fatalf("Sign error: %v", err)
	}

	if pub.Verify(sig[:len(sig)-1], hash[:]) {
		t.Fatal("Verify returned true for 63-byte signature, want false")
	}
	if pub.Verify(sig[:len(sig)-2], hash[:]) {
		t.Fatal("Verify returned true for 62-byte signature, want false")
	}
}

func TestVerify_RejectsEmptySignature(t *testing.T) {
	// Zero-length signature — must fail.
	_, pub, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey error: %v", err)
	}

	hash := sha256.Sum256([]byte("empty sig test"))
	if pub.Verify([]byte{}, hash[:]) {
		t.Fatal("Verify returned true for empty signature, want false")
	}
}

func TestVerify_RejectsAllZeroSignature(t *testing.T) {
	// 64-byte all-zero signature — must fail.
	_, pub, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey error: %v", err)
	}

	hash := sha256.Sum256([]byte("zero sig test"))
	if pub.Verify(make([]byte, 64), hash[:]) {
		t.Fatal("Verify returned true for all-zero signature, want false")
	}
}

// TestVerify_ValidSignatures verifies that legitimate signatures
// produced by different key pairs all verify correctly.
func TestVerify_ValidSignatures(t *testing.T) {
	msg := []byte("cross-implementation valid signature")
	hash := sha256.Sum256(msg)

	for i := 0; i < 10; i++ {
		priv, pub, err := GenerateKey()
		if err != nil {
			t.Fatalf("GenerateKey[%d] error: %v", i, err)
		}

		sig, err := priv.Sign(hash[:])
		if err != nil {
			t.Fatalf("Sign[%d] error: %v", i, err)
		}

		if !pub.Verify(sig, hash[:]) {
			t.Fatalf("Verify[%d] returned false for valid signature", i)
		}
	}
}

// --- Wycheproof test vector loading ---
// See README.md for format conversion and EIP-2 handling.

const wycheproofSecp256k1File = "testdata/ecdsa_secp256k1_sha256_test.json"

type wpSecp256k1Suite struct {
	Algorithm     string             `json:"algorithm"`
	NumberOfTests int                `json:"numberOfTests"`
	TestGroups    []wpSecp256k1Group `json:"testGroups"`
}

type wpSecp256k1Group struct {
	PublicKey wpSecp256k1PublicKey `json:"publicKey"`
	Tests     []wpSecp256k1Test    `json:"tests"`
}

type wpSecp256k1PublicKey struct {
	Uncompressed string `json:"uncompressed"`
}

type wpSecp256k1Test struct {
	TcID    int      `json:"tcId"`
	Comment string   `json:"comment"`
	Flags   []string `json:"flags"`
	Msg     string   `json:"msg"`
	Sig     string   `json:"sig"`
	Result  string   `json:"result"`
}

// derSig is the ASN.1 structure of a DER-encoded ECDSA signature.
type derSig struct {
	R *big.Int
	S *big.Int
}

// derToRS parses a DER-encoded ECDSA signature and returns the 64-byte
// r||s representation. Returns nil if the signature is not valid DER,
// has trailing elements, has negative r/s, or if r/s exceed the
// secp256k1 order n. Strict validation catches Wycheproof
// ModifiedSignature, ModifiedInteger, and ArithmeticError cases.
func derToRS(der []byte) []byte {
	var ds derSig
	rest, err := asn1.Unmarshal(der, &ds)
	if err != nil {
		return nil
	}
	if len(rest) > 0 {
		return nil
	}
	if ds.R == nil || ds.S == nil {
		return nil
	}
	// Negative integers are invalid (ModifiedInteger cases).
	if ds.R.Sign() < 0 || ds.S.Sign() < 0 {
		return nil
	}

	rBytes := ds.R.Bytes()
	sBytes := ds.S.Bytes()
	if len(rBytes) > 32 || len(sBytes) > 32 {
		return nil
	}

	// Re-serialize and compare to catch non-canonical DER (extra
	// elements in the sequence, non-minimal encoding). Go's
	// asn1.Unmarshal silently ignores extra SEQUENCE elements, so
	// this round-trip check is the only way to detect them.
	reencoded, err := asn1.Marshal(derSig{R: ds.R, S: ds.S})
	if err != nil {
		return nil
	}
	if subtle.ConstantTimeCompare(reencoded, der) != 1 {
		return nil
	}

	// Reject r/s >= n (ArithmeticError cases). The secp256k1 order:
	// fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141
	n, _ := new(big.Int).SetString("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141", 16)
	if ds.R.Cmp(n) >= 0 || ds.S.Cmp(n) >= 0 {
		return nil
	}

	out := make([]byte, 64)
	copy(out[32-len(rBytes):32], rBytes)
	copy(out[64-len(sBytes):64], sBytes)
	return out
}

// uncompressedToCompressed converts a 65-byte uncompressed secp256k1
// public key (04 || x || y) to a 33-byte compressed key. The
// compression prefix is 0x02 if y is even, 0x03 if odd.
func uncompressedToCompressed(uncompressed []byte) []byte {
	if len(uncompressed) != 65 || uncompressed[0] != 0x04 {
		return nil
	}
	prefix := byte(0x02)
	if uncompressed[64]&1 == 1 {
		prefix = 0x03
	}
	out := make([]byte, 33)
	out[0] = prefix
	copy(out[1:], uncompressed[1:33])
	return out
}

// TestWycheproof loads Project Wycheproof secp256k1 ECDSA SHA-256
// vectors and runs every case against our Verify wrapper. See
// README.md for format conversion and EIP-2 handling details.
//
// Vector: [Wycheproof] ecdsa_secp256k1_sha256_test.json
func TestWycheproof(t *testing.T) {
	data, err := os.ReadFile(wycheproofSecp256k1File)
	if err != nil {
		t.Fatalf("Wycheproof test data not found: %v", err)
	}

	var suite wpSecp256k1Suite
	if err := json.Unmarshal(data, &suite); err != nil {
		t.Fatalf("unmarshal wycheproof: %v", err)
	}

	// secp256k1 curve order n.
	n, ok := new(big.Int).SetString("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141", 16)
	if !ok {
		t.Fatal("failed to parse curve order")
	}
	halfN := new(big.Int).Rsh(n, 1)

	total := 0
	for _, group := range suite.TestGroups {
		uncompressedBytes, err := hex.DecodeString(group.PublicKey.Uncompressed)
		if err != nil {
			continue
		}
		compressed := uncompressedToCompressed(uncompressedBytes)
		if compressed == nil {
			continue
		}
		pub, err := NewPublicKey(compressed)
		if err != nil {
			continue
		}

		for _, tc := range group.Tests {
			total++
			tc := tc
			t.Run(wpFmtTCID(tc.TcID, tc.Comment), func(t *testing.T) {
				msg, _ := hex.DecodeString(tc.Msg)
				hash := sha256.Sum256(msg)

				derSig, _ := hex.DecodeString(tc.Sig)
				rsSig := derToRS(derSig)

				if rsSig == nil {
					// DER parsing failed — our wrapper would reject
					// this. Only valid cases are a problem here.
					if tc.Result == "valid" || tc.Result == "acceptable" {
						t.Errorf("tcId %d (%s): DER parse failed for %s case [flags: %v]", tc.TcID, tc.Comment, tc.Result, tc.Flags)
					}
					return
				}

				got := pub.Verify(rsSig, hash[:])

				// Check if the signature has high-s. Wycheproof doesn't
				// enforce EIP-2, but our wrapper does. Valid cases with
				// high-s are expected to fail our Verify.
				sInt := new(big.Int).SetBytes(rsSig[32:])
				isHighS := sInt.Cmp(halfN) > 0

				switch tc.Result {
				case "valid", "acceptable":
					if isHighS && tc.Result == "valid" {
						// Valid per Wycheproof but high-s — our EIP-2
						// rejection is correct and stricter.
						if got {
							t.Errorf("tcId %d (%s): high-s valid case passed Verify, but EIP-2 should reject [flags: %v]", tc.TcID, tc.Comment, tc.Flags)
						}
						return
					}
					if !got {
						t.Errorf("tcId %d (%s): Verify = false, want true [flags: %v]", tc.TcID, tc.Comment, tc.Flags)
					}
				case "invalid":
					if got {
						t.Errorf("tcId %d (%s): Verify = true, want false [flags: %v]", tc.TcID, tc.Comment, tc.Flags)
					}
				}
			})
		}
	}

	if total == 0 {
		t.Fatal("no Wycheproof test cases were run")
	}
	t.Logf("ran %d Wycheproof test cases", total)
}

func wpFmtTCID(id int, comment string) string {
	if comment == "" {
		return "tcId-" + wpItoa(id)
	}
	c := strings.NewReplacer(" ", "_", "/", "_", "(", "", ")", "").Replace(comment)
	return "tcId-" + wpItoa(id) + "-" + c
}

func wpItoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}
