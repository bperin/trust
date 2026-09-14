package ed25519

import (
	stded25519 "crypto/ed25519"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
)

// Test vectors from RFC 8032 §7.1 — Ed25519.
// Source: https://www.rfc-editor.org/rfc/rfc8032

func TestRFC8032_Vector1(t *testing.T) {
	// RFC 8032 §7.1 Test Vector 1 (TEST 1) — empty message.
	// Vector: [RFC 8032] §7.1 Test Vector 1
	seedHex := "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
	wantPubHex := "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
	wantSigHex := "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"

	seed, _ := hex.DecodeString(seedHex)
	wantPub, _ := hex.DecodeString(wantPubHex)
	wantSig, _ := hex.DecodeString(wantSigHex)

	// Construct private key from seed — the Go stdlib NewKeyFromSeed
	// produces the 64-byte (seed||pubkey) representation.
	stdPriv := stded25519.NewKeyFromSeed(seed)
	priv := &PrivateKey{key: stdPriv}

	// Public key derivation must match the RFC vector.
	pub := priv.Public()
	pubBytes := pub.Bytes()
	if subtle.ConstantTimeCompare(pubBytes[:], wantPub) != 1 {
		t.Errorf("public key = %x, want %s", pubBytes, wantPubHex)
	}

	// Sign the empty message — Ed25519 is deterministic.
	sig := priv.Sign(nil)
	if subtle.ConstantTimeCompare(sig, wantSig) != 1 {
		t.Errorf("signature = %x, want %s", sig, wantSigHex)
	}

	// Verify the known signature against the known public key.
	if !pub.Verify(wantSig, nil) {
		t.Error("Verify(known sig, empty msg) returned false, want true")
	}
}

func TestRFC8032_Vector2(t *testing.T) {
	// RFC 8032 §7.1 Test Vector 2 (TEST 2) — 1-byte message 0x72.
	// Vector: [RFC 8032] §7.1 Test Vector 2
	seedHex := "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb"
	wantPubHex := "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c"
	msgHex := "72"
	wantSigHex := "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"

	seed, _ := hex.DecodeString(seedHex)
	wantPub, _ := hex.DecodeString(wantPubHex)
	msg, _ := hex.DecodeString(msgHex)
	wantSig, _ := hex.DecodeString(wantSigHex)

	stdPriv := stded25519.NewKeyFromSeed(seed)
	priv := &PrivateKey{key: stdPriv}

	pub := priv.Public()
	pubBytes := pub.Bytes()
	if subtle.ConstantTimeCompare(pubBytes[:], wantPub) != 1 {
		t.Errorf("public key = %x, want %s", pubBytes, wantPubHex)
	}

	sig := priv.Sign(msg)
	if subtle.ConstantTimeCompare(sig, wantSig) != 1 {
		t.Errorf("signature = %x, want %s", sig, wantSigHex)
	}

	if !pub.Verify(wantSig, msg) {
		t.Error("Verify(known sig, 1-byte msg) returned false, want true")
	}
}

func TestSign_Deterministic(t *testing.T) {
	// Ed25519 is deterministic per [RFC 8032] §2.6 — same key + same
	// message always produces the same signature.
	seedHex := "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb"
	seed, _ := hex.DecodeString(seedHex)
	stdPriv := stded25519.NewKeyFromSeed(seed)
	priv := &PrivateKey{key: stdPriv}

	msg := []byte("deterministic test message")

	sig1 := priv.Sign(msg)
	sig2 := priv.Sign(msg)

	if subtle.ConstantTimeCompare(sig1, sig2) != 1 {
		t.Fatal("deterministic signing failed: same key + message produced different signatures")
	}
}

func TestGenerateKey_RoundTrip(t *testing.T) {
	priv, pub, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey error: %v", err)
	}

	msg := []byte("round-trip test")
	sig := priv.Sign(msg)

	if !pub.Verify(sig, msg) {
		t.Fatal("round-trip failed: Verify returned false for freshly signed message")
	}

	// Public() must derive the same public key that GenerateKey returned.
	derivedPub := priv.Public()
	if !pub.Equal(derivedPub) {
		t.Fatal("Public() does not match the public key from GenerateKey")
	}
}

func TestVerify_RejectsModifiedSignature(t *testing.T) {
	// Flip a bit in the signature — must fail.
	priv, pub, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey error: %v", err)
	}

	msg := []byte("modified signature test")
	sig := priv.Sign(msg)

	tampered := make([]byte, len(sig))
	copy(tampered, sig)
	tampered[0] ^= 0x01

	if pub.Verify(tampered, msg) {
		t.Fatal("Verify returned true for modified signature, want false")
	}
}

func TestVerify_RejectsModifiedMessage(t *testing.T) {
	// Same signature, different message — must fail.
	priv, pub, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey error: %v", err)
	}

	msg := []byte("original message")
	sig := priv.Sign(msg)

	if pub.Verify(sig, []byte("modified message")) {
		t.Fatal("Verify returned true for modified message, want false")
	}
}

func TestVerify_RejectsWrongPublicKey(t *testing.T) {
	// Correct signature, wrong public key — must fail.
	priv, _, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey error: %v", err)
	}

	msg := []byte("wrong pubkey test")
	sig := priv.Sign(msg)

	tamperedPubBytes := priv.Public().Bytes()
	tamperedPubBytes[0] ^= 0x01
	wrongPub, err := NewPublicKey(tamperedPubBytes[:])
	if err != nil {
		t.Fatalf("NewPublicKey error: %v", err)
	}

	if wrongPub.Verify(sig, msg) {
		t.Fatal("Verify returned true with wrong public key, want false")
	}
}

func TestVerify_RejectsShortSignature(t *testing.T) {
	// 63-byte signature — must fail (Ed25519 signatures are 64 bytes).
	_, pub, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey error: %v", err)
	}

	if pub.Verify(make([]byte, 63), []byte("short sig test")) {
		t.Fatal("Verify returned true for 63-byte signature, want false")
	}
}

func TestVerify_RejectsLongSignature(t *testing.T) {
	// 65-byte signature — must fail.
	_, pub, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey error: %v", err)
	}

	if pub.Verify(make([]byte, 65), []byte("long sig test")) {
		t.Fatal("Verify returned true for 65-byte signature, want false")
	}
}

func TestVerify_RejectsEmptySignature(t *testing.T) {
	// Zero-length signature — must fail.
	_, pub, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey error: %v", err)
	}

	if pub.Verify([]byte{}, []byte("empty sig test")) {
		t.Fatal("Verify returned true for empty signature, want false")
	}
}

func TestVerify_RejectsAllZeroSignature(t *testing.T) {
	// 64-byte all-zero signature — must fail.
	_, pub, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey error: %v", err)
	}

	if pub.Verify(make([]byte, 64), []byte("zero sig test")) {
		t.Fatal("Verify returned true for all-zero signature, want false")
	}
}

func TestVerify_EmptyMessage(t *testing.T) {
	// Boundary: empty message must sign and verify correctly.
	priv, pub, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey error: %v", err)
	}

	sig := priv.Sign(nil)
	if !pub.Verify(sig, nil) {
		t.Fatal("Verify returned false for empty message round-trip")
	}
}

func TestNewPrivateKey_InvalidLength(t *testing.T) {
	tests := []struct {
		name string
		key  []byte
	}{
		{"nil", nil},
		{"empty", []byte{}},
		{"too short", make([]byte, 63)},
		{"too long", make([]byte, 65)},
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
		{"too short", make([]byte, 31)},
		{"too long", make([]byte, 33)},
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

func TestPrivateKey_Redact(t *testing.T) {
	priv, _, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey error: %v", err)
	}

	redacted := priv.Redact()

	// Must not contain the full key.
	fullHex := hex.EncodeToString(priv.key)
	if strings.Contains(redacted, fullHex) {
		t.Fatal("Redact() exposes full key material")
	}

	// Must not contain any 2+ consecutive raw key bytes.
	for i := 0; i+1 < len(priv.key); i++ {
		pairHex := hex.EncodeToString(priv.key[i : i+2])
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

// wycheproofTestFile is the Project Wycheproof EdDSA test vector file.
// Source: https://github.com/C2SP/wycheproof/blob/master/testvectors_v1/ed25519_test.json
const wycheproofTestFile = "testdata/ed25519_test.json"

// wycheproofSuite models the relevant fields of the Wycheproof
// ed25519_test.json structure.
type wycheproofSuite struct {
	Algorithm     string            `json:"algorithm"`
	NumberOfTests int               `json:"numberOfTests"`
	TestGroups    []wycheproofGroup `json:"testGroups"`
}

type wycheproofGroup struct {
	PublicKey wycheproofPublicKey `json:"publicKey"`
	Tests     []wycheproofTest    `json:"tests"`
}

type wycheproofPublicKey struct {
	PK string `json:"pk"`
}

type wycheproofTest struct {
	TcID    int      `json:"tcId"`
	Comment string   `json:"comment"`
	Flags   []string `json:"flags"`
	Msg     string   `json:"msg"`
	Sig     string   `json:"sig"`
	Result  string   `json:"result"`
}

// TestWycheproof loads Project Wycheproof EdDSA vectors and runs
// every case against our Verify wrapper. See README.md for details.
//
// Vector: [Wycheproof] ed25519_test.json
func TestWycheproof(t *testing.T) {
	data, err := os.ReadFile(wycheproofTestFile)
	if err != nil {
		t.Fatalf("Wycheproof test data not found: %v", err)
	}

	var suite wycheproofSuite
	if err := json.Unmarshal(data, &suite); err != nil {
		t.Fatalf("unmarshal wycheproof: %v", err)
	}

	total := 0
	for _, group := range suite.TestGroups {
		pkBytes, err := hex.DecodeString(group.PublicKey.PK)
		if err != nil {
			t.Fatalf("decode publicKey pk: %v", err)
		}
		pub, err := NewPublicKey(pkBytes)
		if err != nil {
			// Some Wycheproof groups use deliberately invalid public
			// keys; skip those groups — they test parsing, not verify.
			continue
		}

		for _, tc := range group.Tests {
			total++
			tc := tc
			t.Run(fmtTCID(tc.TcID, tc.Comment), func(t *testing.T) {
				msg, _ := hex.DecodeString(tc.Msg)
				sig, _ := hex.DecodeString(tc.Sig)

				got := pub.Verify(sig, msg)

				switch tc.Result {
				case "valid", "acceptable":
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

func fmtTCID(id int, comment string) string {
	if comment == "" {
		return "tcId-" + itoa(id)
	}
	// Sanitize comment for test name (no spaces or special chars).
	c := strings.NewReplacer(" ", "_", "/", "_", "(", "", ")", "").Replace(comment)
	return "tcId-" + itoa(id) + "-" + c
}

func itoa(n int) string {
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
