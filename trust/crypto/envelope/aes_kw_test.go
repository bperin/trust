package envelope

import (
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// RFC 3394 known-answer vectors
// ---------------------------------------------------------------------------
//
// Vectors: [RFC 3394] §4.1–§4.6.
// Source: https://www.rfc-editor.org/rfc/rfc3394

// rfc3394Vector is a single RFC 3394 test vector.
type rfc3394Vector struct {
	name string
	kek  string // hex
	key  string // hex
	ct   string // hex
}

// rfc3394Vectors contains all six RFC 3394 §4 test vectors. Each wraps
// a known plaintext key with a known KEK and expects a byte-exact
// ciphertext. The vectors cover every combination of AES-128/192/256
// KEK and 128/192/256-bit key data defined in the RFC.
var rfc3394Vectors = []rfc3394Vector{
	{
		name: "4.1_128bit_key_128bit_kek",
		kek:  "000102030405060708090A0B0C0D0E0F",
		key:  "00112233445566778899AABBCCDDEEFF",
		ct:   "1FA68B0A8112B447AEF34BD8FB5A7B829D3E862371D2CFE5",
	},
	{
		name: "4.2_128bit_key_192bit_kek",
		kek:  "000102030405060708090A0B0C0D0E0F1011121314151617",
		key:  "00112233445566778899AABBCCDDEEFF",
		ct:   "96778B25AE6CA435F92B5B97C050AED2468AB8A17AD84E5D",
	},
	{
		name: "4.3_128bit_key_256bit_kek",
		kek:  "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
		key:  "00112233445566778899AABBCCDDEEFF",
		ct:   "64E8C3F9CE0F5BA263E9777905818A2A93C8191E7D6E8AE7",
	},
	{
		name: "4.4_192bit_key_192bit_kek",
		kek:  "000102030405060708090A0B0C0D0E0F1011121314151617",
		key:  "00112233445566778899AABBCCDDEEFF0001020304050607",
		ct:   "031D33264E15D33268F24EC260743EDCE1C6C7DDEE725A936BA814915C6762D2",
	},
	{
		name: "4.5_192bit_key_256bit_kek",
		kek:  "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
		key:  "00112233445566778899AABBCCDDEEFF0001020304050607",
		ct:   "A8F9BC1612C68B3FF6E6F4FBE30E71E4769C8B80A32CB8958CD5D17D6B254DA1",
	},
	{
		name: "4.6_256bit_key_256bit_kek",
		kek:  "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
		key:  "00112233445566778899AABBCCDDEEFF000102030405060708090A0B0C0D0E0F",
		ct:   "28C9F404C4B810F4CBCCB35CFB87F8263F5786E2D80ED326CBC7F0E71A99F43BFB988B9B7A02DD21",
	},
}

// TestRFC3394KnownVectors verifies Wrap against every RFC 3394 §4
// test vector. Each case wraps the known plaintext key with the known
// KEK and asserts the ciphertext is byte-exact, then unwraps and
// verifies the original key is recovered.
//
// Vector: [RFC 3394] §4.1–§4.6
func TestRFC3394KnownVectors(t *testing.T) {
	t.Parallel()
	for _, tv := range rfc3394Vectors {
		tv := tv
		t.Run(tv.name, func(t *testing.T) {
			t.Parallel()
			kek, err := hex.DecodeString(tv.kek)
			if err != nil {
				t.Fatalf("decode KEK: %v", err)
			}
			key, err := hex.DecodeString(tv.key)
			if err != nil {
				t.Fatalf("decode key: %v", err)
			}
			want, err := hex.DecodeString(tv.ct)
			if err != nil {
				t.Fatalf("decode ct: %v", err)
			}

			got, err := Wrap(kek, key)
			if err != nil {
				t.Fatalf("Wrap: %v", err)
			}
			if subtle.ConstantTimeCompare(got, want) != 1 {
				t.Fatalf("Wrap: got %x, want %x", got, want)
			}

			unwrap, err := Unwrap(kek, got)
			if err != nil {
				t.Fatalf("Unwrap: %v", err)
			}
			if subtle.ConstantTimeCompare(unwrap, key) != 1 {
				t.Fatalf("Unwrap: got %x, want %x", unwrap, key)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Round-trip with GenerateKEK
// ---------------------------------------------------------------------------

// TestWrapUnwrapRoundTrip verifies Wrap/Unwrap round-trips with a
// generated 256-bit KEK.
func TestWrapUnwrapRoundTrip(t *testing.T) {
	t.Parallel()
	kek, err := GenerateKEK()
	if err != nil {
		t.Fatalf("GenerateKEK: %v", err)
	}
	if len(kek) != 32 {
		t.Fatalf("GenerateKEK: got %d bytes, want 32", len(kek))
	}

	keys := [][]byte{
		make([]byte, 16), // 128-bit key
		make([]byte, 24), // 192-bit key
		make([]byte, 32), // 256-bit key
		make([]byte, 64), // 512-bit key (multiple semiblocks)
	}
	for i, key := range keys {
		for j := range key {
			key[j] = byte(i*100 + j)
		}
	}

	for _, key := range keys {
		key := key
		t.Run(fmt.Sprintf("keyLen_%d", len(key)), func(t *testing.T) {
			t.Parallel()
			wrapped, err := Wrap(kek, key)
			if err != nil {
				t.Fatalf("Wrap: %v", err)
			}
			if len(wrapped) != len(key)+8 {
				t.Fatalf("wrapped length: got %d, want %d", len(wrapped), len(key)+8)
			}
			unwrap, err := Unwrap(kek, wrapped)
			if err != nil {
				t.Fatalf("Unwrap: %v", err)
			}
			if subtle.ConstantTimeCompare(unwrap, key) != 1 {
				t.Fatalf("Unwrap: got %x, want %x", unwrap, key)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Determinism
// ---------------------------------------------------------------------------

// TestWrapDeterminism verifies that wrapping the same key with the
// same KEK produces the same wrapped key. AES-KW is deterministic per
// [RFC 3394] §2.2.1 — no nonce, no IV.
func TestWrapDeterminism(t *testing.T) {
	t.Parallel()
	kek, _ := hex.DecodeString("000102030405060708090A0B0C0D0E0F")
	key, _ := hex.DecodeString("00112233445566778899AABBCCDDEEFF")

	w1, err := Wrap(kek, key)
	if err != nil {
		t.Fatalf("Wrap (1): %v", err)
	}
	w2, err := Wrap(kek, key)
	if err != nil {
		t.Fatalf("Wrap (2): %v", err)
	}
	if subtle.ConstantTimeCompare(w1, w2) != 1 {
		t.Fatalf("Wrap is not deterministic: got %x and %x", w1, w2)
	}
}

// ---------------------------------------------------------------------------
// Negative tests
// ---------------------------------------------------------------------------

// TestUnwrapWrongKEK verifies that unwrapping with a wrong KEK causes
// an ICV mismatch error.
func TestUnwrapWrongKEK(t *testing.T) {
	t.Parallel()
	kek, _ := hex.DecodeString("000102030405060708090A0B0C0D0E0F")
	key, _ := hex.DecodeString("00112233445566778899AABBCCDDEEFF")
	wrapped, err := Wrap(kek, key)
	if err != nil {
		t.Fatalf("Wrap: %v", err)
	}

	wrongKEK, _ := hex.DecodeString("FF0102030405060708090A0B0C0D0E0F")
	_, err = Unwrap(wrongKEK, wrapped)
	if !errors.Is(err, ErrICVMismatch) {
		t.Fatalf("got %v, want ErrICVMismatch", err)
	}
}

// TestUnwrapTamperedWrappedKey verifies that a tampered wrapped key
// (one bit flipped) causes an ICV mismatch error.
func TestUnwrapTamperedWrappedKey(t *testing.T) {
	t.Parallel()
	kek, _ := hex.DecodeString("000102030405060708090A0B0C0D0E0F")
	key, _ := hex.DecodeString("00112233445566778899AABBCCDDEEFF")
	wrapped, err := Wrap(kek, key)
	if err != nil {
		t.Fatalf("Wrap: %v", err)
	}

	for bit := 0; bit < len(wrapped)*8; bit++ {
		bit := bit
		t.Run(fmt.Sprintf("bit_%d", bit), func(t *testing.T) {
			t.Parallel()
			tampered := flipBit(wrapped, bit)
			_, err := Unwrap(kek, tampered)
			if !errors.Is(err, ErrICVMismatch) {
				t.Fatalf("bit %d: got %v, want ErrICVMismatch", bit, err)
			}
		})
	}
}

// TestWrapInvalidKEKSize verifies that Wrap rejects KEKs that are not
// 16, 24, or 32 bytes.
func TestWrapInvalidKEKSize(t *testing.T) {
	t.Parallel()
	key := make([]byte, 16)
	tests := []struct {
		name string
		kek  []byte
	}{
		{"nil", nil},
		{"empty", []byte{}},
		{"15_bytes", make([]byte, 15)},
		{"17_bytes", make([]byte, 17)},
		{"20_bytes", make([]byte, 20)},
		{"33_bytes", make([]byte, 33)},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, err := Wrap(tt.kek, key)
			if !errors.Is(err, ErrInvalidKEK) {
				t.Fatalf("got %v, want ErrInvalidKEK", err)
			}
		})
	}
}

// TestUnwrapInvalidKEKSize verifies that Unwrap rejects KEKs that are
// not 16, 24, or 32 bytes.
func TestUnwrapInvalidKEKSize(t *testing.T) {
	t.Parallel()
	wrapped := make([]byte, 24)
	tests := []struct {
		name string
		kek  []byte
	}{
		{"nil", nil},
		{"empty", []byte{}},
		{"15_bytes", make([]byte, 15)},
		{"17_bytes", make([]byte, 17)},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, err := Unwrap(tt.kek, wrapped)
			if !errors.Is(err, ErrInvalidKEK) {
				t.Fatalf("got %v, want ErrInvalidKEK", err)
			}
		})
	}
}

// TestWrapInvalidKeySize verifies that Wrap rejects plaintext keys
// that are too short (< 16 bytes = 2 semiblocks) or not a multiple of
// 8 bytes.
func TestWrapInvalidKeySize(t *testing.T) {
	t.Parallel()
	kek := make([]byte, 32)
	tests := []struct {
		name string
		key  []byte
	}{
		{"nil", nil},
		{"empty", []byte{}},
		{"8_bytes", make([]byte, 8)},   // < 2 semiblocks
		{"15_bytes", make([]byte, 15)}, // < 16 bytes
		{"17_bytes", make([]byte, 17)}, // not multiple of 8
		{"20_bytes", make([]byte, 20)}, // not multiple of 8
		{"25_bytes", make([]byte, 25)}, // not multiple of 8
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, err := Wrap(kek, tt.key)
			if !errors.Is(err, ErrInvalidKey) {
				t.Fatalf("got %v, want ErrInvalidKey", err)
			}
		})
	}
}

// TestUnwrapInvalidWrappedSize verifies that Unwrap rejects wrapped
// keys that are too short (< 24 bytes = 3 semiblocks) or not a
// multiple of 8 bytes.
func TestUnwrapInvalidWrappedSize(t *testing.T) {
	t.Parallel()
	kek := make([]byte, 32)
	tests := []struct {
		name    string
		wrapped []byte
	}{
		{"nil", nil},
		{"empty", []byte{}},
		{"8_bytes", make([]byte, 8)},   // < 3 semiblocks
		{"16_bytes", make([]byte, 16)}, // < 3 semiblocks
		{"23_bytes", make([]byte, 23)}, // < 24 bytes
		{"25_bytes", make([]byte, 25)}, // not multiple of 8
		{"28_bytes", make([]byte, 28)}, // not multiple of 8
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, err := Unwrap(kek, tt.wrapped)
			if !errors.Is(err, ErrInvalidWrapped) {
				t.Fatalf("got %v, want ErrInvalidWrapped", err)
			}
		})
	}
}

// TestGenerateKEK verifies that GenerateKEK returns a 32-byte key and
// that two calls produce different keys (CSPRNG is working).
func TestGenerateKEK(t *testing.T) {
	t.Parallel()
	k1, err := GenerateKEK()
	if err != nil {
		t.Fatalf("GenerateKEK (1): %v", err)
	}
	if len(k1) != 32 {
		t.Fatalf("got %d bytes, want 32", len(k1))
	}
	k2, err := GenerateKEK()
	if err != nil {
		t.Fatalf("GenerateKEK (2): %v", err)
	}
	if subtle.ConstantTimeCompare(k1, k2) == 1 {
		t.Fatal("GenerateKEK returned the same key twice — CSPRNG not working")
	}
}

// ---------------------------------------------------------------------------
// Wycheproof tests
// ---------------------------------------------------------------------------

// wycheproofKWSuite models the relevant fields of the Wycheproof
// AES-WRAP test vector JSON structure.
//
// Vector: [Wycheproof] aes_wrap_test.json
type wycheproofKWSuite struct {
	Algorithm     string                  `json:"algorithm"`
	NumberOfTests int                     `json:"numberOfTests"`
	TestGroups    []wycheproofKWTestGroup `json:"testGroups"`
}

type wycheproofKWTestGroup struct {
	KeySize int                `json:"keySize"`
	Tests   []wycheproofKWTest `json:"tests"`
}

type wycheproofKWTest struct {
	TcID    int      `json:"tcId"`
	Comment string   `json:"comment"`
	Flags   []string `json:"flags"`
	Key     string   `json:"key"` // KEK (hex)
	Msg     string   `json:"msg"` // plaintext key (hex)
	Ct      string   `json:"ct"`  // wrapped ciphertext (hex)
	Result  string   `json:"result"`
}

// TestWycheproof loads Project Wycheproof AES-KW vectors and runs
// every case against our Wrap/Unwrap. Test groups are filtered to
// keySize in {128, 192, 256} (AES-128/192/256 KEKs).
//
//   - valid: Unwrap succeeds and re-wrap matches the original ciphertext.
//   - acceptable: Unwrap may succeed or fail; we log the result and
//     flags for security review but do not fail the test.
//   - invalid: Unwrap must return an error.
//
// Vector: [Wycheproof] aes_wrap_test.json
func TestWycheproof(t *testing.T) {
	t.Parallel()
	data, err := os.ReadFile("testdata/aes_kw_test.json")
	if err != nil {
		t.Fatalf("Wycheproof test data not found: %v", err)
	}

	var suite wycheproofKWSuite
	if err := json.Unmarshal(data, &suite); err != nil {
		t.Fatalf("unmarshal wycheproof: %v", err)
	}

	total := 0
	for _, group := range suite.TestGroups {
		// Filter to AES-128/192/256 KEK sizes.
		switch group.KeySize {
		case 128, 192, 256:
		default:
			continue
		}

		for _, tc := range group.Tests {
			tc := tc
			total++
			t.Run(wycheproofKWName(tc.TcID, tc.Comment), func(t *testing.T) {
				t.Parallel()
				kek, _ := hex.DecodeString(tc.Key)
				msg, _ := hex.DecodeString(tc.Msg)
				ct, _ := hex.DecodeString(tc.Ct)

				switch tc.Result {
				case "valid":
					// Unwrap must succeed and recover the
					// original plaintext key.
					unwrap, err := Unwrap(kek, ct)
					if err != nil {
						t.Fatalf("tcId %d (%s): Unwrap = %v, want nil [flags: %v]",
							tc.TcID, tc.Comment, err, tc.Flags)
					}
					if subtle.ConstantTimeCompare(unwrap, msg) != 1 {
						t.Fatalf("tcId %d (%s): Unwrap = %x, want %x [flags: %v]",
							tc.TcID, tc.Comment, unwrap, msg, tc.Flags)
					}
					// Re-wrap must produce the same ciphertext
					// (AES-KW is deterministic).
					rewrap, err := Wrap(kek, msg)
					if err != nil {
						t.Fatalf("tcId %d (%s): re-Wrap = %v, want nil [flags: %v]",
							tc.TcID, tc.Comment, err, tc.Flags)
					}
					if subtle.ConstantTimeCompare(rewrap, ct) != 1 {
						t.Fatalf("tcId %d (%s): re-Wrap = %x, want %x [flags: %v]",
							tc.TcID, tc.Comment, rewrap, ct, tc.Flags)
					}

				case "acceptable":
					// Acceptable cases may pass or fail
					// depending on implementation choices
					// (e.g. 8-byte key wrapping per RFC 3394
					// §2 vs NIST SP 800-38F). Log the result
					// and flags for security review.
					unwrap, err := Unwrap(kek, ct)
					t.Logf("tcId %d (%s): acceptable, Unwrap err = %v, unwrap = %x [flags: %v]",
						tc.TcID, tc.Comment, err, unwrap, tc.Flags)

				case "invalid":
					// Unwrap must fail.
					_, err := Unwrap(kek, ct)
					if err == nil {
						t.Fatalf("tcId %d (%s): Unwrap = nil, want error [flags: %v]",
							tc.TcID, tc.Comment, tc.Flags)
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

// ---------------------------------------------------------------------------
// Examples
// ---------------------------------------------------------------------------

// Example_wrapUnwrap demonstrates wrapping a 256-bit key with a
// generated KEK and then unwrapping it to recover the original key.
func Example_wrapUnwrap() {
	// Generate a 256-bit AES key-encryption key.
	kek, err := GenerateKEK()
	if err != nil {
		panic(err)
	}

	// The plaintext key to wrap (256-bit DEK).
	key := []byte("0123456789ABCDEF0123456789ABCDEF")

	// Wrap the key with the KEK.
	wrapped, err := Wrap(kek, key)
	if err != nil {
		panic(err)
	}

	// Unwrap to recover the original key.
	unwrapped, err := Unwrap(kek, wrapped)
	if err != nil {
		panic(err)
	}

	fmt.Println(subtle.ConstantTimeCompare(unwrapped, key) == 1)
	// Output: true
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// flipBit returns a copy of b with the specified bit flipped.
func flipBit(b []byte, bit int) []byte {
	out := make([]byte, len(b))
	copy(out, b)
	out[bit/8] ^= 1 << (bit % 8)
	return out
}

// wycheproofKWName formats a Wycheproof test case name for t.Run.
func wycheproofKWName(tcID int, comment string) string {
	if comment == "" {
		return "tcId-" + itoaKW(tcID)
	}
	c := strings.NewReplacer(" ", "_", "/", "_", "(", "", ")", "", ",", "_").Replace(comment)
	return "tcId-" + itoaKW(tcID) + "-" + c
}

// itoaKW converts a non-negative int to its decimal string.
func itoaKW(n int) string {
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
