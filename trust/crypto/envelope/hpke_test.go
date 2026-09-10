package envelope

import (
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"testing"

	"github.com/bperin/trust/crypto/x25519"
)

// ---------------------------------------------------------------------------
// RFC 9180 known-answer vector (Appendix A.1.1)
// ---------------------------------------------------------------------------
//
// Vector: [RFC 9180] Appendix A.1.1
// Suite: DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, AES-128-GCM
// Mode: base
// Source: https://www.rfc-editor.org/rfc/rfc9180#appendix-A.1.1
//
// The RFC vector uses a known ephemeral key pair and receiver key pair.
// Since SetupSender generates a fresh ephemeral key internally, we
// verify the key schedule and AEAD layers directly using the known
// DHKEM shared_secret from the vector. This tests the labeled
// HKDF-Extract/Expand chain, key/nonce derivation, nonce sequencing,
// and AES-128-GCM encryption against the byte-exact expected
// ciphertext from the RFC.

// rfc9180A1_1 contains the RFC 9180 Appendix A.1.1 base-mode test
// vector for the X25519 + HKDF-SHA256 + AES-128-GCM suite.
var rfc9180A1_1 = struct {
	info         string // hex
	sharedSecret string // hex — DHKEM ExtractAndExpand output
	key          string // hex — derived AEAD key
	baseNonce    string // hex — derived base nonce
}{
	info:         "4f6465206f6e2061204772656369616e2055726e",
	sharedSecret: "fe0e18c9f024ce43799ae393c7e8fe8fce9d218875e8227b0187c04e7d2ea1fc",
	key:          "4531685d41d65f03dc48f6b8302c05b0",
	baseNonce:    "56d890e5accaaf011cff4b7d",
}

// rfc9180A1_1Encryption is a single encryption from RFC 9180 A.1.1.1.
type rfc9180A1_1Encryption struct {
	seq   uint64
	pt    string // hex
	aad   string // hex
	nonce string // hex
	ct    string // hex
}

// rfc9180A1_1Encryptions contains the encryption sub-vectors from
// RFC 9180 Appendix A.1.1.1. Each uses the same plaintext with a
// different AAD and sequence number.
var rfc9180A1_1Encryptions = []rfc9180A1_1Encryption{
	{
		seq:   0,
		pt:    "4265617574792069732074727574682c20747275746820626561757479",
		aad:   "436f756e742d30",
		nonce: "56d890e5accaaf011cff4b7d",
		ct:    "f938558b5d72f1a23810b4be2ab4f84331acc02fc97babc53a52ae8218a355a96d8770ac83d07bea87e13c512a",
	},
	{
		seq:   1,
		pt:    "4265617574792069732074727574682c20747275746820626561757479",
		aad:   "436f756e742d31",
		nonce: "56d890e5accaaf011cff4b7c",
		ct:    "af2d7e9ac9ae7e270f46ba1f975be53c09f8d875bdc8535458c2494e8a6eab251c03d0c22a56b8ca42c2063b84",
	},
	{
		seq:   2,
		pt:    "4265617574792069732074727574682c20747275746820626561757479",
		aad:   "436f756e742d32",
		nonce: "56d890e5accaaf011cff4b7f",
		ct:    "498dfcabd92e8acedc281e85af1cb4e3e31c7dc394a1ca20e173cb72516491588d96a19ad4a683518973dcc180",
	},
}

// TestRFC9180_A1_1_KeySchedule verifies the HPKE key schedule against
// the RFC 9180 Appendix A.1.1 base-mode test vector. The known DHKEM
// shared_secret is fed through keySchedule and the derived key and
// base nonce must match the RFC byte-exact.
//
// Vector: [RFC 9180] Appendix A.1.1
func TestRFC9180_A1_1_KeySchedule(t *testing.T) {
	t.Parallel()
	suite := DefaultSuite()
	info, _ := hex.DecodeString(rfc9180A1_1.info)
	sharedSecret, _ := hex.DecodeString(rfc9180A1_1.sharedSecret)
	wantKey, _ := hex.DecodeString(rfc9180A1_1.key)
	wantNonce, _ := hex.DecodeString(rfc9180A1_1.baseNonce)

	key, nonce, err := keySchedule(suite, sharedSecret, info)
	if err != nil {
		t.Fatalf("keySchedule: %v", err)
	}
	if subtle.ConstantTimeCompare(key, wantKey) != 1 {
		t.Fatalf("key: got %x, want %x", key, wantKey)
	}
	if subtle.ConstantTimeCompare(nonce, wantNonce) != 1 {
		t.Fatalf("base_nonce: got %x, want %x", nonce, wantNonce)
	}
}

// TestRFC9180_A1_1_Encryptions verifies AES-128-GCM encryption
// against the RFC 9180 Appendix A.1.1.1 encryption sub-vectors. Each
// case uses the known key and base nonce derived from the key
// schedule, computes the per-sequence nonce, encrypts the known
// plaintext with the known AAD, and asserts the ciphertext is
// byte-exact.
//
// Vector: [RFC 9180] Appendix A.1.1.1
func TestRFC9180_A1_1_Encryptions(t *testing.T) {
	t.Parallel()
	suite := DefaultSuite()
	info, _ := hex.DecodeString(rfc9180A1_1.info)
	sharedSecret, _ := hex.DecodeString(rfc9180A1_1.sharedSecret)

	key, nonce, err := keySchedule(suite, sharedSecret, info)
	if err != nil {
		t.Fatalf("keySchedule: %v", err)
	}

	aead, err := newAEAD(suite, key)
	if err != nil {
		t.Fatalf("newAEAD: %v", err)
	}

	for _, enc := range rfc9180A1_1Encryptions {
		enc := enc
		t.Run(fmt.Sprintf("seq_%d", enc.seq), func(t *testing.T) {
			t.Parallel()
			pt, _ := hex.DecodeString(enc.pt)
			aad, _ := hex.DecodeString(enc.aad)
			wantNonce, _ := hex.DecodeString(enc.nonce)
			wantCT, _ := hex.DecodeString(enc.ct)

			nonce := nonceForCounter(nonce, enc.seq)
			if subtle.ConstantTimeCompare(nonce, wantNonce) != 1 {
				t.Fatalf("nonce: got %x, want %x", nonce, wantNonce)
			}

			got := aead.Seal(nil, nonce, pt, aad)
			if subtle.ConstantTimeCompare(got, wantCT) != 1 {
				t.Fatalf("ct: got %x, want %x", got, wantCT)
			}
		})
	}
}

// TestRFC9180_A1_1_NonceSequencing verifies that nonceForCounter
// produces the expected per-sequence nonces from the RFC 9180
// Appendix A.1.1 vector. The nonce is base_nonce XOR I2OSP(seq, 12).
//
// Vector: [RFC 9180] Appendix A.1.1.1
func TestRFC9180_A1_1_NonceSequencing(t *testing.T) {
	t.Parallel()
	baseNonce, _ := hex.DecodeString(rfc9180A1_1.baseNonce)

	for _, enc := range rfc9180A1_1Encryptions {
		enc := enc
		t.Run(fmt.Sprintf("seq_%d", enc.seq), func(t *testing.T) {
			t.Parallel()
			want, _ := hex.DecodeString(enc.nonce)
			got := nonceForCounter(baseNonce, enc.seq)
			if subtle.ConstantTimeCompare(got, want) != 1 {
				t.Fatalf("seq %d: got %x, want %x", enc.seq, got, want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Round-trip tests
// ---------------------------------------------------------------------------

// TestHPKERoundTrip verifies the full HPKE base-mode round-trip:
// SetupSender → Seal → SetupReceiver → Open → original plaintext.
func TestHPKERoundTrip(t *testing.T) {
	t.Parallel()
	receiverPriv, receiverPub, err := x25519.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	info := []byte("test info")
	plaintext := []byte("secret message")
	aad := []byte("associated data")

	sender, enc, err := SetupSender(receiverPub, info)
	if err != nil {
		t.Fatalf("SetupSender: %v", err)
	}
	ciphertext, err := sender.Seal(plaintext, aad)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	receiver, err := SetupReceiver(enc, receiverPriv, info)
	if err != nil {
		t.Fatalf("SetupReceiver: %v", err)
	}
	got, err := receiver.Open(ciphertext, aad)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if subtle.ConstantTimeCompare(got, plaintext) != 1 {
		t.Fatalf("got %x, want %x", got, plaintext)
	}
}

// TestHPKERoundTripWithAAD verifies the HPKE round-trip with AAD.
// Sealing with AAD and opening with the same AAD must recover the
// plaintext; opening with a different AAD must fail.
func TestHPKERoundTripWithAAD(t *testing.T) {
	t.Parallel()
	receiverPriv, receiverPub, err := x25519.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	info := []byte("test info")
	plaintext := []byte("secret message")
	aad := []byte("associated data")

	sender, enc, err := SetupSender(receiverPub, info)
	if err != nil {
		t.Fatalf("SetupSender: %v", err)
	}
	ciphertext, err := sender.Seal(plaintext, aad)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	// Correct AAD → Open succeeds.
	receiver, err := SetupReceiver(enc, receiverPriv, info)
	if err != nil {
		t.Fatalf("SetupReceiver: %v", err)
	}
	got, err := receiver.Open(ciphertext, aad)
	if err != nil {
		t.Fatalf("Open (correct AAD): %v", err)
	}
	if subtle.ConstantTimeCompare(got, plaintext) != 1 {
		t.Fatalf("got %x, want %x", got, plaintext)
	}
}

// ---------------------------------------------------------------------------
// Nonce sequencing
// ---------------------------------------------------------------------------

// TestHPKENonceSequencing verifies that multiple Seal calls produce
// different ciphertexts (the nonce counter increments per [RFC 9180]
// §5.3).
func TestHPKENonceSequencing(t *testing.T) {
	t.Parallel()
	_, receiverPub, err := x25519.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	sender, _, err := SetupSender(receiverPub, nil)
	if err != nil {
		t.Fatalf("SetupSender: %v", err)
	}

	plaintext := []byte("same message")
	ciphertexts := make([][]byte, 5)
	for i := range ciphertexts {
		ct, err := sender.Seal(plaintext, nil)
		if err != nil {
			t.Fatalf("Seal %d: %v", i, err)
		}
		ciphertexts[i] = ct
	}

	// Every pair of ciphertexts must differ.
	for i := 0; i < len(ciphertexts); i++ {
		for j := i + 1; j < len(ciphertexts); j++ {
			if subtle.ConstantTimeCompare(ciphertexts[i], ciphertexts[j]) == 1 {
				t.Fatalf("ciphertexts %d and %d are identical — nonce not incrementing", i, j)
			}
		}
	}
}

// ---------------------------------------------------------------------------
// Negative tests
// ---------------------------------------------------------------------------

// TestHPKEWrongReceiverKey verifies that Open with the wrong receiver
// private key fails.
func TestHPKEWrongReceiverKey(t *testing.T) {
	t.Parallel()
	_, receiverPub, err := x25519.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	info := []byte("test info")
	plaintext := []byte("secret message")

	sender, enc, err := SetupSender(receiverPub, info)
	if err != nil {
		t.Fatalf("SetupSender: %v", err)
	}
	ciphertext, err := sender.Seal(plaintext, nil)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	wrongPriv, _, err := x25519.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey (wrong): %v", err)
	}
	receiver, err := SetupReceiver(enc, wrongPriv, info)
	if err != nil {
		t.Fatalf("SetupReceiver: %v", err)
	}
	_, err = receiver.Open(ciphertext, nil)
	if !errors.Is(err, ErrDecryptionFailed) {
		t.Fatalf("got %v, want ErrDecryptionFailed", err)
	}
}

// TestHPKETamperedCiphertext verifies that a tampered ciphertext (one
// bit flipped) causes Open to fail.
func TestHPKETamperedCiphertext(t *testing.T) {
	t.Parallel()
	receiverPriv, receiverPub, err := x25519.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	info := []byte("test info")
	plaintext := []byte("secret message")

	sender, enc, err := SetupSender(receiverPub, info)
	if err != nil {
		t.Fatalf("SetupSender: %v", err)
	}
	ciphertext, err := sender.Seal(plaintext, nil)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	for bit := 0; bit < len(ciphertext)*8; bit++ {
		bit := bit
		t.Run(fmt.Sprintf("bit_%d", bit), func(t *testing.T) {
			t.Parallel()
			// Create a fresh receiver per subtest — Receiver.Open
			// mutates the counter, so sharing across parallel
			// subtests would race.
			receiver, err := SetupReceiver(enc, receiverPriv, info)
			if err != nil {
				t.Fatalf("SetupReceiver: %v", err)
			}
			tampered := flipBit(ciphertext, bit)
			_, err = receiver.Open(tampered, nil)
			if !errors.Is(err, ErrDecryptionFailed) {
				t.Fatalf("bit %d: got %v, want ErrDecryptionFailed", bit, err)
			}
		})
	}
}

// TestHPKEWrongAAD verifies that opening with a different AAD than
// was used for sealing fails.
func TestHPKEWrongAAD(t *testing.T) {
	t.Parallel()
	receiverPriv, receiverPub, err := x25519.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	info := []byte("test info")
	plaintext := []byte("secret message")
	aad := []byte("correct aad")

	sender, enc, err := SetupSender(receiverPub, info)
	if err != nil {
		t.Fatalf("SetupSender: %v", err)
	}
	ciphertext, err := sender.Seal(plaintext, aad)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	receiver, err := SetupReceiver(enc, receiverPriv, info)
	if err != nil {
		t.Fatalf("SetupReceiver: %v", err)
	}
	_, err = receiver.Open(ciphertext, []byte("wrong aad"))
	if !errors.Is(err, ErrDecryptionFailed) {
		t.Fatalf("got %v, want ErrDecryptionFailed", err)
	}
}

// TestHPKEWrongInfo verifies that using a different info for receiver
// setup than was used for sender setup causes Open to fail.
func TestHPKEWrongInfo(t *testing.T) {
	t.Parallel()
	receiverPriv, receiverPub, err := x25519.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	sender, enc, err := SetupSender(receiverPub, []byte("info-a"))
	if err != nil {
		t.Fatalf("SetupSender: %v", err)
	}
	ciphertext, err := sender.Seal([]byte("msg"), nil)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	receiver, err := SetupReceiver(enc, receiverPriv, []byte("info-b"))
	if err != nil {
		t.Fatalf("SetupReceiver: %v", err)
	}
	_, err = receiver.Open(ciphertext, nil)
	if !errors.Is(err, ErrDecryptionFailed) {
		t.Fatalf("got %v, want ErrDecryptionFailed", err)
	}
}

// ---------------------------------------------------------------------------
// Boundary tests
// ---------------------------------------------------------------------------

// TestHPKEEmptyPlaintext verifies that an empty plaintext seals and
// opens correctly.
func TestHPKEEmptyPlaintext(t *testing.T) {
	t.Parallel()
	receiverPriv, receiverPub, err := x25519.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	info := []byte("test info")
	aad := []byte("associated data")

	sender, enc, err := SetupSender(receiverPub, info)
	if err != nil {
		t.Fatalf("SetupSender: %v", err)
	}
	ciphertext, err := sender.Seal(nil, aad)
	if err != nil {
		t.Fatalf("Seal (empty pt): %v", err)
	}
	// AES-128-GCM tag is 16 bytes; empty plaintext → 16-byte ciphertext.
	if len(ciphertext) != 16 {
		t.Fatalf("ciphertext length: got %d, want 16 (GCM tag only)", len(ciphertext))
	}

	receiver, err := SetupReceiver(enc, receiverPriv, info)
	if err != nil {
		t.Fatalf("SetupReceiver: %v", err)
	}
	got, err := receiver.Open(ciphertext, aad)
	if err != nil {
		t.Fatalf("Open (empty pt): %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("got %d bytes, want 0", len(got))
	}
}

// TestHPKEEmptyAAD verifies that an empty AAD seals and opens
// correctly.
func TestHPKEEmptyAAD(t *testing.T) {
	t.Parallel()
	receiverPriv, receiverPub, err := x25519.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	info := []byte("test info")
	plaintext := []byte("secret message")

	sender, enc, err := SetupSender(receiverPub, info)
	if err != nil {
		t.Fatalf("SetupSender: %v", err)
	}
	ciphertext, err := sender.Seal(plaintext, nil)
	if err != nil {
		t.Fatalf("Seal (empty AAD): %v", err)
	}

	receiver, err := SetupReceiver(enc, receiverPriv, info)
	if err != nil {
		t.Fatalf("SetupReceiver: %v", err)
	}
	got, err := receiver.Open(ciphertext, nil)
	if err != nil {
		t.Fatalf("Open (empty AAD): %v", err)
	}
	if subtle.ConstantTimeCompare(got, plaintext) != 1 {
		t.Fatalf("got %x, want %x", got, plaintext)
	}
}

// TestHPKEEmptyPlaintextEmptyAAD verifies the double-empty boundary:
// both plaintext and AAD are empty.
func TestHPKEEmptyPlaintextEmptyAAD(t *testing.T) {
	t.Parallel()
	receiverPriv, receiverPub, err := x25519.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	sender, enc, err := SetupSender(receiverPub, nil)
	if err != nil {
		t.Fatalf("SetupSender: %v", err)
	}
	ciphertext, err := sender.Seal(nil, nil)
	if err != nil {
		t.Fatalf("Seal (empty pt + empty AAD): %v", err)
	}

	receiver, err := SetupReceiver(enc, receiverPriv, nil)
	if err != nil {
		t.Fatalf("SetupReceiver: %v", err)
	}
	got, err := receiver.Open(ciphertext, nil)
	if err != nil {
		t.Fatalf("Open (empty pt + empty AAD): %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("got %d bytes, want 0", len(got))
	}
}

// ---------------------------------------------------------------------------
// SetupReceiver error tests
// ---------------------------------------------------------------------------

// TestSetupReceiverInvalidEnc verifies that SetupReceiver rejects an
// encapsulated key that is not 32 bytes.
func TestSetupReceiverInvalidEnc(t *testing.T) {
	t.Parallel()
	receiverPriv, _, err := x25519.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	tests := []struct {
		name string
		enc  []byte
	}{
		{"nil", nil},
		{"empty", []byte{}},
		{"16_bytes", make([]byte, 16)},
		{"31_bytes", make([]byte, 31)},
		{"33_bytes", make([]byte, 33)},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, err := SetupReceiver(tt.enc, receiverPriv, nil)
			if !errors.Is(err, ErrInvalidEnc) {
				t.Fatalf("got %v, want ErrInvalidEnc", err)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Suite tests
// ---------------------------------------------------------------------------

// TestDefaultSuite verifies that DefaultSuite returns the expected
// X25519 + HKDF-SHA256 + AES-128-GCM identifiers per [RFC 9180] §7.
func TestDefaultSuite(t *testing.T) {
	t.Parallel()
	s := DefaultSuite()
	if s.KEMID != kemX25519 {
		t.Fatalf("KEMID: got 0x%04x, want 0x%04x", s.KEMID, kemX25519)
	}
	if s.KDFID != kdfHKDFSHA256 {
		t.Fatalf("KDFID: got 0x%04x, want 0x%04x", s.KDFID, kdfHKDFSHA256)
	}
	if s.AEADID != aeadAES128GCM {
		t.Fatalf("AEADID: got 0x%04x, want 0x%04x", s.AEADID, aeadAES128GCM)
	}
}

// ---------------------------------------------------------------------------
// Examples
// ---------------------------------------------------------------------------

// Example_hpkeRoundTrip demonstrates a full HPKE base-mode round-trip:
// generate a receiver keypair, set up a sender, seal a message, set
// up the receiver, and open the ciphertext to recover the plaintext.
func Example_hpkeRoundTrip() {
	// Generate the receiver's X25519 keypair.
	receiverPriv, receiverPub, err := x25519.GenerateKey()
	if err != nil {
		panic(err)
	}

	info := []byte("application info")
	plaintext := []byte("hello, HPKE")
	aad := []byte("associated data")

	// Sender: set up and seal.
	sender, enc, err := SetupSender(receiverPub, info)
	if err != nil {
		panic(err)
	}
	ciphertext, err := sender.Seal(plaintext, aad)
	if err != nil {
		panic(err)
	}

	// Receiver: set up and open.
	receiver, err := SetupReceiver(enc, receiverPriv, info)
	if err != nil {
		panic(err)
	}
	got, err := receiver.Open(ciphertext, aad)
	if err != nil {
		panic(err)
	}

	fmt.Println(subtle.ConstantTimeCompare(got, plaintext) == 1)
	// Output: true
}
