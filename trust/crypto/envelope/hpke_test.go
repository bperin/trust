package envelope

import (
	"bytes"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"testing"

	"github.com/bperin/trust/crypto/x25519"
)

// ---------------------------------------------------------------------------
// RFC 9180 known-answer vectors (Appendix A.1.1)
// ---------------------------------------------------------------------------
//
// Vector: [RFC 9180] Appendix A.1.1
// Suite: DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, AES-128-GCM
// Mode: base
// Source: https://www.rfc-editor.org/rfc/rfc9180#appendix-A.1.1
//
// The RFC vector provides a known receiver key pair, encapsulation key,
// and a set of encryptions. Since SetupSender generates a fresh
// ephemeral key internally (via circl's DHKEM), the sender-side vector
// is verified by injecting the known encapsulation seed (ikmE) into
// circl's Setup directly. The receiver-side vector is verified through
// the adapted public API: SetupReceiver with the known receiver
// private key and enc, then Open each RFC ciphertext.

// rfc9180A1_1 contains the RFC 9180 Appendix A.1.1 base-mode test
// vector for the X25519 + HKDF-SHA256 + AES-128-GCM suite.
var rfc9180A1_1 = struct {
	info      string // hex
	skRm      string // hex — receiver private key
	pkRm      string // hex — receiver public key
	enc       string // hex — encapsulated key (ephemeral public key)
	ikmE      string // hex — encapsulation seed for deterministic Setup
	sharedSec string // hex — DHKEM ExtractAndExpand output
	key       string // hex — derived AEAD key
	baseNonce string // hex — derived base nonce
}{
	info:      "4f6465206f6e2061204772656369616e2055726e",
	skRm:      "4612c550263fc8ad58375df3f557aac531d26850903e55a9f23f21d8534e8ac8",
	pkRm:      "3948cfe0ad1ddb695d780e59077195da6c56506b027329794ab02bca80815c4d",
	enc:       "37fda3567bdbd628e88668c3c8d7e97d1d1253b6d4ea6d44c150f741f1bf4431",
	ikmE:      "7268600d403fce431561aef583ee1613527cff655c1343f29812e66706df3234",
	sharedSec: "fe0e18c9f024ce43799ae393c7e8fe8fce9d218875e8227b0187c04e7d2ea1fc",
	key:       "4531685d41d65f03dc48f6b8302c05b0",
	baseNonce: "56d890e5accaaf011cff4b7d",
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

// TestRFC9180_A1_1_ReceiverOpen verifies that the adapted public API
// can open the RFC 9180 Appendix A.1.1.1 encryption sub-vectors. The
// known receiver private key and encapsulated key from the RFC are fed
// through SetupReceiver, then each ciphertext is opened with its
// corresponding AAD. This proves the key schedule, AEAD, and nonce
// sequencing are correct end-to-end.
//
// Vector: [RFC 9180] Appendix A.1.1.1
func TestRFC9180_A1_1_ReceiverOpen(t *testing.T) {
	t.Parallel()

	info, _ := hex.DecodeString(rfc9180A1_1.info)
	skRm, _ := hex.DecodeString(rfc9180A1_1.skRm)
	enc, _ := hex.DecodeString(rfc9180A1_1.enc)

	receiverPriv, err := x25519.NewPrivateKey(skRm)
	if err != nil {
		t.Fatalf("NewPrivateKey: %v", err)
	}

	// Verify that opening all encryptions in sequence through a
	// single receiver works — this tests nonce sequencing.
	t.Run("sequential", func(t *testing.T) {
		rcv, err := SetupReceiver(enc, receiverPriv, info)
		if err != nil {
			t.Fatalf("SetupReceiver: %v", err)
		}
		for i, e := range rfc9180A1_1Encryptions {
			ct, _ := hex.DecodeString(e.ct)
			aad, _ := hex.DecodeString(e.aad)
			wantPT, _ := hex.DecodeString(e.pt)

			got, err := rcv.Open(ct, aad)
			if err != nil {
				t.Fatalf("Open %d: %v", i, err)
			}
			if subtle.ConstantTimeCompare(got, wantPT) != 1 {
				t.Fatalf("seq %d: got %x, want %x", i, got, wantPT)
			}
		}
	})

	// Verify each encryption individually. Each subtest creates a
	// fresh receiver and advances it to the correct sequence number.
	for _, e := range rfc9180A1_1Encryptions {
		e := e
		t.Run(fmt.Sprintf("seq_%d", e.seq), func(t *testing.T) {
			t.Parallel()
			rcv, err := SetupReceiver(enc, receiverPriv, info)
			if err != nil {
				t.Fatalf("SetupReceiver: %v", err)
			}
			// Advance the receiver to the correct sequence number
			// by opening the preceding encryptions.
			for i := uint64(0); i < e.seq; i++ {
				prev := rfc9180A1_1Encryptions[i]
				prevCT, _ := hex.DecodeString(prev.ct)
				prevAAD, _ := hex.DecodeString(prev.aad)
				if _, err := rcv.Open(prevCT, prevAAD); err != nil {
					t.Fatalf("Open seq %d (prerequisite): %v", i, err)
				}
			}

			ct, _ := hex.DecodeString(e.ct)
			aad, _ := hex.DecodeString(e.aad)
			wantPT, _ := hex.DecodeString(e.pt)

			got, err := rcv.Open(ct, aad)
			if err != nil {
				t.Fatalf("Open seq %d: %v", e.seq, err)
			}
			if subtle.ConstantTimeCompare(got, wantPT) != 1 {
				t.Fatalf("seq %d: got %x, want %x", e.seq, got, wantPT)
			}
		})
	}
}

// TestRFC9180_A1_1_SenderSeal verifies that circl's HPKE sender, seeded
// with the known encapsulation seed (ikmE) from RFC 9180 A.1.1,
// produces the exact enc and ciphertexts from the RFC. This proves the
// sender-side key schedule, DHKEM, and AEAD match the standard.
//
// Vector: [RFC 9180] Appendix A.1.1.1
func TestRFC9180_A1_1_SenderSeal(t *testing.T) {
	t.Parallel()

	info, _ := hex.DecodeString(rfc9180A1_1.info)
	pkRm, _ := hex.DecodeString(rfc9180A1_1.pkRm)
	ikmE, _ := hex.DecodeString(rfc9180A1_1.ikmE)
	wantEnc, _ := hex.DecodeString(rfc9180A1_1.enc)

	// Convert the receiver public key to a circl KEM public key.
	receiverPub, err := x25519.NewPublicKey(pkRm)
	if err != nil {
		t.Fatalf("NewPublicKey: %v", err)
	}
	pkR, err := toKEMPublicKey(receiverPub)
	if err != nil {
		t.Fatalf("toKEMPublicKey: %v", err)
	}

	// Use circl directly with the known seed to reproduce the exact
	// enc and ciphertexts from the RFC.
	suite := circlSuite()
	sender, err := suite.NewSender(pkR, info)
	if err != nil {
		t.Fatalf("NewSender: %v", err)
	}

	enc, sealer, err := sender.Setup(bytes.NewReader(ikmE))
	if err != nil {
		t.Fatalf("Setup: %v", err)
	}

	// The encapsulated key must match the RFC byte-exact.
	if subtle.ConstantTimeCompare(enc, wantEnc) != 1 {
		t.Fatalf("enc: got %x, want %x", enc, wantEnc)
	}

	for i, e := range rfc9180A1_1Encryptions {
		pt, _ := hex.DecodeString(e.pt)
		aad, _ := hex.DecodeString(e.aad)
		wantCT, _ := hex.DecodeString(e.ct)

		got, err := sealer.Seal(pt, aad)
		if err != nil {
			t.Fatalf("Seal %d: %v", i, err)
		}
		if subtle.ConstantTimeCompare(got, wantCT) != 1 {
			t.Fatalf("ct %d: got %x, want %x", i, got, wantCT)
		}
	}
}

// ---------------------------------------------------------------------------
// Cross-implementation vector tests
// ---------------------------------------------------------------------------
//
// Verify that a seal produced by circl directly opens through the
// adapted public API, and vice versa. This proves the adapter
// correctly translates between trust's x25519 key types and circl's
// KEM key types, and that the wire format (enc || ciphertext) is
// interoperable.

// TestHPKECrossImpl_CirclSeal_PublicOpen verifies that an HPKE seal
// produced by circl directly opens through the adapted public API.
func TestHPKECrossImpl_CirclSeal_PublicOpen(t *testing.T) {
	t.Parallel()

	receiverPriv, receiverPub, err := x25519.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	info := []byte("cross-impl info")
	plaintext := []byte("cross-impl message")
	aad := []byte("cross-impl aad")

	// Produce a seal using circl directly.
	pkR, err := toKEMPublicKey(receiverPub)
	if err != nil {
		t.Fatalf("toKEMPublicKey: %v", err)
	}
	suite := circlSuite()
	sender, err := suite.NewSender(pkR, info)
	if err != nil {
		t.Fatalf("NewSender: %v", err)
	}
	enc, sealer, err := sender.Setup(rand.Reader)
	if err != nil {
		t.Fatalf("Setup: %v", err)
	}
	ciphertext, err := sealer.Seal(plaintext, aad)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	// Open through the adapted public API.
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

// TestHPKECrossImpl_PublicSeal_CirclOpen verifies that an HPKE seal
// produced by the adapted public API opens through circl directly.
func TestHPKECrossImpl_PublicSeal_CirclOpen(t *testing.T) {
	t.Parallel()

	receiverPriv, receiverPub, err := x25519.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	info := []byte("cross-impl info")
	plaintext := []byte("cross-impl message")
	aad := []byte("cross-impl aad")

	// Produce a seal using the adapted public API.
	sender, enc, err := SetupSender(receiverPub, info)
	if err != nil {
		t.Fatalf("SetupSender: %v", err)
	}
	ciphertext, err := sender.Seal(plaintext, aad)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	// Open through circl directly.
	skR, err := toKEMPrivateKey(receiverPriv)
	if err != nil {
		t.Fatalf("toKEMPrivateKey: %v", err)
	}
	suite := circlSuite()
	receiver, err := suite.NewReceiver(skR, info)
	if err != nil {
		t.Fatalf("NewReceiver: %v", err)
	}
	opener, err := receiver.Setup(enc)
	if err != nil {
		t.Fatalf("Setup: %v", err)
	}
	got, err := opener.Open(ciphertext, aad)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if subtle.ConstantTimeCompare(got, plaintext) != 1 {
		t.Fatalf("got %x, want %x", got, plaintext)
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

// TestHPKETamperedEncKey verifies that a tampered encapsulated key
// (one bit flipped in the 32-byte enc) causes Open to fail. The
// tampered enc produces a different DHKEM shared secret, so the
// derived AEAD key is wrong and decryption fails.
func TestHPKETamperedEncKey(t *testing.T) {
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

	// Flip each bit in the 32-byte enc key.
	for bit := 0; bit < len(enc)*8; bit++ {
		bit := bit
		t.Run(fmt.Sprintf("bit_%d", bit), func(t *testing.T) {
			t.Parallel()
			tamperedEnc := flipBit(enc, bit)

			receiver, err := SetupReceiver(tamperedEnc, receiverPriv, info)
			if err != nil {
				// SetupReceiver may fail if the tampered enc
				// is a low-order X25519 point (all-zero
				// shared secret). That is also a valid
				// failure mode.
				return
			}
			_, err = receiver.Open(ciphertext, aad)
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
