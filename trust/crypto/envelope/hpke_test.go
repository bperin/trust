package envelope

import (
	"crypto/subtle"
	"testing"

	"github.com/bperin/trust/crypto/x25519"
)

func TestHPKERoundTrip(t *testing.T) {
	// Generate receiver keypair
	receiverPriv, receiverPub, err := x25519.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	info := []byte("test info")
	plaintext := []byte("secret message")
	aad := []byte("associated data")

	// Sender: setup + seal
	sender, enc, err := SetupSender(receiverPub, info)
	if err != nil {
		t.Fatalf("SetupSender: %v", err)
	}
	ciphertext, err := sender.Seal(plaintext, aad)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	// Receiver: setup + open
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

func TestHPKEWrongKey(t *testing.T) {
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
	ciphertext, _ := sender.Seal(plaintext, nil)

	// Wrong receiver key
	wrongPriv, _, err := x25519.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	receiver, err := SetupReceiver(enc, wrongPriv, info)
	if err != nil {
		t.Fatalf("SetupReceiver: %v", err)
	}
	_, err = receiver.Open(ciphertext, nil)
	if err == nil {
		t.Fatal("Open should fail with wrong key")
	}
}

func TestHPKEWrongInfo(t *testing.T) {
	receiverPriv, receiverPub, err := x25519.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	sender, enc, err := SetupSender(receiverPub, []byte("info-a"))
	if err != nil {
		t.Fatalf("SetupSender: %v", err)
	}
	ciphertext, _ := sender.Seal([]byte("msg"), nil)

	// Wrong info
	receiver, err := SetupReceiver(enc, receiverPriv, []byte("info-b"))
	if err != nil {
		t.Fatalf("SetupReceiver: %v", err)
	}
	_, err = receiver.Open(ciphertext, nil)
	if err == nil {
		t.Fatal("Open should fail with wrong info")
	}
}

func TestHPKENonceSequencing(t *testing.T) {
	_, receiverPub, err := x25519.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	sender, _, err := SetupSender(receiverPub, nil)
	if err != nil {
		t.Fatalf("SetupSender: %v", err)
	}

	// Multiple seals should produce different ciphertexts
	c1, _ := sender.Seal([]byte("msg"), nil)
	c2, _ := sender.Seal([]byte("msg"), nil)

	if subtle.ConstantTimeCompare(c1, c2) == 1 {
		t.Fatal("nonce sequencing: ciphertexts should differ")
	}
}
