package jwkutil

import (
	"crypto"
	"crypto/elliptic"
	"testing"

	"github.com/bperin/trust/crypto/ecdsa"
	"github.com/bperin/trust/crypto/ed25519"
	"github.com/bperin/trust/crypto/rsa"
	"github.com/bperin/trust/crypto/secp256k1"
)

func TestCoseSignVerifyEd25519(t *testing.T) {
	key, pub, err := ed25519.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	payload := []byte("Hello COSE Ed25519")
	coseBytes, err := CoseSign(payload, key, CoseSignOptions{Algorithm: AlgEdDSA})
	if err != nil {
		t.Fatalf("CoseSign: %v", err)
	}

	gotPayload, err := CoseVerify(coseBytes, pub, CoseVerifyOptions{Algorithm: AlgEdDSA})
	if err != nil {
		t.Fatalf("CoseVerify: %v", err)
	}

	if string(gotPayload) != string(payload) {
		t.Errorf("got payload %q, want %q", gotPayload, payload)
	}
}

func TestCoseSignVerifyECDSA(t *testing.T) {
	key, pub, err := ecdsa.GenerateKey(elliptic.P256(), crypto.SHA256)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	payload := []byte("Hello COSE ES256")
	coseBytes, err := CoseSign(payload, key, CoseSignOptions{Algorithm: AlgES256})
	if err != nil {
		t.Fatalf("CoseSign: %v", err)
	}

	gotPayload, err := CoseVerify(coseBytes, pub, CoseVerifyOptions{})
	if err != nil {
		t.Fatalf("CoseVerify: %v", err)
	}

	if string(gotPayload) != string(payload) {
		t.Errorf("got payload %q, want %q", gotPayload, payload)
	}
}

func TestCoseSignVerifySecp256k1(t *testing.T) {
	key, pub, err := secp256k1.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	payload := []byte("Hello COSE ES256K")
	coseBytes, err := CoseSign(payload, key, CoseSignOptions{Algorithm: AlgES256K})
	if err != nil {
		t.Fatalf("CoseSign: %v", err)
	}

	gotPayload, err := CoseVerify(coseBytes, pub, CoseVerifyOptions{})
	if err != nil {
		t.Fatalf("CoseVerify: %v", err)
	}

	if string(gotPayload) != string(payload) {
		t.Errorf("got payload %q, want %q", gotPayload, payload)
	}
}

func TestCoseSignVerifyRSA(t *testing.T) {
	key, pub, err := rsa.GeneratePSSKey(2048, crypto.SHA256)
	if err != nil {
		t.Fatalf("GeneratePSSKey: %v", err)
	}

	payload := []byte("Hello COSE PS256")
	coseBytes, err := CoseSign(payload, key, CoseSignOptions{Algorithm: AlgPS256})
	if err != nil {
		t.Fatalf("CoseSign: %v", err)
	}

	gotPayload, err := CoseVerify(coseBytes, pub, CoseVerifyOptions{})
	if err != nil {
		t.Fatalf("CoseVerify: %v", err)
	}

	if string(gotPayload) != string(payload) {
		t.Errorf("got payload %q, want %q", gotPayload, payload)
	}
}

func TestCoseNegative(t *testing.T) {
	key, pub, err := ed25519.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	coseBytes, err := CoseSign([]byte("test"), key, CoseSignOptions{Algorithm: AlgEdDSA})
	if err != nil {
		t.Fatalf("CoseSign: %v", err)
	}

	// Tampered verification (wrong key)
	_, wrongPub, _ := ed25519.GenerateKey()
	if _, err := CoseVerify(coseBytes, wrongPub, CoseVerifyOptions{}); err == nil {
		t.Error("expected error verifying with wrong key, got nil")
	}

	// Tampered payload
	coseBytes[len(coseBytes)-5] ^= 0xFF
	if _, err := CoseVerify(coseBytes, pub, CoseVerifyOptions{}); err == nil {
		t.Error("expected error verifying tampered COSE object, got nil")
	}
}
