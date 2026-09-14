package secp256k1

import (
	"crypto/subtle"
	"testing"
)

func TestRecoverPubKeyRoundTrip(t *testing.T) {
	priv, pub, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	digest := []byte("0123456789abcdef0123456789abcdef") // 32 bytes
	sig, recID, err := priv.SignRecoverable(digest)
	if err != nil {
		t.Fatalf("SignRecoverable: %v", err)
	}

	recovered, err := RecoverPubKey(sig, digest, recID)
	if err != nil {
		t.Fatalf("RecoverPubKey: %v", err)
	}

	// Compare compressed bytes.
	a := pub.Bytes()
	b := recovered.Bytes()
	if subtle.ConstantTimeCompare(a, b) != 1 {
		t.Fatalf("recovered key %x != original %x", b, a)
	}
}

func TestRecoverPubKeyInvalidRecID(t *testing.T) {
	priv, _, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	digest := []byte("0123456789abcdef0123456789abcdef")
	sig, _, err := priv.SignRecoverable(digest)
	if err != nil {
		t.Fatalf("SignRecoverable: %v", err)
	}

	_, err = RecoverPubKey(sig, digest, 4)
	if err == nil {
		t.Fatal("RecoverPubKey should reject recID 4")
	}
}

func TestRecoverPubKeyInvalidSig(t *testing.T) {
	digest := []byte("0123456789abcdef0123456789abcdef")
	_, err := RecoverPubKey(make([]byte, 63), digest, 0)
	if err == nil {
		t.Fatal("RecoverPubKey should reject 63-byte signature")
	}
}

func TestEVMAddressVitalik(t *testing.T) {
	// Generate a key, derive address, verify format and checksum.
	_, pub, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	addr, err := EVMAddress(pub)
	if err != nil {
		t.Fatalf("EVMAddress: %v", err)
	}

	if len(addr) != 42 {
		t.Fatalf("address length %d, want 42", len(addr))
	}
	if addr[:2] != "0x" {
		t.Fatalf("address %q missing 0x prefix", addr)
	}

	// Verify the address matches EIP-55 checksum (re-checksumming should be idempotent).
	checksummed := ChecksumAddress(addr)
	if checksummed != addr {
		t.Fatalf("ChecksumAddress not idempotent: got %q, want %q", checksummed, addr)
	}
}

func TestEVMAddressNilKey(t *testing.T) {
	_, err := EVMAddress(nil)
	if err == nil {
		t.Fatal("EVMAddress should reject nil key")
	}
}

func TestChecksumAddressKnown(t *testing.T) {
	// EIP-55 spec example.
	got := ChecksumAddress("0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed")
	want := "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed"
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}

	// All-lowercase input → checksummed output.
	got = ChecksumAddress("0xfb6916095ca1df60bb79ce92ce3ea74c37c5d359")
	want = "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359"
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}
