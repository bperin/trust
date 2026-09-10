package ethereum

import (
	"testing"

	"github.com/bperin/trust/crypto/secp256k1"
)

func TestEIP55Checksum(t *testing.T) {
	rawHex := "52908400098527886e0f7030069857d2e4169ee7"
	addr, err := ParseAddress(rawHex)
	if err != nil {
		t.Fatalf("ParseAddress: %v", err)
	}

	expectedHex := "0x52908400098527886E0F7030069857D2E4169EE7"
	if addr.Hex() != expectedHex {
		t.Errorf("EIP-55 checksum: got %q, want %q", addr.Hex(), expectedHex)
	}

	parsed, err := ParseAddress(expectedHex)
	if err != nil {
		t.Fatalf("ParseAddress EIP-55: %v", err)
	}
	if parsed != addr {
		t.Errorf("parsed address mismatch")
	}

	badChecksum := "0x52908400098527886E0F7030069857d2E4169EE7"
	if _, err := ParseAddress(badChecksum); err == nil {
		t.Error("ParseAddress with bad checksum: expected error, got nil")
	}
}

func TestFromPublicKey(t *testing.T) {
	_, pub, err := secp256k1.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	addr, err := FromPublicKey(pub)
	if err != nil {
		t.Fatalf("FromPublicKey: %v", err)
	}

	if !stringsHasPrefix(addr.Hex(), "0x") || len(addr.Hex()) != 42 {
		t.Errorf("Invalid address format: %q", addr.Hex())
	}
}

func stringsHasPrefix(s, prefix string) bool {
	return len(s) >= len(prefix) && s[0:len(prefix)] == prefix
}
