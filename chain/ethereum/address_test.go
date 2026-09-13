package ethereum

import (
	"crypto/subtle"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/bperin/trust/trust/crypto/secp256k1"
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

	if !strings.HasPrefix(addr.Hex(), "0x") || len(addr.Hex()) != 42 {
		t.Errorf("Invalid address format: %q", addr.Hex())
	}
}

// TestFromPublicKey_CompressedVectors derives Ethereum addresses from
// known secp256k1 private keys and asserts the EIP-55 checksummed
// address matches. These keys are compressed (33-byte) public keys, so
// FromPublicKey must decompress them before Keccak-256 per [SEC 1 v2]
// §2.3.3 and [EIP-55].
//
// Vector: Hardhat default test accounts (widely used Ethereum test
// vectors; addresses verified against ethers.js).
func TestFromPublicKey_CompressedVectors(t *testing.T) {
	tests := []struct {
		name    string
		privHex string
		wantHex string
	}{
		{
			name:    "hardhat account 0",
			privHex: "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
			wantHex: "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
		},
		{
			name:    "hardhat account 1",
			privHex: "59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d",
			wantHex: "0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			keyBytes, err := hex.DecodeString(tt.privHex)
			if err != nil {
				t.Fatalf("hex decode private key: %v", err)
			}

			priv, err := secp256k1.NewPrivateKey(keyBytes)
			if err != nil {
				t.Fatalf("NewPrivateKey: %v", err)
			}

			pub := priv.Public()

			// Sanity: the public key is in compressed (33-byte) form.
			compressed := pub.Bytes()
			if len(compressed) != 33 {
				t.Fatalf("compressed public key length: got %d, want 33", len(compressed))
			}

			addr, err := FromPublicKey(pub)
			if err != nil {
				t.Fatalf("FromPublicKey: %v", err)
			}

			got := addr.Hex()
			if got != tt.wantHex {
				t.Errorf("address: got %q, want %q", got, tt.wantHex)
			}

			// Cross-check: the address bytes must match the expected
			// 20-byte value in constant time.
			wantAddr, err := ParseAddress(tt.wantHex)
			if err != nil {
				t.Fatalf("ParseAddress(%q): %v", tt.wantHex, err)
			}
			if subtle.ConstantTimeCompare(addr[:], wantAddr[:]) != 1 {
				t.Errorf("address bytes: got %x, want %x", addr[:], wantAddr[:])
			}
		})
	}
}

// TestFromPublicKey_Nil verifies that a nil public key produces an
// error rather than a panic.
func TestFromPublicKey_Nil(t *testing.T) {
	_, err := FromPublicKey(nil)
	if err == nil {
		t.Fatal("FromPublicKey(nil) expected error, got nil")
	}
}
