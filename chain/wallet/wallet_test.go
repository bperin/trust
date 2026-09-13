package wallet

import (
	"crypto/subtle"
	"testing"

	"github.com/bperin/trust/chain/ethereum"
	"github.com/bperin/trust/trust/crypto/secp256k1"
)

// TestWallet_Address verifies EIP-55 address derivation from a known
// private key. The vector uses the first Hardhat default account.
//
// Vector: Hardhat account 0 private key
// 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80
// → address 0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266
func TestWallet_Address(t *testing.T) {
	t.Parallel()

	privKeyHex := "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
	privBytes := hexDecode(t, privKeyHex)
	priv, err := secp256k1.NewPrivateKey(privBytes)
	if err != nil {
		t.Fatalf("NewPrivateKey: %v", err)
	}

	w := NewWallet(priv)
	addr, err := w.Address()
	if err != nil {
		t.Fatalf("Address: %v", err)
	}

	want := "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"
	got := addr.Hex()
	if got != want {
		t.Fatalf("address: got %s, want %s", got, want)
	}

	// Verify the raw 20 bytes with constant-time compare.
	wantAddr, err := ethereum.ParseAddress(want)
	if err != nil {
		t.Fatalf("ParseAddress: %v", err)
	}
	if subtle.ConstantTimeCompare(addr[:], wantAddr[:]) != 1 {
		t.Fatalf("raw address bytes mismatch")
	}
}

// TestWallet_NilPrivateKey verifies that a nil wallet or nil key
// produces an error, not a panic.
func TestWallet_NilPrivateKey(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		w    *Wallet
	}{
		{"nil wallet", nil},
		{"nil private key", NewWallet(nil)},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := tc.w.Address()
			if err == nil {
				t.Fatal("Address: got nil error, want error")
			}
		})
	}
}

// TestWallet_PublicKey verifies the public key matches the private key.
func TestWallet_PublicKey(t *testing.T) {
	t.Parallel()

	privBytes := hexDecode(t, "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80")
	priv, err := secp256k1.NewPrivateKey(privBytes)
	if err != nil {
		t.Fatalf("NewPrivateKey: %v", err)
	}

	w := NewWallet(priv)
	pub := w.PublicKey()
	if pub == nil {
		t.Fatal("PublicKey: got nil")
	}

	// The public key bytes should match the derived public key.
	got := pub.Bytes()
	expectedPub := priv.Public()
	if subtle.ConstantTimeCompare(got, expectedPub.Bytes()) != 1 {
		t.Fatalf("public key mismatch")
	}
}
