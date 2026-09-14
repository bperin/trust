package wallet

import (
	"crypto/subtle"
	"math/big"
	"testing"

	"github.com/bperin/trust/chain/ethereum"
	"github.com/bperin/trust/crypto/secp256k1"
)

// TestSignPersonalMessage_EIP191 verifies that signing a personal
// message produces a 65-byte signature that recovers to the wallet's
// address per [EIP-191].
func TestSignPersonalMessage_EIP191(t *testing.T) {
	t.Parallel()

	privBytes := hexDecode(t, "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80")
	priv, err := secp256k1.NewPrivateKey(privBytes)
	if err != nil {
		t.Fatalf("NewPrivateKey: %v", err)
	}
	w := NewWallet(priv)
	walletAddr, _ := w.Address()

	msg := []byte("Hello, Ethereum!")
	sig, err := w.SignPersonalMessage(msg)
	if err != nil {
		t.Fatalf("SignPersonalMessage: %v", err)
	}

	if len(sig) != 65 {
		t.Fatalf("signature length: got %d, want 65", len(sig))
	}

	// Recompute the EIP-191 digest and recover the signer.
	digest := personalMessageDigest(t, msg)
	recoveredPub, err := recoverPublicKey(sig, digest)
	if err != nil {
		t.Fatalf("recoverPublicKey: %v", err)
	}
	recoveredAddr, err := ethereum.FromPublicKey(recoveredPub)
	if err != nil {
		t.Fatalf("FromPublicKey: %v", err)
	}

	if recoveredAddr != walletAddr {
		t.Fatalf("recovered address: got %s, want %s", recoveredAddr.Hex(), walletAddr.Hex())
	}
}

// TestSignPersonalMessage_EmptyMessage verifies an empty message
// produces a valid signature that recovers to the wallet address.
func TestSignPersonalMessage_EmptyMessage(t *testing.T) {
	t.Parallel()

	privBytes := hexDecode(t, "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80")
	priv, _ := secp256k1.NewPrivateKey(privBytes)
	w := NewWallet(priv)
	walletAddr, _ := w.Address()

	sig, err := w.SignPersonalMessage(nil)
	if err != nil {
		t.Fatalf("SignPersonalMessage(nil): %v", err)
	}
	if len(sig) != 65 {
		t.Fatalf("signature length: got %d, want 65", len(sig))
	}

	digest := personalMessageDigest(t, nil)
	recoveredPub, err := recoverPublicKey(sig, digest)
	if err != nil {
		t.Fatalf("recoverPublicKey: %v", err)
	}
	recoveredAddr, _ := ethereum.FromPublicKey(recoveredPub)
	if recoveredAddr != walletAddr {
		t.Fatalf("recovered address: got %s, want %s", recoveredAddr.Hex(), walletAddr.Hex())
	}
}

// TestSignPersonalMessage_TamperedMessage verifies that a signature
// over message A does not recover to the wallet address when checked
// against message B.
func TestSignPersonalMessage_TamperedMessage(t *testing.T) {
	t.Parallel()

	privBytes := hexDecode(t, "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80")
	priv, _ := secp256k1.NewPrivateKey(privBytes)
	w := NewWallet(priv)
	walletAddr, _ := w.Address()

	sig, err := w.SignPersonalMessage([]byte("message A"))
	if err != nil {
		t.Fatalf("SignPersonalMessage: %v", err)
	}

	// Recover against a different message → should not match.
	digestB := personalMessageDigest(t, []byte("message B"))
	recoveredPub, err := recoverPublicKey(sig, digestB)
	if err != nil {
		t.Fatalf("recoverPublicKey: %v", err)
	}
	recoveredAddr, _ := ethereum.FromPublicKey(recoveredPub)
	if recoveredAddr == walletAddr {
		t.Fatal("signature from message A should not recover to wallet address against message B")
	}
}

// TestSignPersonalMessage_NilWallet verifies a nil wallet produces an
// error.
func TestSignPersonalMessage_NilWallet(t *testing.T) {
	t.Parallel()

	_, err := (*Wallet)(nil).SignPersonalMessage([]byte("test"))
	if err == nil {
		t.Fatal("SignPersonalMessage: got nil error, want error")
	}
}

// TestSignDigest verifies that SignDigest signs a raw 32-byte digest
// and the resulting 65-byte signature recovers to the wallet's public
// key.
func TestSignDigest(t *testing.T) {
	t.Parallel()

	privBytes := hexDecode(t, "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80")
	priv, _ := secp256k1.NewPrivateKey(privBytes)
	w := NewWallet(priv)

	// A known 32-byte digest (Keccak-256 of "test digest").
	digest := make([]byte, 32)
	for i := range digest {
		digest[i] = byte(i)
	}

	sig, err := w.SignDigest(digest)
	if err != nil {
		t.Fatalf("SignDigest: %v", err)
	}
	if len(sig) != 65 {
		t.Fatalf("signature length: got %d, want 65", len(sig))
	}

	// Recover the public key from the signature.
	recID := sig[64] - 27
	recoveredPub, err := secp256k1.RecoverPubKey(sig[:64], digest, recID)
	if err != nil {
		t.Fatalf("RecoverPubKey: %v", err)
	}
	if subtle.ConstantTimeCompare(recoveredPub.Bytes(), w.PublicKey().Bytes()) != 1 {
		t.Fatal("recovered public key does not match wallet public key")
	}
}

// TestSignDigest_InvalidLength verifies a non-32-byte digest is
// rejected.
func TestSignDigest_InvalidLength(t *testing.T) {
	t.Parallel()

	privBytes := hexDecode(t, "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80")
	priv, _ := secp256k1.NewPrivateKey(privBytes)
	w := NewWallet(priv)

	_, err := w.SignDigest([]byte("too short"))
	if err == nil {
		t.Fatal("SignDigest: got nil error, want error for short digest")
	}
}

// TestSignDigest_NilWallet verifies a nil wallet produces an error.
func TestSignDigest_NilWallet(t *testing.T) {
	t.Parallel()

	_, err := (*Wallet)(nil).SignDigest(make([]byte, 32))
	if err == nil {
		t.Fatal("SignDigest: got nil error, want error")
	}
}

// TestAssembleV_EIP2930 verifies that assembleV returns the y-parity
// (recID) for an [EIP-2930] type-1 transaction. The v field is a single
// byte (0 or 1), not the legacy [EIP-155] form.
//
// Reference: [EIP-2930] — y_parity is the parity of the y coordinate
// of the point R = (r, y).
func TestAssembleV_EIP2930(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name  string
		recID byte
		want  []byte
	}{
		{"recID_0", 0, []byte{0}},
		{"recID_1", 1, []byte{1}},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			tx := &EIP2930Tx{ChainID: big.NewInt(1)}
			got, err := assembleV(tx, tc.recID)
			if err != nil {
				t.Fatalf("assembleV: %v", err)
			}
			if subtle.ConstantTimeCompare(got, tc.want) != 1 {
				t.Fatalf("assembleV: got %x, want %x", got, tc.want)
			}
		})
	}
}

// personalMessageDigest computes the [EIP-191] digest of a message:
// Keccak-256 of "\x19Ethereum Signed Message:\n<len>" + msg.
func personalMessageDigest(t *testing.T, msg []byte) []byte {
	t.Helper()
	prefixed := append(personalMessagePrefix(msg), msg...)
	return hashKeccak256(prefixed)
}

// hashKeccak256 returns the 32-byte Keccak-256 digest of data.
func hashKeccak256(data []byte) []byte {
	return keccak256(data)
}
