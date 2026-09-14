// Package wallet binds a secp256k1 private key to its [EIP-55] Ethereum
// address and signs transactions and personal messages with
// recoverable signatures.
//
// The wallet holds an in-memory [secp256k1.PrivateKey]. It does not
// implement keystore file formats or password management — those are
// application-layer concerns. The wallet owns:
//
//   - Address derivation via [ethereum.FromPublicKey] ([EIP-55]).
//   - Transaction signing for legacy (type 0, [EIP-155]) and
//     EIP-1559 (type 2, [EIP-1559]) transactions behind an [EIP-2718]
//     typed-transaction envelope.
//   - [EIP-191] personal message signing.
//   - Raw digest signing via SignDigest, exposed for [EIP-712] typed
//     data hashing packages that compute their own digest.
package wallet

import (
	"fmt"

	"github.com/bperin/trust/chain/ethereum"
	"github.com/bperin/trust/crypto/secp256k1"
)

// Wallet binds a secp256k1 private key to its [EIP-55] Ethereum address.
// The private key is held in memory; no keystore or password management
// is performed.
type Wallet struct {
	priv *secp256k1.PrivateKey
}

// NewWallet returns a Wallet backed by the given secp256k1 private key.
// The key is retained by reference, not copied — callers must not
// mutate the underlying key material.
func NewWallet(priv *secp256k1.PrivateKey) *Wallet {
	return &Wallet{priv: priv}
}

// Address derives the [EIP-55] checksummed Ethereum address from the
// wallet's public key via [ethereum.FromPublicKey].
func (w *Wallet) Address() (ethereum.Address, error) {
	if w == nil || w.priv == nil {
		return ethereum.Address{}, fmt.Errorf("wallet: nil private key")
	}
	return ethereum.FromPublicKey(w.priv.Public())
}

// PublicKey returns the secp256k1 public key for this wallet.
func (w *Wallet) PublicKey() *secp256k1.PublicKey {
	if w == nil || w.priv == nil {
		return nil
	}
	return w.priv.Public()
}
