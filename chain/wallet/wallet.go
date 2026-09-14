// Package wallet binds a secp256k1 private key to its Ethereum address
// and signs transactions and personal messages with recoverable
// signatures.
//
// The wallet holds an in-memory key; keystore file formats and
// password management are application-layer concerns.
package wallet

import (
	"fmt"

	"github.com/bperin/trust/chain/ethereum"
	"github.com/bperin/trust/crypto/secp256k1"
)

// Wallet binds a secp256k1 private key to its Ethereum address.
type Wallet struct {
	priv *secp256k1.PrivateKey
}

// NewWallet returns a Wallet backed by the given secp256k1 private key.
// The key is retained by reference, not copied — callers must not
// mutate the underlying key material.
func NewWallet(priv *secp256k1.PrivateKey) *Wallet {
	return &Wallet{priv: priv}
}

// Address returns the wallet's checksummed Ethereum address.
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
