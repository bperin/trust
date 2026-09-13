package wallet

import (
	"fmt"
	"math/big"
	"strconv"

	"github.com/bperin/trust/crypto/hash"
	"github.com/bperin/trust/crypto/secp256k1"
)

// SignTx signs a [Transaction] with the wallet's private key and
// returns the fully RLP-encoded signed transaction ready for
// broadcast.
//
// The signing flow per [EIP-2718] and [SEC 1 v2] §4.3.3:
//  1. Compute the transaction's signing hash.
//  2. Produce a recoverable secp256k1 signature (64-byte r||s + recID).
//  3. Assemble the v field per the transaction type:
//     - Legacy (type 0): v = recID + 35 + chainID*2 per [EIP-155].
//     - EIP-1559 (type 2): v = recID (y-parity) per [EIP-1559].
//  4. Encode the signed transaction via EncodeSigned.
func (w *Wallet) SignTx(tx Transaction) ([]byte, error) {
	if w == nil || w.priv == nil {
		return nil, fmt.Errorf("wallet: nil private key")
	}
	if tx == nil {
		return nil, fmt.Errorf("wallet: nil transaction")
	}

	digest, err := tx.SigningHash()
	if err != nil {
		return nil, fmt.Errorf("wallet: signing hash: %w", err)
	}

	sig, recID, err := w.priv.SignRecoverable(digest)
	if err != nil {
		return nil, fmt.Errorf("wallet: sign recoverable: %w", err)
	}

	r := sig[:32]
	s := sig[32:64]

	v, err := assembleV(tx, recID)
	if err != nil {
		return nil, err
	}

	return tx.EncodeSigned(r, s, v)
}

// SignPersonalMessage signs an [EIP-191] personal message. The message
// is prefixed with "\x19Ethereum Signed Message:\n<len>", Keccak-256
// hashed, and signed with a recoverable secp256k1 signature. The
// returned signature is 65 bytes: r(32) || s(32) || v(1) where
// v = recID + 27 per [EIP-191].
func (w *Wallet) SignPersonalMessage(msg []byte) ([]byte, error) {
	if w == nil || w.priv == nil {
		return nil, fmt.Errorf("wallet: nil private key")
	}

	prefixed := append(personalMessagePrefix(msg), msg...)
	digest := hash.NewKeccak256().SumBytes(prefixed)

	sig, recID, err := w.priv.SignRecoverable(digest)
	if err != nil {
		return nil, fmt.Errorf("wallet: sign personal message: %w", err)
	}

	out := make([]byte, 65)
	copy(out[:32], sig[:32])
	copy(out[32:64], sig[32:64])
	out[64] = recID + 27
	return out, nil
}

// SignDigest signs a raw 32-byte digest with a recoverable secp256k1
// signature. The returned signature is 65 bytes: r(32) || s(32) || v(1)
// where v = recID + 27.
//
// This is exposed for [EIP-712] typed-data hashing, which computes its
// own digest (0x1901 || domainSeparator || structHash) and needs to
// sign it without re-hashing or applying the [EIP-191] personal-message
// prefix. Callers that need [EIP-191] personal-message signing should
// use SignPersonalMessage instead.
func (w *Wallet) SignDigest(digest []byte) ([]byte, error) {
	if w == nil || w.priv == nil {
		return nil, fmt.Errorf("wallet: nil private key")
	}
	if len(digest) != 32 {
		return nil, fmt.Errorf("wallet: digest must be 32 bytes, got %d", len(digest))
	}

	sig, recID, err := w.priv.SignRecoverable(digest)
	if err != nil {
		return nil, fmt.Errorf("wallet: sign digest: %w", err)
	}

	out := make([]byte, 65)
	copy(out[:32], sig[:32])
	copy(out[32:64], sig[32:64])
	out[64] = recID + 27
	return out, nil
}

// assembleV computes the v field for a signed transaction per the
// transaction type.
func assembleV(tx Transaction, recID byte) ([]byte, error) {
	switch tx.Type() {
	case 0:
		// Legacy: v = recID + 35 + chainID*2 per [EIP-155].
		legacy, ok := tx.(*LegacyTx)
		if !ok {
			return nil, fmt.Errorf("wallet: type 0 transaction is not *LegacyTx")
		}
		chainID := legacy.ChainID
		if chainID == nil || chainID.Sign() == 0 {
			return nil, fmt.Errorf("wallet: legacy tx requires non-zero chain ID")
		}
		v := new(big.Int).Mul(chainID, big.NewInt(2))
		v.Add(v, big.NewInt(int64(recID)+35))
		return v.Bytes(), nil
	case 2:
		// EIP-1559: v = recID (y-parity) per [EIP-1559].
		return []byte{recID}, nil
	default:
		return nil, fmt.Errorf("wallet: unsupported transaction type %d", tx.Type())
	}
}

// personalMessagePrefix returns the [EIP-191] personal-message prefix:
// "\x19Ethereum Signed Message:\n<len>" where <len> is the decimal
// length of msg.
func personalMessagePrefix(msg []byte) []byte {
	prefix := "\x19Ethereum Signed Message:\n" + strconv.Itoa(len(msg))
	return []byte(prefix)
}

// recoverPublicKey recovers the secp256k1 public key from a 65-byte
// r||s||v signature and a 32-byte digest. The v byte uses the
// Ethereum convention (27 + recID); the recovery id is v - 27.
func recoverPublicKey(sig []byte, digest []byte) (*secp256k1.PublicKey, error) {
	if len(sig) != 65 {
		return nil, fmt.Errorf("wallet: signature must be 65 bytes, got %d", len(sig))
	}
	if len(digest) != 32 {
		return nil, fmt.Errorf("wallet: digest must be 32 bytes, got %d", len(digest))
	}
	recID := sig[64] - 27
	if recID > 3 {
		return nil, fmt.Errorf("wallet: invalid recovery id %d (v=%d)", recID, sig[64])
	}
	return secp256k1.RecoverPubKey(sig[:64], digest, recID)
}
