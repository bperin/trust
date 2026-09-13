// Package eip712 implements [EIP-712] typed structured data hashing and
// signing. EIP-712 defines a domain separator, per-struct hashing, and
// a final signing digest that combines them under an [EIP-191] magic
// prefix.
//
// The package owns hashing only. Signing is delegated to the wallet
// ([wallet.Wallet.SignDigest]); recovery is delegated to
// [secp256k1.RecoverPubKey] and [ethereum.FromPublicKey]. No private
// keys are held in this package.
//
// Per [EIP-712] §4:
//   - domainSeparator = keccak256(typeHash || abiEncoded(domainFields))
//   - structHash      = keccak256(typeHash || abiEncoded(structFields))
//   - digest          = keccak256(0x1901 || domainSeparator || structHash)
//
// The 0x1901 prefix is the [EIP-191] magic byte (0x19) followed by the
// EIP-712 version byte (0x01).
package eip712

import (
	"fmt"
	"math/big"

	"github.com/bperin/chain/ethereum"
	"github.com/bperin/chain/wallet"
	"github.com/bperin/trust/crypto/hash"
	"github.com/bperin/trust/crypto/secp256k1"
)

// keccak256 returns the 32-byte Keccak-256 digest of data.
func keccak256(data []byte) [32]byte {
	return hash.NewKeccak256().Sum(data)
}

// keccak256Concat returns the Keccak-256 digest of the concatenation of
// the given byte slices.
func keccak256Concat(parts ...[]byte) [32]byte {
	total := 0
	for _, p := range parts {
		total += len(p)
	}
	buf := make([]byte, 0, total)
	for _, p := range parts {
		buf = append(buf, p...)
	}
	return hash.NewKeccak256().Sum(buf)
}

// DomainSeparator is the [EIP-712] §4 domain separator. It binds a
// signed message to a specific application, version, chain, and
// contract, preventing cross-domain replay.
type DomainSeparator struct {
	Name              string
	Version           string
	ChainID           *big.Int
	VerifyingContract ethereum.Address
	Salt              [32]byte
}

// domainTypeHash is the Keccak-256 of the canonical EIP-712 domain
// type string. Per [EIP-712] §4, the type string encodes the field
// names and types in canonical order.
var domainTypeHash = keccak256([]byte(
	"EIP712Domain(string name,string version,uint256 chainId,address verifyingContract,bytes32 salt)",
))

// Hash returns the [EIP-712] §4 domain separator hash:
// keccak256(domainTypeHash || abiEncode(name, version, chainId, verifyingContract, salt)).
//
// ABI encoding rules per [EIP-712] §4:
//   - string → keccak256(utf8 string), then 32 bytes
//   - uint256 → 32-byte big-endian
//   - address → 32-byte left-padded (12 zero bytes + 20 address bytes)
//   - bytes32 → 32 bytes as-is
func (d DomainSeparator) Hash() [32]byte {
	// ABI-encode the fields in canonical order.
	nameHash := keccak256([]byte(d.Name))
	versionHash := keccak256([]byte(d.Version))

	chainID := encodeUint256(d.ChainID)
	contract := encodeAddress(d.VerifyingContract)
	salt := d.Salt[:]

	encoded := make([]byte, 0, 32*5)
	encoded = append(encoded, nameHash[:]...)
	encoded = append(encoded, versionHash[:]...)
	encoded = append(encoded, chainID...)
	encoded = append(encoded, contract...)
	encoded = append(encoded, salt...)

	return keccak256Concat(domainTypeHash[:], encoded)
}

// HashStruct returns the [EIP-712] §4 struct hash:
// keccak256(typeHash || encodedFields). The caller provides the type
// hash (Keccak-256 of the canonical type string) and the ABI-encoded
// field values. This is the generic struct-hashing primitive — the
// caller is responsible for correct ABI encoding of the struct fields.
func HashStruct(typeHash []byte, encodedFields []byte) [32]byte {
	return keccak256Concat(typeHash, encodedFields)
}

// Digest returns the final [EIP-712] §4 signing digest:
// keccak256(0x1901 || domainSeparator || structHash).
//
// The 0x1901 prefix is the [EIP-191] magic byte (0x19) followed by the
// EIP-712 version byte (0x01). This distinguishes EIP-712 typed-data
// signatures from [EIP-191] personal messages (0x191E) and raw
// transaction signatures.
func Digest(domainSeparator [32]byte, structHash [32]byte) [32]byte {
	prefix := []byte{0x19, 0x01}
	return keccak256Concat(prefix, domainSeparator[:], structHash[:])
}

// Sign computes the [EIP-712] §4 digest from the domain separator and
// struct hash, signs it via the wallet's secp256k1 signer, and returns
// a 65-byte signature (r || s || v) where v = recID + 27.
//
// The wallet must have a non-nil private key. The digest is passed to
// [wallet.Wallet.SignDigest] — EIP-712 does not re-hash the digest.
func Sign(w *wallet.Wallet, domainSeparator [32]byte, structHash [32]byte) ([]byte, error) {
	if w == nil {
		return nil, fmt.Errorf("eip712: nil wallet")
	}
	digest := Digest(domainSeparator, structHash)
	return w.SignDigest(digest[:])
}

// Recover recovers the signer's Ethereum address from an EIP-712
// signature. It recomputes the digest from the domain separator and
// struct hash, splits the 65-byte signature into r, s, and v, calls
// [secp256k1.RecoverPubKey], and converts the recovered public key to
// an [EIP-55] address via [ethereum.FromPublicKey].
//
// The v byte uses the Ethereum convention (27 + recID); the recovery
// id is v - 27.
func Recover(sig []byte, domainSeparator [32]byte, structHash [32]byte) (ethereum.Address, error) {
	if len(sig) != 65 {
		return ethereum.Address{}, fmt.Errorf("eip712: signature must be 65 bytes, got %d", len(sig))
	}

	digest := Digest(domainSeparator, structHash)
	recID := sig[64] - 27
	if recID > 3 {
		return ethereum.Address{}, fmt.Errorf("eip712: invalid recovery id %d (v=%d)", recID, sig[64])
	}

	pub, err := secp256k1.RecoverPubKey(sig[:64], digest[:], recID)
	if err != nil {
		return ethereum.Address{}, fmt.Errorf("eip712: recover public key: %w", err)
	}

	addr, err := ethereum.FromPublicKey(pub)
	if err != nil {
		return ethereum.Address{}, fmt.Errorf("eip712: derive address: %w", err)
	}
	return addr, nil
}

// encodeUint256 ABI-encodes a uint256 as 32-byte big-endian. A nil or
// zero big.Int encodes as 32 zero bytes.
func encodeUint256(n *big.Int) []byte {
	out := make([]byte, 32)
	if n == nil || n.Sign() <= 0 {
		return out
	}
	b := n.Bytes()
	copy(out[32-len(b):], b)
	return out
}

// encodeAddress ABI-encodes an Ethereum address as a 32-byte
// left-padded value (12 zero bytes + 20 address bytes).
func encodeAddress(addr ethereum.Address) []byte {
	out := make([]byte, 32)
	copy(out[12:], addr[:])
	return out
}
