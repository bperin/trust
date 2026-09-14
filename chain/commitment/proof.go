package commitment

import (
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"

	"github.com/bperin/trust/chain/abi"
	"github.com/bperin/trust/chain/eip712"
	"github.com/bperin/trust/chain/ethereum"
	"github.com/bperin/trust/chain/wallet"
	"github.com/bperin/trust/crypto/hash"
)

// ProofStructType is the canonical EIP-712 type string for a
// commitment proof binding a Merkle root to its on-chain anchor.
const ProofStructType = "Commitment(bytes32 root,bytes32 txHash,uint256 blockNumber)"

// CommitmentProof binds a Merkle root to a confirmed on-chain
// transaction via an EIP-712 typed-data signature from the publisher.
type CommitmentProof struct {
	Root        [32]byte `json:"root"`
	ChainID     *big.Int `json:"chainId"`
	Contract    [20]byte `json:"contract"`
	TxHash      [32]byte `json:"txHash"`
	BlockNumber uint64   `json:"blockNumber"`
	Signature   []byte   `json:"signature"`
}

// commitmentDomain builds the EIP-712 domain separator for an anchor
// and returns the separator and its hash.
func commitmentDomain(a *Anchor) (eip712.DomainSeparator, [32]byte, error) {
	if a == nil {
		return eip712.DomainSeparator{}, [32]byte{}, ErrNilAnchor
	}
	domain := eip712.DomainSeparator{
		Name:              "TrustCommitment",
		Version:           "1",
		ChainID:           a.ChainID,
		VerifyingContract: a.Contract,
		Salt:              [32]byte{},
	}
	domainHash, err := domain.Hash()
	if err != nil {
		return eip712.DomainSeparator{}, [32]byte{}, fmt.Errorf("commitment: domain hash: %w", err)
	}
	return domain, domainHash, nil
}

// commitmentStructHash returns the EIP-712 struct hash for the
// commitment proof fields.
func commitmentStructHash(root [32]byte, txHash [32]byte, blockNumber uint64) ([32]byte, error) {
	encoded, err := abi.EncodeArgs(
		[]abi.ABIType{abi.ABITypeBytes32, abi.ABITypeBytes32, abi.ABITypeUint256},
		[]interface{}{root, txHash, new(big.Int).SetUint64(blockNumber)},
	)
	if err != nil {
		return [32]byte{}, fmt.Errorf("commitment: encode struct: %w", err)
	}
	typeHash := hash.NewKeccak256().Sum([]byte(ProofStructType))
	return eip712.HashStruct(typeHash[:], encoded), nil
}

// Proof signs a commitment binding root to the receipt's on-chain
// transaction using the wallet, returning a verifiable CommitmentProof.
func Proof(root [32]byte, a *Anchor, r Receipt, w *wallet.Wallet) (CommitmentProof, error) {
	if a == nil {
		return CommitmentProof{}, ErrNilAnchor
	}
	if w == nil {
		return CommitmentProof{}, ErrNilWallet
	}

	txHash, err := parseTxHash(r.TransactionHash)
	if err != nil {
		return CommitmentProof{}, err
	}

	_, domainHash, err := commitmentDomain(a)
	if err != nil {
		return CommitmentProof{}, err
	}
	structHash, err := commitmentStructHash(root, txHash, r.BlockNumber)
	if err != nil {
		return CommitmentProof{}, err
	}

	sig, err := eip712.Sign(w, domainHash, structHash)
	if err != nil {
		return CommitmentProof{}, fmt.Errorf("commitment: sign: %w", err)
	}

	return CommitmentProof{
		Root:        root,
		ChainID:     a.ChainID,
		Contract:    a.Contract,
		TxHash:      txHash,
		BlockNumber: r.BlockNumber,
		Signature:   sig,
	}, nil
}

// VerifyCommitmentProof recovers the publisher's Ethereum address from
// the proof's EIP-712 signature. Any signature or domain failure is
// wrapped as ErrBadSignature.
func VerifyCommitmentProof(p CommitmentProof) (ethereum.Address, error) {
	a := &Anchor{ChainID: p.ChainID, Contract: p.Contract}
	_, domainHash, err := commitmentDomain(a)
	if err != nil {
		return ethereum.Address{}, fmt.Errorf("commitment: %w: %v", ErrBadSignature, err)
	}
	structHash, err := commitmentStructHash(p.Root, p.TxHash, p.BlockNumber)
	if err != nil {
		return ethereum.Address{}, fmt.Errorf("commitment: %w: %v", ErrBadSignature, err)
	}
	addr, err := eip712.Recover(p.Signature, domainHash, structHash)
	if err != nil {
		return ethereum.Address{}, fmt.Errorf("commitment: %w: %v", ErrBadSignature, err)
	}
	return addr, nil
}

// parseTxHash converts a hex transaction hash string (with or without
// 0x prefix) into a 32-byte value.
func parseTxHash(s string) ([32]byte, error) {
	body := strings.TrimPrefix(s, "0x")
	decoded, err := hex.DecodeString(body)
	if err != nil {
		return [32]byte{}, fmt.Errorf("commitment: %w: transaction hash is not valid hex", ErrMalformedReceipt)
	}
	if len(decoded) != 32 {
		return [32]byte{}, fmt.Errorf("commitment: %w: transaction hash is %d bytes, want 32", ErrMalformedReceipt, len(decoded))
	}
	var out [32]byte
	copy(out[:], decoded)
	return out, nil
}
