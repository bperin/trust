// Package proof assembles chain proofs that combine a Merkle inclusion
// proof with an on-chain root looked up via read-only EVM RPC. It
// applies a configurable finality threshold so verification reports
// committed only for roots confirmed at or above that block depth, and
// returns a typed root-mismatch error when the on-chain root does not
// equal the proof's Merkle root.
package proof

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"

	"github.com/bperin/trust/chain/evm"
	"github.com/bperin/trust/trust/attestation"
	"github.com/bperin/trust/trust/merkle"
)

// Sentinel errors returned by VerifyChainProof. Check with errors.Is.
var (
	// ErrRootMismatch is returned when the on-chain Merkle root does
	// not equal the proof's MerkleRoot. The proof is invalid — either
	// the proof was tampered with or the chain has a different root.
	ErrRootMismatch = errors.New("proof: on-chain root mismatch")

	// ErrCanonicalHashMismatch is returned when the attestation's
	// recomputed canonical hash does not equal the proof's
	// CanonicalHash field.
	ErrCanonicalHashMismatch = errors.New("proof: canonical hash mismatch")

	// ErrBelowFinalityThreshold is returned when the current block
	// number is below the confirmation block number — a defensive
	// guard against clock or RPC inconsistency. A root below the
	// finality threshold but at or above the confirmation block
	// returns StatusPending without this error.
	ErrBelowFinalityThreshold = errors.New("proof: current block below confirmation block")
)

// Status is the finality status of a verified chain proof.
type Status uint8

const (
	// StatusPending means the on-chain root matches but the
	// confirmation block has not yet reached the finality threshold.
	// The proof is cryptographically valid but not yet final.
	StatusPending Status = iota

	// StatusCommitted means the on-chain root matches and the
	// confirmation block is at or above the finality threshold.
	// The root is final and safe against reorgs.
	StatusCommitted
)

// String returns the human-readable status name.
func (s Status) String() string {
	switch s {
	case StatusPending:
		return "pending"
	case StatusCommitted:
		return "committed"
	default:
		return fmt.Sprintf("unknown(%d)", s)
	}
}

// BlockMetadata carries the block context in which the on-chain root
// was confirmed. It is used for finality calculation: a root is
// committed when currentBlock - BlockNumber >= finalityThreshold.
type BlockMetadata struct {
	// BlockNumber is the block at which the root was confirmed on chain.
	BlockNumber uint64

	// Timestamp is the block timestamp (Unix seconds). It is context
	// metadata — finality uses BlockNumber, not Timestamp.
	Timestamp uint64
}

// ChainProof assembles a Merkle inclusion proof with an on-chain root
// lookup. It carries everything a verifier needs to confirm that an
// attestation's canonical hash is committed in a Merkle batch whose
// root is anchored on-chain via the EVM commitment registry contract.
//
// The chain is a timestamp oracle, not the source of truth — the
// Merkle proof is self-verifying off-chain. The on-chain root lookup
// confirms that the batch root was published at a specific block, and
// the finality threshold gates committed status to roots at or above
// a configurable block depth, defending against reorgs and
// non-canonical blocks.
type ChainProof struct {
	// Attestation is the original signed attestation whose canonical
	// hash is a leaf in the Merkle batch.
	Attestation attestation.Attestation

	// CanonicalHash is the canonical hash of the attestation — the
	// Merkle leaf. VerifyChainProof recomputes it and compares in
	// constant time.
	CanonicalHash [32]byte

	// LeafIndex is the index of the attestation's canonical hash in
	// the Merkle batch's leaf list.
	LeafIndex uint64

	// TreeSize is the number of leaves in the Merkle batch. It binds
	// LeafIndex to the tree shape for [RFC 6962] §2.1.1 inclusion
	// verification — the audit path's side-marker sequence is
	// determined by LeafIndex and TreeSize together.
	TreeSize uint64

	// MerkleProof is the inclusion proof path from the leaf to the
	// root, as produced by merkle.InclusionProof.
	MerkleProof [][]byte

	// MerkleRoot is the [RFC 6962] §2.1 Merkle Tree Hash of the batch.
	// VerifyChainProof verifies the inclusion proof against this root
	// and compares it to the on-chain root.
	MerkleRoot [32]byte

	// ContractAddress is the EVM commitment registry contract address
	// that anchors the batch root on chain.
	ContractAddress [20]byte

	// TxHash is the transaction hash that submitted the root on chain.
	TxHash [32]byte

	// BlockMetadata carries the block number and timestamp at which
	// the root was confirmed. Finality is calculated from BlockNumber.
	BlockMetadata BlockMetadata

	// BatchID is the content-addressed batch identifier.
	BatchID merkle.BatchID

	// Sequence is the monotonic batch sequence number.
	Sequence uint64

	// ProtocolVersion is the commitment protocol version.
	ProtocolVersion uint
}

// RootLookup is a consumer-side interface for looking up on-chain
// commitment roots by batch ID. It is defined here so verification is
// testable without a live EVM node — a mock implementation returns a
// known root or a typed error.
//
// The concrete evm.RootLookup satisfies this interface.
type RootLookup interface {
	// Lookup returns the on-chain root for the given batch ID. It
	// returns evm.ErrRootNotFound if the batch is not on chain and
	// evm.ErrRPCError on transport failure.
	Lookup(ctx context.Context, batchID merkle.BatchID) (evm.OnChainRoot, error)
}

// VerifyOptions injects the on-chain root lookup and current block
// number so VerifyChainProof is testable without live RPC. The caller
// supplies the finality threshold; a root is committed when
// CurrentBlock - proof.BlockMetadata.BlockNumber >= FinalityThreshold.
type VerifyOptions struct {
	// Lookup is the on-chain root lookup client (or mock).
	Lookup RootLookup

	// CurrentBlock is the current chain head block number.
	CurrentBlock uint64

	// FinalityThreshold is the minimum block depth for committed
	// status. A root confirmed at block N is committed when
	// CurrentBlock - N >= FinalityThreshold.
	FinalityThreshold uint64
}

// VerifyChainProof verifies a chain proof: it confirms that the
// attestation's canonical hash is a leaf in a Merkle batch whose root
// is anchored on-chain, and applies a finality threshold to determine
// whether the root is committed or pending.
//
// Verification proceeds in order:
//
//  1. The attestation's canonical hash is recomputed and compared to
//     p.CanonicalHash in constant time (ErrCanonicalHashMismatch).
//  2. The Merkle inclusion proof is verified against p.MerkleRoot via
//     merkle.VerifyInclusion, which binds p.LeafIndex to p.TreeSize
//     (merkle.ErrIndexOutOfRange or merkle.ErrTamperedLeaf on
//     failure).
//  3. The on-chain root is looked up via opts.Lookup and compared to
//     p.MerkleRoot in constant time (ErrRootMismatch on mismatch,
//     evm.ErrRootNotFound if the batch is not on chain, evm.ErrRPCError
//     on transport failure).
//  4. Finality is applied: if opts.CurrentBlock -
//     p.BlockMetadata.BlockNumber >= opts.FinalityThreshold, the root
//     is StatusCommitted; otherwise StatusPending.
//
// The chain is a timestamp oracle — the Merkle proof is self-verifying
// off-chain. The on-chain lookup confirms publication; the finality
// threshold gates committed status to roots safe against reorgs.
//
// Per [EIP-1474], the on-chain lookup is a read-only eth_call that
// does not change chain state.
func VerifyChainProof(p ChainProof, opts VerifyOptions) (Status, error) {
	// Step 1: verify the attestation canonical hash.
	computed, err := attestation.CanonicalHash(&p.Attestation)
	if err != nil {
		return StatusPending, fmt.Errorf("proof: canonical hash: %w", err)
	}
	if subtle.ConstantTimeCompare(computed[:], p.CanonicalHash[:]) != 1 {
		return StatusPending, ErrCanonicalHashMismatch
	}

	// Step 2: verify the Merkle inclusion proof.
	if err := merkle.VerifyInclusion(p.MerkleRoot, p.LeafIndex, p.TreeSize, p.CanonicalHash, p.MerkleProof); err != nil {
		return StatusPending, fmt.Errorf("proof: merkle inclusion: %w", err)
	}

	// Step 3: look up the on-chain root and compare in constant time.
	onChain, err := opts.Lookup.Lookup(context.Background(), p.BatchID)
	if err != nil {
		return StatusPending, err
	}
	if subtle.ConstantTimeCompare(onChain.MerkleRoot[:], p.MerkleRoot[:]) != 1 {
		return StatusPending, ErrRootMismatch
	}

	// Step 4: apply finality threshold.
	if opts.CurrentBlock < p.BlockMetadata.BlockNumber {
		// Defensive: the current block is before the confirmation
		// block. This should not happen with a healthy RPC.
		return StatusPending, ErrBelowFinalityThreshold
	}
	depth := opts.CurrentBlock - p.BlockMetadata.BlockNumber
	if depth >= opts.FinalityThreshold {
		return StatusCommitted, nil
	}
	return StatusPending, nil
}
