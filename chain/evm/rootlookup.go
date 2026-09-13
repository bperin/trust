// Package evm provides a read-only EVM root-lookup client for the
// commitment registry contract. It queries on-chain Merkle roots by
// batch ID via eth_call and decodes the ABI-encoded result. The client
// performs no writes, no event indexing, and no state mutation — the
// chain is a timestamp oracle, not the source of truth.
//
// The RPCClient interface is defined consumer-side so unit tests can
// mock the RPC layer without a live EVM node. A real implementation
// wraps an ethclient or JSON-RPC client and satisfies the interface.
//
// Per [EIP-1474] (Remote Procedure Call Specification), eth_call is a
// read-only invocation that does not change chain state. The
// FinalityThreshold gates committed status to roots confirmed at or
// above a configurable block depth, defending against reorgs and
// non-canonical blocks.
package evm

import (
	"context"
	"errors"
	"fmt"

	"github.com/bperin/trust/chain/abi"
	"github.com/bperin/trust/trust/merkle"
)

// Sentinel errors returned by Lookup. Check them with errors.Is.
var (
	// ErrRPCError is returned when the underlying RPC transport fails
	// — network timeout, connection refused, or a malformed response.
	// It wraps the original transport error.
	ErrRPCError = errors.New("evm: rpc error")
	// ErrRootNotFound is returned when the queried batch ID has no
	// committed root on chain — the batch was never submitted or has
	// not yet been confirmed.
	ErrRootNotFound = errors.New("evm: root not found")
)

// getRootSelector is the 4-byte function selector for
// getRoot(bytes32), the first 4 bytes of keccak256("getRoot(bytes32)")
// per the [Solidity ABI Specification v2] §"Function Selector". Computed
// once via abi.FunctionSelector so a malformed selector is caught at
// startup.
//
// Per [EIP-1474], eth_call is a read-only invocation that does not
// change chain state; the selector prefixes the calldata for that call.
//
// [Solidity ABI Specification v2]: https://docs.soliditylang.org/en/latest/abi-spec.html
// [EIP-1474]: https://eips.ethereum.org/EIPS/eip-1474
var getRootSelector = abi.FunctionSelector("getRoot(bytes32)")

// ABI encoding constants for the getRoot return tuple. Each component
// is a 32-byte word; the total encoding is 160 bytes. uint64 values
// are ABI-encoded as uint256 (big-endian, left-padded to 32 bytes).
const (
	abiWordSize  = 32
	abiNumWords  = 5
	abiResultLen = abiWordSize * abiNumWords
)

// RPCClient is a consumer-side interface for read-only EVM JSON-RPC.
// It is defined here (consumer-side) so unit tests can mock the RPC
// layer without a live EVM node. A real implementation wraps an
// ethclient or JSON-RPC client.
//
// Per [EIP-1474], eth_call is a read-only invocation: it does not
// change chain state or consume gas. The caller supplies the contract
// address; the client does not hold a hardcoded address.
type RPCClient interface {
	// GetRoot calls the commitment registry contract's getRoot(bytes32)
	// view function at contractAddress and returns the raw ABI-encoded
	// result. An empty result indicates the batch is not on chain. A
	// non-nil error indicates a transport failure.
	GetRoot(ctx context.Context, contractAddress [20]byte, batchID [32]byte) ([]byte, error)

	// BlockNumber returns the current chain head block number, used
	// for finality calculation.
	BlockNumber(ctx context.Context) (uint64, error)
}

// RootLookup is a read-only EVM root-lookup client for the commitment
// registry contract. It queries on-chain Merkle roots by batch ID via
// eth_call and decodes the ABI-encoded result. The caller supplies the
// contract address and FinalityThreshold; the client performs no
// writes and holds no chain state.
//
// The chain is a timestamp oracle, not the source of truth — the
// Merkle proof is self-verifying off-chain. FinalityThreshold gates
// committed status to roots confirmed at or above a configurable
// block depth, defending against reorgs and non-canonical blocks.
type RootLookup struct {
	// ContractAddress is the caller-supplied EVM commitment registry
	// contract address. The client does not hardcode it.
	ContractAddress [20]byte
	// Client is the read-only RPC client used for eth_call and
	// eth_blockNumber.
	Client RPCClient
	// FinalityThreshold is the minimum block depth for a root to be
	// considered committed. A root confirmed at block N is committed
	// when currentBlock - N >= FinalityThreshold.
	FinalityThreshold uint64
}

// OnChainRoot is a decoded on-chain commitment root returned by Lookup.
// It carries the Merkle root, batch metadata, and the block and
// transaction at which the root was confirmed.
type OnChainRoot struct {
	// BatchID is the content-addressed batch identifier queried.
	BatchID merkle.BatchID
	// MerkleRoot is the on-chain [RFC 6962] §2.1 Merkle Tree Hash for
	// the batch.
	MerkleRoot [32]byte
	// Sequence is the monotonic batch sequence number stored on chain.
	Sequence uint64
	// ProtocolVersion is the commitment protocol version stored on chain.
	ProtocolVersion uint
	// BlockNumber is the block at which the root was confirmed.
	BlockNumber uint64
	// TxHash is the transaction hash that submitted the root.
	TxHash [32]byte
}

// Lookup queries the on-chain Merkle root for batchID via a read-only
// eth_call to the commitment registry contract's getRoot(bytes32)
// view function. It encodes the function selector and batch ID,
// calls the RPC client, and decodes the ABI-encoded result.
//
// It returns ErrRootNotFound if the batch is not on chain (empty
// result) and ErrRPCError on transport failure. The caller-supplied
// ContractAddress selects the registry; the client does not hardcode it.
//
// Per [EIP-1474], eth_call is read-only and does not change chain state.
func (r *RootLookup) Lookup(ctx context.Context, batchID merkle.BatchID) (OnChainRoot, error) {
	// Encode calldata: selector (4 bytes) + batchID (32 bytes).
	data := make([]byte, 4+32)
	copy(data[:4], getRootSelector[:])
	copy(data[4:], batchID[:])

	raw, err := r.Client.GetRoot(ctx, r.ContractAddress, batchID)
	if err != nil {
		return OnChainRoot{}, fmt.Errorf("evm: lookup: %w", errors.Join(ErrRPCError, err))
	}
	if len(raw) == 0 {
		return OnChainRoot{}, ErrRootNotFound
	}

	root, err := decodeRoot(raw, batchID)
	if err != nil {
		return OnChainRoot{}, fmt.Errorf("evm: lookup: %w", errors.Join(ErrRPCError, err))
	}
	return root, nil
}

// CurrentBlock returns the current chain head block number via a
// read-only eth_blockNumber call. It is used for finality calculation.
func (r *RootLookup) CurrentBlock(ctx context.Context) (uint64, error) {
	n, err := r.Client.BlockNumber(ctx)
	if err != nil {
		return 0, fmt.Errorf("evm: block number: %w", errors.Join(ErrRPCError, err))
	}
	return n, nil
}

// decodeRoot decodes the ABI-encoded getRoot return value into an
// OnChainRoot. The return tuple is:
//
//	(bytes32 merkleRoot, uint64 sequence, uint256 protocolVersion,
//	 uint64 blockNumber, bytes32 txHash)
//
// Each component is a 32-byte word; the total encoding is 160 bytes.
// uint64 values are ABI-encoded as uint256 (big-endian, left-padded
// to 32 bytes). Values exceeding uint64 are truncated.
func decodeRoot(raw []byte, batchID merkle.BatchID) (OnChainRoot, error) {
	if len(raw) < abiResultLen {
		return OnChainRoot{}, fmt.Errorf("short result: got %d bytes, want %d", len(raw), abiResultLen)
	}

	var root OnChainRoot
	root.BatchID = batchID
	copy(root.MerkleRoot[:], raw[0:32])
	root.Sequence = decodeUint64(raw[32:64])
	root.ProtocolVersion = uint(decodeUint64(raw[64:96]))
	root.BlockNumber = decodeUint64(raw[96:128])
	copy(root.TxHash[:], raw[128:160])
	return root, nil
}

// decodeUint64 reads a 32-byte ABI-encoded uint256 word and returns
// its uint64 value. ABI encodes unsigned integers big-endian,
// left-padded with zeros; the value occupies the last 8 bytes.
// Values exceeding uint64 are truncated.
func decodeUint64(word []byte) uint64 {
	// The value is big-endian in the last 8 bytes of the 32-byte word.
	var v uint64
	for i := 0; i < 8; i++ {
		v = (v << 8) | uint64(word[24+i])
	}
	return v
}
