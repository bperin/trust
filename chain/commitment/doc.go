// Package commitment anchors trust Merkle roots to external EVM chain
// state. It derives a deterministic commitment contract address for a
// (chain ID, namespace) pair, builds and signs the root-publishing
// transaction, proves the anchor with [EIP-712] typed data, and
// verifies that a root is bound to a confirmed on-chain transaction.
//
// Publish transactions carry the chain ID in the [EIP-155]
// replay-protected signature so a root anchored on one chain cannot
// be replayed on another. Commitment proofs are [EIP-712]
// typed-data signatures binding the root to the chain ID and
// contract address.
//
// The sentinel error taxonomy lives in errors.go.
package commitment

import "github.com/bperin/trust/chain/broadcast"

// Receipt is the typed eth_getTransactionReceipt response a published
// commitment transaction confirms against.
type Receipt = broadcast.Receipt
