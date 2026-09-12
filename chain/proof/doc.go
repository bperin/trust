// Package proof assembles chain proofs that combine a Merkle inclusion
// proof with an on-chain root looked up via read-only EVM RPC.
//
// # Chain as witness, not source of truth
//
// The Merkle proof is self-verifying off-chain: a verifier recomputes
// the root from the leaf and the inclusion path and needs no chain
// data to confirm the hash is in the tree. The EVM commitment
// registry contract is a timestamp oracle — it records when a batch
// root was published but does not define the tree. A compromised or
// forked RPC can return a matching root from a non-canonical block,
// so verification does not trust the root alone.
//
// # Finality threshold
//
// A configurable finality threshold gates committed status. A root
// confirmed at block N is StatusCommitted only when
// currentBlock - N >= finalityThreshold; otherwise it is
// StatusPending. This defends against reorgs and non-canonical
// blocks: a root that appears on chain but is later reorged away will
// not reach the threshold before the reorg, so a verifier that waits
// for the threshold will not report it as committed.
//
// # Read-only RPC
//
// The on-chain root lookup is a read-only eth_call per [EIP-1474]. It
// does not change chain state, consume gas, or submit transactions.
// The proof package performs no writes, no event indexing, and no
// state mutation — those are operator concerns.
//
// # Verification is pure over the proof and the on-chain root
//
// VerifyChainProof takes a ChainProof and a VerifyOptions that injects
// the on-chain root lookup and current block number. Everything the
// verifier needs comes from the proof bytes and the injected lookup;
// no database, no global state. The lookup is an interface so
// verification is testable without a live EVM node.
package proof
