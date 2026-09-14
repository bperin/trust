// Package rpc is a provider-agnostic JSON-RPC 2.0 client for EVM
// nodes. It implements the transport layer only — no crypto, no
// transaction types, no vendor-specific APIs. Any JSON-RPC 2.0
// endpoint works: a local geth node, Alchemy, Infura, QuickNode.
//
// The Client interface covers nine EVM methods (eth_chainId,
// eth_getTransactionCount, eth_estimateGas, eth_gasPrice,
// eth_maxPriorityFeePerGas, eth_feeHistory, eth_sendRawTransaction,
// eth_getTransactionReceipt, eth_getTransactionByHash). The single
// concrete implementation, HTTPClient, round-trips requests over
// HTTP and additionally exposes BlockNumber (eth_blockNumber) and
// Call (eth_call), which are transport methods not part of Client.
// The interface exists so consumer-side tests can mock the RPC
// endpoint without a live server — it decouples callers from HTTP
// transport details.
//
// Per [JSON-RPC 2.0] §4, every request carries a numeric id and every
// response echoes it. HTTPClient matches the response id to the
// request id and rejects mismatches — a response with an unexpected id
// is treated as an injection and fails the call.
//
// [JSON-RPC 2.0]: https://www.jsonrpc.org/specification
package rpc

import (
	"context"
	"strconv"
)

// RPCError is a JSON-RPC 2.0 error object returned by the server.
//
// Per [JSON-RPC 2.0] §5.1, the error object carries a Code and a
// Message. Code is server-defined; the reserved range -32000 to -32099
// covers implementation-defined server errors (e.g. revert, nonce too
// low). RPCError implements the error interface so callers can type-
// assert or use errors.As to recover the code.
//
// [JSON-RPC 2.0]: https://www.jsonrpc.org/specification
type RPCError struct {
	// Code is the JSON-RPC error code. Server errors use the
	// -32000 to -32099 reserved range; application codes vary.
	Code int
	// Message is the server-supplied human-readable error
	// description. It is not localized and must not be parsed as
	// structured data.
	Message string
}

// Error implements the error interface. The string form is
// "rpc: code <Code>: <Message>".
func (e *RPCError) Error() string {
	return "rpc: code " + strconv.Itoa(e.Code) + ": " + e.Message
}

// Client is a provider-agnostic JSON-RPC 2.0 client for EVM methods.
//
// The interface covers nine methods: chain id, nonce lookup, gas
// estimation, fee oracle queries, raw transaction broadcast, and
// transaction/receipt lookup. All methods take a context as the
// first parameter for cancellation and timeouts. Hex-string results
// are returned as strings; structured results (fee history, receipts,
// transactions) are returned as interface{} so the caller decodes the
// provider's JSON shape.
//
// The interface has one concrete implementation, HTTPClient. It
// exists for mock testability: consumer-side tests can substitute a
// fake without a live server, and callers are decoupled from HTTP
// transport details.
//
// Per [EIP-1474] (Remote Procedure Call Specification), these methods
// are the standard EVM RPC surface. eth_call and eth_blockNumber are
// not included here — consumer-side callers keep their own RPCClient
// for those.
//
// [JSON-RPC 2.0]: https://www.jsonrpc.org/specification
type Client interface {
	// ChainID calls eth_chainId and returns the chain id as a
	// hex string (e.g. "0x1" for Ethereum mainnet). Per [EIP-695].
	ChainID(ctx context.Context) (string, error)

	// GetTransactionCount calls eth_getTransactionCount and
	// returns the account nonce as a hex string. blockTag is
	// "latest", "earliest", "pending", or a hex block number.
	// Per [EIP-1474].
	GetTransactionCount(ctx context.Context, addr string, blockTag string) (string, error)

	// EstimateGas calls eth_estimateGas for the given transaction
	// call object and returns the gas estimate as a hex string.
	// Per [EIP-1474].
	EstimateGas(ctx context.Context, tx map[string]interface{}) (string, error)

	// GasPrice calls eth_gasPrice and returns the current gas
	// price as a hex string. Per [EIP-1474].
	GasPrice(ctx context.Context) (string, error)

	// MaxPriorityFeePerGas calls eth_maxPriorityFeePerGas and
	// returns the priority fee suggestion as a hex string.
	// Per [EIP-1559].
	MaxPriorityFeePerGas(ctx context.Context) (string, error)

	// FeeHistory calls eth_feeHistory and returns the fee history
	// object. blockCount is a hex string; newestBlock is a block
	// tag; rewardPercentiles are floats in [0,100]. Per [EIP-1559].
	FeeHistory(ctx context.Context, blockCount string, newestBlock string, rewardPercentiles []float64) (interface{}, error)

	// SendRawTransaction calls eth_sendRawTransaction with the
	// signed raw transaction bytes (hex-encoded, 0x-prefixed) and
	// returns the transaction hash as a hex string. Per [EIP-1474].
	SendRawTransaction(ctx context.Context, rawTx string) (string, error)

	// GetTransactionReceipt calls eth_getTransactionReceipt and
	// returns the receipt object, or nil if the transaction is
	// not yet mined. Per [EIP-1474].
	GetTransactionReceipt(ctx context.Context, txHash string) (interface{}, error)

	// GetTransactionByHash calls eth_getTransactionByHash and
	// returns the transaction object, or nil if unknown. Per
	// [EIP-1474].
	GetTransactionByHash(ctx context.Context, txHash string) (interface{}, error)
}
