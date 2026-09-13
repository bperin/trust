// Package broadcast composes the send-and-wait flow for EVM
// transactions over a JSON-RPC 2.0 provider. It wires chain/rpc.Client
// to two operations: SendTx broadcasts a signed raw transaction via
// eth_sendRawTransaction, and WaitForReceipt polls eth_getTransactionReceipt
// until the transaction is mined or the context is cancelled.
//
// The package owns no transport. chain/rpc keeps the JSON-RPC client
// untyped — GetTransactionReceipt returns interface{} — so this package
// is the typed boundary that extracts a Receipt struct from the
// provider's JSON shape using ParseQuantity and ParseBlockNumber from
// chain/rpc for hex field decoding.
//
// Per [EIP-1474] (Remote Procedure Call Specification),
// eth_sendRawTransaction and eth_getTransactionReceipt are standard EVM
// RPC methods. Per [JSON-RPC 2.0] §4, every request carries a numeric id
// echoed in the response; the underlying client handles that matching.
//
// [EIP-1474]: https://eips.ethereum.org/EIPS/eip-1474
// [JSON-RPC 2.0]: https://www.jsonrpc.org/specification
package broadcast

import (
	"context"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/bperin/trust/chain/rpc"
)

// DefaultPollInterval is the interval WaitForReceipt polls
// eth_getTransactionReceipt when no WithPollInterval option is supplied.
const DefaultPollInterval = 2 * time.Second

// Receipt is the typed form of the eth_getTransactionReceipt response.
//
// Per [EIP-1474], the receipt object carries the post-execution state
// of a transaction: its status, the block it was mined in, gas used, and
// emitted logs. The fields are decoded from the provider's JSON shape
// (map[string]interface{}) using ParseQuantity and ParseBlockNumber from
// chain/rpc for the hex-encoded numeric fields.
//
// [EIP-1474]: https://eips.ethereum.org/EIPS/eip-1474
type Receipt struct {
	// Status is the post-transaction execution status: 1 for
	// success, 0 for failure (EIP-658). Decoded from the hex
	// quantity "status" field.
	Status uint64
	// BlockHash is the hash of the block that mined the
	// transaction, as a 0x-prefixed hex string.
	BlockHash string
	// BlockNumber is the block height that mined the transaction,
	// decoded from the hex quantity "blockNumber" field.
	BlockNumber uint64
	// TransactionHash is the hash of the transaction, as a
	// 0x-prefixed hex string.
	TransactionHash string
	// TransactionIndex is the index of the transaction within
	// its block, decoded from the hex quantity
	// "transactionIndex" field.
	TransactionIndex uint64
	// GasUsed is the gas consumed by the transaction, decoded
	// from the hex quantity "gasUsed" field.
	GasUsed uint64
	// ContractAddress is the address of a contract created by
	// the transaction, or the empty string when none was
	// created. Returned as a 0x-prefixed hex string.
	ContractAddress string
	// Logs is the list of log entries emitted by the
	// transaction. The provider returns these as an untyped
	// array; they are passed through as []interface{} so the
	// caller decodes the provider's log shape.
	Logs []interface{}
}

// WaitOption is a functional option for WaitForReceipt.
type WaitOption func(*waitConfig)

// waitConfig holds the resolved options for a WaitForReceipt call.
type waitConfig struct {
	pollInterval time.Duration
}

// WithPollInterval sets the interval at which WaitForReceipt polls
// eth_getTransactionReceipt. The default is DefaultPollInterval (2s).
// A non-positive duration is ignored, leaving the default in place.
func WithPollInterval(d time.Duration) WaitOption {
	return func(c *waitConfig) {
		if d > 0 {
			c.pollInterval = d
		}
	}
}

// newWaitConfig builds a waitConfig from the supplied options, applying
// the default poll interval before options run.
func newWaitConfig(opts []WaitOption) waitConfig {
	c := waitConfig{pollInterval: DefaultPollInterval}
	for _, opt := range opts {
		opt(&c)
	}
	return c
}

// SendTx broadcasts a signed raw transaction via eth_sendRawTransaction.
//
// rawTx is the signed RLP-encoded transaction bytes. It is hex-encoded
// with a "0x" prefix per [EIP-1474] before being passed to
// client.SendRawTransaction. The returned string is the transaction
// hash reported by the node.
//
// RPC errors from the client are wrapped with fmt.Errorf and %w so
// callers can recover the underlying *rpc.RPCError via errors.As.
//
// [EIP-1474]: https://eips.ethereum.org/EIPS/eip-1474
func SendTx(ctx context.Context, client rpc.Client, rawTx []byte) (string, error) {
	if client == nil {
		return "", fmt.Errorf("broadcast: nil rpc client")
	}
	hexStr := "0x" + hex.EncodeToString(rawTx)
	hash, err := client.SendRawTransaction(ctx, hexStr)
	if err != nil {
		return "", fmt.Errorf("broadcast: send raw transaction: %w", err)
	}
	return hash, nil
}

// WaitForReceipt polls eth_getTransactionReceipt at a fixed interval
// until the transaction is mined and a receipt is available, or until
// ctx is cancelled.
//
// The poll loop uses time.NewTicker and selects on the ticker channel
// and ctx.Done(); there is no separate timeout parameter — context
// cancellation is the only timeout. When the receipt is not yet mined
// (the RPC returns a nil interface), the loop continues polling. When
// the receipt is available, it is decoded into a typed *Receipt and
// returned.
//
// WaitForReceipt holds no shared mutable state and is safe under the
// race detector. An already-cancelled context returns immediately with
// the context error.
//
// Per [EIP-1474], eth_getTransactionReceipt returns null until the
// transaction is mined; this package treats that nil as "keep polling".
//
// [EIP-1474]: https://eips.ethereum.org/EIPS/eip-1474
func WaitForReceipt(ctx context.Context, client rpc.Client, txHash string, opts ...WaitOption) (*Receipt, error) {
	if client == nil {
		return nil, fmt.Errorf("broadcast: nil rpc client")
	}
	cfg := newWaitConfig(opts)

	// An already-cancelled context returns immediately without
	// allocating a ticker.
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	ticker := time.NewTicker(cfg.pollInterval)
	defer ticker.Stop()

	for {
		raw, err := client.GetTransactionReceipt(ctx, txHash)
		if err != nil {
			return nil, fmt.Errorf("broadcast: get transaction receipt: %w", err)
		}
		if raw != nil {
			return parseReceipt(raw)
		}

		select {
		case <-ticker.C:
			// poll again
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
}

// parseReceipt decodes the interface{} returned by
// eth_getTransactionReceipt into a typed *Receipt.
//
// The provider returns the receipt as a JSON object, which the RPC
// client decodes into a map[string]interface{}. Numeric fields are hex
// quantities per [EIP-1474] and are parsed with ParseQuantity and
// ParseBlockNumber from chain/rpc. A response that is not a
// map[string]interface{} is rejected with an error.
//
// [EIP-1474]: https://eips.ethereum.org/EIPS/eip-1474
func parseReceipt(raw interface{}) (*Receipt, error) {
	m, ok := raw.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("broadcast: receipt is %T, want map[string]interface{}", raw)
	}

	r := &Receipt{}

	if v, ok := m["status"].(string); ok && v != "" {
		n, err := rpc.ParseBlockNumber(v)
		if err != nil {
			return nil, fmt.Errorf("broadcast: parse status: %w", err)
		}
		r.Status = n
	}

	if v, ok := m["blockHash"].(string); ok {
		r.BlockHash = v
	}

	if v, ok := m["blockNumber"].(string); ok && v != "" {
		n, err := rpc.ParseBlockNumber(v)
		if err != nil {
			return nil, fmt.Errorf("broadcast: parse blockNumber: %w", err)
		}
		r.BlockNumber = n
	}

	if v, ok := m["transactionHash"].(string); ok {
		r.TransactionHash = v
	}

	if v, ok := m["transactionIndex"].(string); ok && v != "" {
		n, err := rpc.ParseBlockNumber(v)
		if err != nil {
			return nil, fmt.Errorf("broadcast: parse transactionIndex: %w", err)
		}
		r.TransactionIndex = n
	}

	if v, ok := m["gasUsed"].(string); ok && v != "" {
		n, err := rpc.ParseBlockNumber(v)
		if err != nil {
			return nil, fmt.Errorf("broadcast: parse gasUsed: %w", err)
		}
		r.GasUsed = n
	}

	if v, ok := m["contractAddress"].(string); ok {
		r.ContractAddress = v
	}

	if v, ok := m["logs"].([]interface{}); ok {
		r.Logs = v
	}

	return r, nil
}
