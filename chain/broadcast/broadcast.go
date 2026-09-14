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
	"errors"
	"fmt"
	"time"

	"github.com/bperin/trust/chain/rpc"
)

// DefaultPollInterval is the interval WaitForReceipt polls
// eth_getTransactionReceipt when no WithPollInterval option is supplied.
const DefaultPollInterval = 2 * time.Second

// ErrMalformedReceipt is returned when an eth_getTransactionReceipt
// response is not a JSON object, is missing a field required by
// [EIP-1474], or carries a field of the wrong type. Checked with
// errors.Is.
//
// [EIP-1474]: https://eips.ethereum.org/EIPS/eip-1474
var ErrMalformedReceipt = errors.New("broadcast: malformed receipt")

// requiredReceiptFields lists the receipt fields [EIP-1474] requires
// on a mined transaction. Every field the Receipt type models is
// mandatory: a response missing one is rejected rather than decoded
// with a silent zero value that would pass for a real receipt.
//
// [EIP-1474]: https://eips.ethereum.org/EIPS/eip-1474
var requiredReceiptFields = []string{
	"status",
	"blockHash",
	"blockNumber",
	"transactionHash",
	"transactionIndex",
	"gasUsed",
	"contractAddress",
	"logs",
}

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
// client decodes into a map[string]interface{}. A response that is
// not a map, or that is missing a required [EIP-1474] field, is
// rejected with ErrMalformedReceipt — a mined receipt always carries
// the full field set, so an absent key means a truncated or hostile
// response, not a zero value. Numeric fields are hex quantities
// parsed with ParseBlockNumber from chain/rpc.
//
// [EIP-1474]: https://eips.ethereum.org/EIPS/eip-1474
func parseReceipt(raw interface{}) (*Receipt, error) {
	m, ok := raw.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("broadcast: %w: got %T, want object", ErrMalformedReceipt, raw)
	}

	// Every required field must be present before any decoding.
	for _, key := range requiredReceiptFields {
		if _, ok := m[key]; !ok {
			return nil, fmt.Errorf("broadcast: %w: missing required field %q", ErrMalformedReceipt, key)
		}
	}

	r := &Receipt{}

	status, err := receiptString(m, "status")
	if err != nil {
		return nil, err
	}
	r.Status, err = rpc.ParseBlockNumber(status)
	if err != nil {
		return nil, fmt.Errorf("broadcast: %w: parse status: %w", ErrMalformedReceipt, err)
	}

	r.BlockHash, err = receiptString(m, "blockHash")
	if err != nil {
		return nil, err
	}

	blockNumber, err := receiptString(m, "blockNumber")
	if err != nil {
		return nil, err
	}
	r.BlockNumber, err = rpc.ParseBlockNumber(blockNumber)
	if err != nil {
		return nil, fmt.Errorf("broadcast: %w: parse blockNumber: %w", ErrMalformedReceipt, err)
	}

	r.TransactionHash, err = receiptString(m, "transactionHash")
	if err != nil {
		return nil, err
	}

	txIndex, err := receiptString(m, "transactionIndex")
	if err != nil {
		return nil, err
	}
	r.TransactionIndex, err = rpc.ParseBlockNumber(txIndex)
	if err != nil {
		return nil, fmt.Errorf("broadcast: %w: parse transactionIndex: %w", ErrMalformedReceipt, err)
	}

	gasUsed, err := receiptString(m, "gasUsed")
	if err != nil {
		return nil, err
	}
	r.GasUsed, err = rpc.ParseBlockNumber(gasUsed)
	if err != nil {
		return nil, fmt.Errorf("broadcast: %w: parse gasUsed: %w", ErrMalformedReceipt, err)
	}

	// contractAddress is null for transactions that created no
	// contract; some providers emit an empty string instead. Both
	// decode to the empty string.
	switch v := m["contractAddress"].(type) {
	case nil:
		// JSON null: no contract created.
	case string:
		r.ContractAddress = v
	default:
		return nil, fmt.Errorf("broadcast: %w: field %q is %T, want string or null", ErrMalformedReceipt, "contractAddress", v)
	}

	logs, ok := m["logs"].([]interface{})
	if !ok {
		return nil, fmt.Errorf("broadcast: %w: field %q is %T, want array", ErrMalformedReceipt, "logs", m["logs"])
	}
	r.Logs = logs

	return r, nil
}

// receiptString returns field key of m as a non-empty string, or an
// error wrapping ErrMalformedReceipt when the field is missing, is
// not a string, or is empty. The presence check is redundant after
// the required-field loop but keeps the helper self-contained.
func receiptString(m map[string]interface{}, key string) (string, error) {
	v, ok := m[key]
	if !ok {
		return "", fmt.Errorf("broadcast: %w: missing required field %q", ErrMalformedReceipt, key)
	}
	s, ok := v.(string)
	if !ok || s == "" {
		return "", fmt.Errorf("broadcast: %w: field %q is %v, want non-empty string", ErrMalformedReceipt, key, v)
	}
	return s, nil
}
