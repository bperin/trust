package rpc

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync/atomic"
	"time"
)

// DefaultTimeout is the per-call timeout used when no WithTimeout
// option is supplied.
const DefaultTimeout = 30 * time.Second

// DefaultMaxResponseBytes is the response body size limit used when
// no WithMaxResponseBytes option is supplied.
const DefaultMaxResponseBytes = 8 << 20 // 8 MiB

// ErrResponseTooLarge is returned when a JSON-RPC response body
// exceeds the configured maximum size. Checked with errors.Is.
var ErrResponseTooLarge = errStr("rpc: response exceeds maximum size")

// HTTPClient is a JSON-RPC 2.0 client over HTTP. It is safe for
// concurrent use: request ids are assigned atomically and the embedded
// *http.Client is goroutine-safe. Responses whose id does not match
// the request are rejected.
type HTTPClient struct {
	// endpoint is the JSON-RPC endpoint URL.
	endpoint string
	// httpc is the HTTP transport client.
	httpc *http.Client
	// id is the request id counter, accessed atomically.
	id atomic.Int64
	// timeout is the per-call deadline bound.
	timeout time.Duration
	// maxResponseBytes is the maximum accepted response body size.
	maxResponseBytes int64
}

// HTTPOption is a functional option for NewHTTPClient.
type HTTPOption func(*HTTPClient)

// WithTimeout sets the per-call timeout; a shorter caller deadline
// still applies. A non-positive d is ignored.
func WithTimeout(d time.Duration) HTTPOption {
	return func(c *HTTPClient) {
		if d > 0 {
			c.timeout = d
		}
	}
}

// WithMaxResponseBytes sets the maximum accepted size of a response
// body. Larger responses are rejected with ErrResponseTooLarge. A
// non-positive n is ignored.
func WithMaxResponseBytes(n int64) HTTPOption {
	return func(c *HTTPClient) {
		if n > 0 {
			c.maxResponseBytes = n
		}
	}
}

// WithHTTPClient sets the underlying HTTP transport client, allowing
// a custom Transport (TLS configuration, proxies, instrumentation).
// A nil c is ignored.
func WithHTTPClient(c *http.Client) HTTPOption {
	return func(h *HTTPClient) {
		if c != nil {
			h.httpc = c
		}
	}
}

// NewHTTPClient returns an HTTPClient for the given endpoint URL.
// With no options it uses the default http.Client, DefaultTimeout,
// and DefaultMaxResponseBytes.
func NewHTTPClient(url string, opts ...HTTPOption) *HTTPClient {
	c := &HTTPClient{
		endpoint:         url,
		httpc:            &http.Client{},
		timeout:          DefaultTimeout,
		maxResponseBytes: DefaultMaxResponseBytes,
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

// rpcRequest is the JSON-RPC 2.0 request object.
type rpcRequest struct {
	JSONRPC string      `json:"jsonrpc"`
	ID      int64       `json:"id"`
	Method  string      `json:"method"`
	Params  interface{} `json:"params"`
}

// rpcResponse is the JSON-RPC 2.0 response object.
type rpcResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      int64           `json:"id"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *RPCError       `json:"error,omitempty"`
}

// call sends a JSON-RPC 2.0 request and decodes the result into the
// provided result pointer. A server error object is returned as an
// *RPCError. The call is bounded by the configured timeout, the
// response id must match the request id, and the response body is
// bounded by maxResponseBytes.
func (c *HTTPClient) call(ctx context.Context, method string, params interface{}, result interface{}) error {
	// Bound the call. context.WithTimeout takes the earlier of the
	// caller's deadline and the client timeout, so a shorter caller
	// deadline still wins and a caller context with no deadline is
	// clamped to the client bound.
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	id := c.id.Add(1)
	req := rpcRequest{
		JSONRPC: "2.0",
		ID:      id,
		Method:  method,
		Params:  params,
	}
	body, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("rpc: marshal request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("rpc: build request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := c.httpc.Do(httpReq)
	if err != nil {
		return fmt.Errorf("rpc: http: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("rpc: http status %d", resp.StatusCode)
	}

	// Read at most maxResponseBytes+1 bytes so an oversized body is
	// detected exactly instead of being truncated mid-stream.
	raw, err := io.ReadAll(io.LimitReader(resp.Body, c.maxResponseBytes+1))
	if err != nil {
		return fmt.Errorf("rpc: read response: %w", err)
	}
	if int64(len(raw)) > c.maxResponseBytes {
		return fmt.Errorf("rpc: response body exceeds %d bytes: %w", c.maxResponseBytes, ErrResponseTooLarge)
	}

	var rpcResp rpcResponse
	if err := json.Unmarshal(raw, &rpcResp); err != nil {
		return fmt.Errorf("rpc: decode response: %w", err)
	}

	// Id matching: reject responses whose id does not match the
	// request id. This defends against response injection.
	if rpcResp.ID != id {
		return fmt.Errorf("rpc: response id mismatch: got %d, want %d", rpcResp.ID, id)
	}

	if rpcResp.Error != nil {
		return rpcResp.Error
	}

	if result != nil {
		if err := json.Unmarshal(rpcResp.Result, result); err != nil {
			return fmt.Errorf("rpc: decode result: %w", err)
		}
	}
	return nil
}

// ChainID calls eth_chainId and returns the chain ID as a hex string.
func (c *HTTPClient) ChainID(ctx context.Context) (string, error) {
	var result string
	if err := c.call(ctx, "eth_chainId", nil, &result); err != nil {
		return "", err
	}
	return result, nil
}

// GetTransactionCount calls eth_getTransactionCount and returns the
// account nonce as a hex string.
func (c *HTTPClient) GetTransactionCount(ctx context.Context, addr string, blockTag string) (string, error) {
	var result string
	params := []interface{}{addr, blockTag}
	if err := c.call(ctx, "eth_getTransactionCount", params, &result); err != nil {
		return "", err
	}
	return result, nil
}

// EstimateGas calls eth_estimateGas and returns the gas estimate as
// a hex string.
func (c *HTTPClient) EstimateGas(ctx context.Context, tx map[string]interface{}) (string, error) {
	var result string
	params := []interface{}{tx}
	if err := c.call(ctx, "eth_estimateGas", params, &result); err != nil {
		return "", err
	}
	return result, nil
}

// GasPrice calls eth_gasPrice and returns the current gas price as a
// hex string.
func (c *HTTPClient) GasPrice(ctx context.Context) (string, error) {
	var result string
	if err := c.call(ctx, "eth_gasPrice", nil, &result); err != nil {
		return "", err
	}
	return result, nil
}

// MaxPriorityFeePerGas calls eth_maxPriorityFeePerGas and returns the
// priority fee suggestion as a hex string.
func (c *HTTPClient) MaxPriorityFeePerGas(ctx context.Context) (string, error) {
	var result string
	if err := c.call(ctx, "eth_maxPriorityFeePerGas", nil, &result); err != nil {
		return "", err
	}
	return result, nil
}

// FeeHistory calls eth_feeHistory and returns the fee history object.
func (c *HTTPClient) FeeHistory(ctx context.Context, blockCount string, newestBlock string, rewardPercentiles []float64) (interface{}, error) {
	var result interface{}
	params := []interface{}{blockCount, newestBlock, rewardPercentiles}
	if err := c.call(ctx, "eth_feeHistory", params, &result); err != nil {
		return nil, err
	}
	return result, nil
}

// SendRawTransaction calls eth_sendRawTransaction and returns the
// transaction hash.
func (c *HTTPClient) SendRawTransaction(ctx context.Context, rawTx string) (string, error) {
	var result string
	params := []interface{}{rawTx}
	if err := c.call(ctx, "eth_sendRawTransaction", params, &result); err != nil {
		return "", err
	}
	return result, nil
}

// GetTransactionReceipt calls eth_getTransactionReceipt and returns
// the receipt object, or nil if not yet mined.
func (c *HTTPClient) GetTransactionReceipt(ctx context.Context, txHash string) (interface{}, error) {
	var result interface{}
	params := []interface{}{txHash}
	if err := c.call(ctx, "eth_getTransactionReceipt", params, &result); err != nil {
		return nil, err
	}
	return result, nil
}

// GetTransactionByHash calls eth_getTransactionByHash and returns the
// transaction object, or nil if unknown.
func (c *HTTPClient) GetTransactionByHash(ctx context.Context, txHash string) (interface{}, error) {
	var result interface{}
	params := []interface{}{txHash}
	if err := c.call(ctx, "eth_getTransactionByHash", params, &result); err != nil {
		return nil, err
	}
	return result, nil
}

// BlockNumber calls eth_blockNumber and returns the head block
// number as a hex string.
func (c *HTTPClient) BlockNumber(ctx context.Context) (string, error) {
	var result string
	if err := c.call(ctx, "eth_blockNumber", nil, &result); err != nil {
		return "", err
	}
	return result, nil
}

// Call calls eth_call with the transaction-call object at blockTag
// and returns the hex result.
func (c *HTTPClient) Call(ctx context.Context, call map[string]interface{}, blockTag string) (string, error) {
	var result string
	params := []interface{}{call, blockTag}
	if err := c.call(ctx, "eth_call", params, &result); err != nil {
		return "", err
	}
	return result, nil
}

// Compile-time interface check: HTTPClient implements Client.
var _ Client = (*HTTPClient)(nil)
