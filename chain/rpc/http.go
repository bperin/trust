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

// DefaultTimeout is the per-call timeout applied when no WithTimeout
// option is supplied. Every RPC call is bounded: call wraps the
// caller's context with this deadline, so a call can never block
// indefinitely even when the caller passes a context with no
// deadline.
const DefaultTimeout = 30 * time.Second

// DefaultMaxResponseBytes is the response body size limit applied
// when no WithMaxResponseBytes option is supplied. A response larger
// than the limit is rejected with ErrResponseTooLarge before it is
// decoded, bounding memory use against a hostile or malfunctioning
// endpoint.
const DefaultMaxResponseBytes = 8 << 20 // 8 MiB

// ErrResponseTooLarge is returned when a JSON-RPC response body
// exceeds the configured maximum size (see WithMaxResponseBytes and
// DefaultMaxResponseBytes). Checked with errors.Is.
var ErrResponseTooLarge = errStr("rpc: response exceeds maximum size")

// HTTPClient is a JSON-RPC 2.0 client over HTTP. It is the single
// concrete implementation of the Client interface. One client is safe
// for concurrent use: the request id counter is incremented atomically,
// and the embedded *http.Client is goroutine-safe.
//
// Per [JSON-RPC 2.0] §4, each request carries a unique numeric id and
// each response echoes it. call matches the response id to the request
// id and rejects mismatches — a response with an unexpected id is
// treated as an injection and fails the call.
//
// [JSON-RPC 2.0]: https://www.jsonrpc.org/specification
type HTTPClient struct {
	// endpoint is the JSON-RPC 2.0 endpoint URL.
	endpoint string
	// httpc is the HTTP client used for transport. It is
	// goroutine-safe.
	httpc *http.Client
	// id is the monotonically increasing request id counter.
	// Accessed atomically; the first id is 1.
	id atomic.Int64
	// timeout is the per-call deadline bound. call wraps the
	// caller's context with context.WithTimeout using this value,
	// so no call is ever unbounded. Always positive.
	timeout time.Duration
	// maxResponseBytes is the maximum accepted size of a response
	// body. Larger responses are rejected with ErrResponseTooLarge.
	// Always positive.
	maxResponseBytes int64
}

// HTTPOption is a functional option for NewHTTPClient.
type HTTPOption func(*HTTPClient)

// WithTimeout sets the per-call timeout. Each call wraps the caller's
// context with this deadline via context.WithTimeout: a shorter
// caller deadline still applies, and a caller context with no
// deadline is bounded by this value — an HTTPClient can never issue
// an unbounded call. A non-positive d is ignored, retaining the
// current timeout.
func WithTimeout(d time.Duration) HTTPOption {
	return func(c *HTTPClient) {
		if d > 0 {
			c.timeout = d
		}
	}
}

// WithMaxResponseBytes sets the maximum accepted size in bytes of a
// JSON-RPC response body. Larger responses are rejected with
// ErrResponseTooLarge before decoding. A non-positive n is ignored,
// retaining the current bound.
func WithMaxResponseBytes(n int64) HTTPOption {
	return func(c *HTTPClient) {
		if n > 0 {
			c.maxResponseBytes = n
		}
	}
}

// WithHTTPClient sets the underlying HTTP transport client, allowing
// callers to supply a custom Transport (TLS configuration, proxies,
// instrumentation). A nil c is ignored. The per-call timeout is
// enforced by call through the request context, independent of the
// transport's own settings, so supplying a client with no Timeout
// field does not weaken the bound.
func WithHTTPClient(c *http.Client) HTTPOption {
	return func(h *HTTPClient) {
		if c != nil {
			h.httpc = c
		}
	}
}

// NewHTTPClient returns an HTTPClient for the given JSON-RPC 2.0
// endpoint URL. With no options it uses the default http.Client, a
// per-call timeout of DefaultTimeout, and a response bound of
// DefaultMaxResponseBytes. The client is safe for concurrent use.
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
//
// Per [JSON-RPC 2.0] §4.0, a request has jsonrpc, id, method, and
// params. params may be omitted (nil) when the method takes none.
type rpcRequest struct {
	JSONRPC string      `json:"jsonrpc"`
	ID      int64       `json:"id"`
	Method  string      `json:"method"`
	Params  interface{} `json:"params"`
}

// rpcResponse is the JSON-RPC 2.0 response object.
//
// Per [JSON-RPC 2.0] §5.0, a response has jsonrpc, id, and either a
// result or an error. result is decoded into the caller-supplied
// pointer by call.
type rpcResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      int64           `json:"id"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *RPCError       `json:"error,omitempty"`
}

// call sends a JSON-RPC 2.0 request and decodes the response.
//
// It builds the request, POSTs it to the endpoint with
// Content-Type: application/json, matches the response id to the
// request id, and decodes the result into the provided result pointer.
// If the server returns an error object, call returns it as an
// *RPCError. A mismatched response id, HTTP error, malformed JSON, or
// cancelled context all produce a non-nil error.
//
// Per [JSON-RPC 2.0] §4.1, the id is a number. Per §5.1, the error
// object carries code and message. Id matching is mandatory: a
// response whose id does not match the request id is rejected as a
// potential injection.
//
// Every call is bounded twice: the caller's context is wrapped with
// the configured timeout (context.WithTimeout), and the response
// body is read through io.LimitReader so an oversized body is
// rejected with ErrResponseTooLarge rather than decoded.
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

// ChainID calls eth_chainId. Per [EIP-695].
func (c *HTTPClient) ChainID(ctx context.Context) (string, error) {
	var result string
	if err := c.call(ctx, "eth_chainId", nil, &result); err != nil {
		return "", err
	}
	return result, nil
}

// GetTransactionCount calls eth_getTransactionCount. Per [EIP-1474].
func (c *HTTPClient) GetTransactionCount(ctx context.Context, addr string, blockTag string) (string, error) {
	var result string
	params := []interface{}{addr, blockTag}
	if err := c.call(ctx, "eth_getTransactionCount", params, &result); err != nil {
		return "", err
	}
	return result, nil
}

// EstimateGas calls eth_estimateGas. Per [EIP-1474].
func (c *HTTPClient) EstimateGas(ctx context.Context, tx map[string]interface{}) (string, error) {
	var result string
	params := []interface{}{tx}
	if err := c.call(ctx, "eth_estimateGas", params, &result); err != nil {
		return "", err
	}
	return result, nil
}

// GasPrice calls eth_gasPrice. Per [EIP-1474].
func (c *HTTPClient) GasPrice(ctx context.Context) (string, error) {
	var result string
	if err := c.call(ctx, "eth_gasPrice", nil, &result); err != nil {
		return "", err
	}
	return result, nil
}

// MaxPriorityFeePerGas calls eth_maxPriorityFeePerGas. Per [EIP-1559].
func (c *HTTPClient) MaxPriorityFeePerGas(ctx context.Context) (string, error) {
	var result string
	if err := c.call(ctx, "eth_maxPriorityFeePerGas", nil, &result); err != nil {
		return "", err
	}
	return result, nil
}

// FeeHistory calls eth_feeHistory. Per [EIP-1559].
func (c *HTTPClient) FeeHistory(ctx context.Context, blockCount string, newestBlock string, rewardPercentiles []float64) (interface{}, error) {
	var result interface{}
	params := []interface{}{blockCount, newestBlock, rewardPercentiles}
	if err := c.call(ctx, "eth_feeHistory", params, &result); err != nil {
		return nil, err
	}
	return result, nil
}

// SendRawTransaction calls eth_sendRawTransaction. Per [EIP-1474].
func (c *HTTPClient) SendRawTransaction(ctx context.Context, rawTx string) (string, error) {
	var result string
	params := []interface{}{rawTx}
	if err := c.call(ctx, "eth_sendRawTransaction", params, &result); err != nil {
		return "", err
	}
	return result, nil
}

// GetTransactionReceipt calls eth_getTransactionReceipt. Per [EIP-1474].
func (c *HTTPClient) GetTransactionReceipt(ctx context.Context, txHash string) (interface{}, error) {
	var result interface{}
	params := []interface{}{txHash}
	if err := c.call(ctx, "eth_getTransactionReceipt", params, &result); err != nil {
		return nil, err
	}
	return result, nil
}

// GetTransactionByHash calls eth_getTransactionByHash. Per [EIP-1474].
func (c *HTTPClient) GetTransactionByHash(ctx context.Context, txHash string) (interface{}, error) {
	var result interface{}
	params := []interface{}{txHash}
	if err := c.call(ctx, "eth_getTransactionByHash", params, &result); err != nil {
		return nil, err
	}
	return result, nil
}

// Compile-time interface check: HTTPClient implements Client.
var _ Client = (*HTTPClient)(nil)
