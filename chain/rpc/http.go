package rpc

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync/atomic"
)

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
}

// NewHTTPClient returns an HTTPClient for the given JSON-RPC 2.0
// endpoint URL. It uses the default http.Client. The client is safe
// for concurrent use.
func NewHTTPClient(url string) *HTTPClient {
	return &HTTPClient{
		endpoint: url,
		httpc:    &http.Client{},
	}
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
func (c *HTTPClient) call(ctx context.Context, method string, params interface{}, result interface{}) error {
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

	var rpcResp rpcResponse
	if err := json.NewDecoder(resp.Body).Decode(&rpcResp); err != nil {
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
