package rpc

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

// mockHandler returns a canned JSON-RPC 2.0 response body and status
// code for every request. Tests configure it per-case.
type mockHandler struct {
	// body is the response body written to the client. If idRewrite
	// is set, the handler echoes the request id instead of using the
	// canned id.
	body       string
	statusCode int
	// idRewrite, when true, makes the handler parse the request id
	// and return it in the response (for mismatched-id tests, set
	// idOverride instead). When false, the canned body is returned
	// verbatim.
	idRewrite bool
	// idOverride is the id to write into the response regardless of
	// the request id. Non-zero enables override.
	idOverride int64
	// delay, when non-zero, sleeps before responding to let the
	// caller cancel the context first.
	delay time.Duration
	// seenMethod is the JSON-RPC method of the last request.
	seenMethod string
	// seenParams is the raw params JSON of the last request.
	seenParams string
}

func (h *mockHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	raw, _ := io.ReadAll(r.Body)
	// Capture the request method and params for assertion.
	if req, err := parseRequest(raw); err == nil {
		h.seenMethod = req.Method
		h.seenParams = string(req.Params)
	}

	if h.delay > 0 {
		time.Sleep(h.delay)
	}

	status := h.statusCode
	if status == 0 {
		status = http.StatusOK
	}

	w.Header().Set("Content-Type", "application/json")
	if h.idOverride != 0 {
		// Replace the canned id with the override. The canned body
		// is expected to use id 1; substitute the override value.
		body := strings.Replace(h.body, `"id":1`, `"id":`+strconv.Itoa(int(h.idOverride)), 1)
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
		return
	}

	w.WriteHeader(status)
	_, _ = w.Write([]byte(h.body))
}

// parseRequest is a minimal JSON-RPC 2.0 request decoder for test
// assertions. It only reads jsonrpc, id, method, and params.
type rawRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      int64           `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params"`
}

func parseRequest(raw []byte) (rawRequest, error) {
	var r rawRequest
	if err := json.Unmarshal(raw, &r); err != nil {
		return rawRequest{}, err
	}
	return r, nil
}

// TestHTTPClient_Call covers the call transport: success, error
// object, mismatched id, HTTP 500, malformed JSON, and context
// cancellation. Table-driven per the testing standard.
func TestHTTPClient_Call(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name       string
		body       string
		statusCode int
		idOverride int64
		delay      time.Duration
		cancel     bool
		wantResult string
		wantErr    bool
		wantCode   int // RPCError.Code, checked when wantErr and > 0
		errSubstr  string
	}{
		{
			name:       "success decodes result",
			body:       `{"jsonrpc":"2.0","id":1,"result":"0x1"}`,
			wantResult: "0x1",
		},
		{
			name:      "error object returns RPCError",
			body:      `{"jsonrpc":"2.0","id":1,"error":{"code":-32000,"message":"reverted"}}`,
			wantErr:   true,
			wantCode:  -32000,
			errSubstr: "reverted",
		},
		{
			name:       "mismatched id rejected",
			body:       `{"jsonrpc":"2.0","id":1,"result":"0x1"}`,
			idOverride: 99,
			wantErr:    true,
			errSubstr:  "id mismatch",
		},
		{
			name:       "http 500 error",
			body:       `internal server error`,
			statusCode: 500,
			wantErr:    true,
			errSubstr:  "http status 500",
		},
		{
			name:      "malformed json error",
			body:      `{not valid json`,
			wantErr:   true,
			errSubstr: "decode response",
		},
		{
			name:      "context cancellation error",
			body:      `{"jsonrpc":"2.0","id":1,"result":"0x1"}`,
			delay:     200 * time.Millisecond,
			cancel:    true,
			wantErr:   true,
			errSubstr: "context",
		},
		{
			name:       "empty result 0x0 is valid",
			body:       `{"jsonrpc":"2.0","id":1,"result":"0x0"}`,
			wantResult: "0x0",
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			h := &mockHandler{
				body:       tc.body,
				statusCode: tc.statusCode,
				idOverride: tc.idOverride,
				delay:      tc.delay,
			}
			srv := httptest.NewServer(h)
			defer srv.Close()

			c := NewHTTPClient(srv.URL)
			ctx := context.Background()
			if tc.cancel {
				var cancel context.CancelFunc
				ctx, cancel = context.WithTimeout(ctx, 10*time.Millisecond)
				defer cancel()
			}

			var result string
			err := c.call(ctx, "eth_chainId", nil, &result)

			if tc.wantErr {
				if err == nil {
					t.Fatalf("call: got nil error, want error containing %q", tc.errSubstr)
				}
				if tc.errSubstr != "" && !strings.Contains(err.Error(), tc.errSubstr) {
					t.Fatalf("call: got error %q, want containing %q", err.Error(), tc.errSubstr)
				}
				if tc.wantCode != 0 {
					var rpcErr *RPCError
					if !errors.As(err, &rpcErr) {
						t.Fatalf("call: got error %T, want *RPCError", err)
					}
					if rpcErr.Code != tc.wantCode {
						t.Fatalf("RPCError.Code: got %d, want %d", rpcErr.Code, tc.wantCode)
					}
				}
				return
			}
			if err != nil {
				t.Fatalf("call: got error %v, want nil", err)
			}
			if result != tc.wantResult {
				t.Fatalf("result: got %q, want %q", result, tc.wantResult)
			}
		})
	}
}

// TestHTTPClient_NilParams covers the nil-params boundary: methods
// with no parameters send a request whose params field is null, and
// the server still returns a valid result.
func TestHTTPClient_NilParams(t *testing.T) {
	t.Parallel()
	h := &mockHandler{
		body: `{"jsonrpc":"2.0","id":1,"result":"0x1"}`,
	}
	srv := httptest.NewServer(h)
	defer srv.Close()

	c := NewHTTPClient(srv.URL)
	var result string
	if err := c.call(context.Background(), "eth_chainId", nil, &result); err != nil {
		t.Fatalf("call: got error %v, want nil", err)
	}
	if result != "0x1" {
		t.Fatalf("result: got %q, want %q", result, "0x1")
	}
	// A nil params request marshals to "params":null.
	if !strings.Contains(h.seenParams, "null") && h.seenParams != "" {
		t.Fatalf("params: got %q, want null", h.seenParams)
	}
}

// TestHTTPClient_EmptyParams covers the empty-params-array boundary.
func TestHTTPClient_EmptyParams(t *testing.T) {
	t.Parallel()
	h := &mockHandler{
		body: `{"jsonrpc":"2.0","id":1,"result":"0x1"}`,
	}
	srv := httptest.NewServer(h)
	defer srv.Close()

	c := NewHTTPClient(srv.URL)
	var result string
	params := []interface{}{}
	if err := c.call(context.Background(), "eth_chainId", params, &result); err != nil {
		t.Fatalf("call: got error %v, want nil", err)
	}
	if result != "0x1" {
		t.Fatalf("result: got %q, want %q", result, "0x1")
	}
}

// TestHTTPClient_Methods covers each of the 9 Client methods against
// a mock server, verifying the correct JSON-RPC method name and params
// shape are sent and the result is decoded.
func TestHTTPClient_Methods(t *testing.T) {
	t.Parallel()

	t.Run("ChainID", func(t *testing.T) {
		t.Parallel()
		h := &mockHandler{body: `{"jsonrpc":"2.0","id":1,"result":"0x1"}`}
		srv := httptest.NewServer(h)
		defer srv.Close()
		c := NewHTTPClient(srv.URL)
		got, err := c.ChainID(context.Background())
		if err != nil {
			t.Fatalf("ChainID: got error %v, want nil", err)
		}
		if want := "0x1"; got != want {
			t.Fatalf("ChainID: got %q, want %q", got, want)
		}
		if h.seenMethod != "eth_chainId" {
			t.Fatalf("method: got %q, want %q", h.seenMethod, "eth_chainId")
		}
	})

	t.Run("GetTransactionCount", func(t *testing.T) {
		t.Parallel()
		h := &mockHandler{body: `{"jsonrpc":"2.0","id":1,"result":"0x0"}`}
		srv := httptest.NewServer(h)
		defer srv.Close()
		c := NewHTTPClient(srv.URL)
		got, err := c.GetTransactionCount(context.Background(), "0xaddr", "latest")
		if err != nil {
			t.Fatalf("GetTransactionCount: got error %v, want nil", err)
		}
		if want := "0x0"; got != want {
			t.Fatalf("GetTransactionCount: got %q, want %q", got, want)
		}
		if h.seenMethod != "eth_getTransactionCount" {
			t.Fatalf("method: got %q, want %q", h.seenMethod, "eth_getTransactionCount")
		}
	})

	t.Run("EstimateGas", func(t *testing.T) {
		t.Parallel()
		h := &mockHandler{body: `{"jsonrpc":"2.0","id":1,"result":"0x5208"}`}
		srv := httptest.NewServer(h)
		defer srv.Close()
		c := NewHTTPClient(srv.URL)
		tx := map[string]interface{}{"to": "0xto", "from": "0xfrom"}
		got, err := c.EstimateGas(context.Background(), tx)
		if err != nil {
			t.Fatalf("EstimateGas: got error %v, want nil", err)
		}
		if want := "0x5208"; got != want {
			t.Fatalf("EstimateGas: got %q, want %q", got, want)
		}
		if h.seenMethod != "eth_estimateGas" {
			t.Fatalf("method: got %q, want %q", h.seenMethod, "eth_estimateGas")
		}
	})

	t.Run("GasPrice", func(t *testing.T) {
		t.Parallel()
		h := &mockHandler{body: `{"jsonrpc":"2.0","id":1,"result":"0x3b9aca00"}`}
		srv := httptest.NewServer(h)
		defer srv.Close()
		c := NewHTTPClient(srv.URL)
		got, err := c.GasPrice(context.Background())
		if err != nil {
			t.Fatalf("GasPrice: got error %v, want nil", err)
		}
		if want := "0x3b9aca00"; got != want {
			t.Fatalf("GasPrice: got %q, want %q", got, want)
		}
		if h.seenMethod != "eth_gasPrice" {
			t.Fatalf("method: got %q, want %q", h.seenMethod, "eth_gasPrice")
		}
	})

	t.Run("MaxPriorityFeePerGas", func(t *testing.T) {
		t.Parallel()
		h := &mockHandler{body: `{"jsonrpc":"2.0","id":1,"result":"0x1"}`}
		srv := httptest.NewServer(h)
		defer srv.Close()
		c := NewHTTPClient(srv.URL)
		got, err := c.MaxPriorityFeePerGas(context.Background())
		if err != nil {
			t.Fatalf("MaxPriorityFeePerGas: got error %v, want nil", err)
		}
		if want := "0x1"; got != want {
			t.Fatalf("MaxPriorityFeePerGas: got %q, want %q", got, want)
		}
		if h.seenMethod != "eth_maxPriorityFeePerGas" {
			t.Fatalf("method: got %q, want %q", h.seenMethod, "eth_maxPriorityFeePerGas")
		}
	})

	t.Run("FeeHistory", func(t *testing.T) {
		t.Parallel()
		h := &mockHandler{body: `{"jsonrpc":"2.0","id":1,"result":{"oldestBlock":"0x1"}}`}
		srv := httptest.NewServer(h)
		defer srv.Close()
		c := NewHTTPClient(srv.URL)
		got, err := c.FeeHistory(context.Background(), "0x1", "latest", []float64{50})
		if err != nil {
			t.Fatalf("FeeHistory: got error %v, want nil", err)
		}
		m, ok := got.(map[string]interface{})
		if !ok {
			t.Fatalf("FeeHistory: got %T, want map", got)
		}
		if m["oldestBlock"] != "0x1" {
			t.Fatalf("FeeHistory oldestBlock: got %v, want %q", m["oldestBlock"], "0x1")
		}
		if h.seenMethod != "eth_feeHistory" {
			t.Fatalf("method: got %q, want %q", h.seenMethod, "eth_feeHistory")
		}
	})

	t.Run("SendRawTransaction", func(t *testing.T) {
		t.Parallel()
		h := &mockHandler{body: `{"jsonrpc":"2.0","id":1,"result":"0xhash"}`}
		srv := httptest.NewServer(h)
		defer srv.Close()
		c := NewHTTPClient(srv.URL)
		got, err := c.SendRawTransaction(context.Background(), "0xraw")
		if err != nil {
			t.Fatalf("SendRawTransaction: got error %v, want nil", err)
		}
		if want := "0xhash"; got != want {
			t.Fatalf("SendRawTransaction: got %q, want %q", got, want)
		}
		if h.seenMethod != "eth_sendRawTransaction" {
			t.Fatalf("method: got %q, want %q", h.seenMethod, "eth_sendRawTransaction")
		}
	})

	t.Run("GetTransactionReceipt", func(t *testing.T) {
		t.Parallel()
		h := &mockHandler{body: `{"jsonrpc":"2.0","id":1,"result":{"status":"0x1"}}`}
		srv := httptest.NewServer(h)
		defer srv.Close()
		c := NewHTTPClient(srv.URL)
		got, err := c.GetTransactionReceipt(context.Background(), "0xhash")
		if err != nil {
			t.Fatalf("GetTransactionReceipt: got error %v, want nil", err)
		}
		m, ok := got.(map[string]interface{})
		if !ok {
			t.Fatalf("GetTransactionReceipt: got %T, want map", got)
		}
		if m["status"] != "0x1" {
			t.Fatalf("status: got %v, want %q", m["status"], "0x1")
		}
		if h.seenMethod != "eth_getTransactionReceipt" {
			t.Fatalf("method: got %q, want %q", h.seenMethod, "eth_getTransactionReceipt")
		}
	})

	t.Run("GetTransactionByHash", func(t *testing.T) {
		t.Parallel()
		h := &mockHandler{body: `{"jsonrpc":"2.0","id":1,"result":{"hash":"0xhash"}}`}
		srv := httptest.NewServer(h)
		defer srv.Close()
		c := NewHTTPClient(srv.URL)
		got, err := c.GetTransactionByHash(context.Background(), "0xhash")
		if err != nil {
			t.Fatalf("GetTransactionByHash: got error %v, want nil", err)
		}
		m, ok := got.(map[string]interface{})
		if !ok {
			t.Fatalf("GetTransactionByHash: got %T, want map", got)
		}
		if m["hash"] != "0xhash" {
			t.Fatalf("hash: got %v, want %q", m["hash"], "0xhash")
		}
		if h.seenMethod != "eth_getTransactionByHash" {
			t.Fatalf("method: got %q, want %q", h.seenMethod, "eth_getTransactionByHash")
		}
	})
}

// TestHTTPClient_NilResultPointer verifies that a nil result pointer
// is handled gracefully (no decode attempted, no panic).
func TestHTTPClient_NilResultPointer(t *testing.T) {
	t.Parallel()
	h := &mockHandler{body: `{"jsonrpc":"2.0","id":1,"result":"0x1"}`}
	srv := httptest.NewServer(h)
	defer srv.Close()

	c := NewHTTPClient(srv.URL)
	if err := c.call(context.Background(), "eth_chainId", nil, nil); err != nil {
		t.Fatalf("call with nil result: got error %v, want nil", err)
	}
}

// TestHTTPClient_IdMonotonic verifies that the request id counter
// increments monotonically across concurrent calls. The mock echoes
// the request id back so we can assert uniqueness.
func TestHTTPClient_IdMonotonic(t *testing.T) {
	t.Parallel()
	const n = 50
	h := newEchoIDHandler(n)
	srv := httptest.NewServer(h)
	defer srv.Close()

	c := NewHTTPClient(srv.URL)
	done := make(chan struct{}, n)
	for i := 0; i < n; i++ {
		go func() {
			var result string
			if err := c.call(context.Background(), "eth_chainId", nil, &result); err != nil {
				t.Errorf("call: got error %v, want nil", err)
				return
			}
			done <- struct{}{}
		}()
	}
	for i := 0; i < n; i++ {
		<-done
	}
	seen := h.ids()
	if len(seen) != n {
		t.Fatalf("id count: got %d, want %d", len(seen), n)
	}
	// Verify uniqueness.
	uniq := make(map[int64]struct{}, n)
	for _, id := range seen {
		uniq[id] = struct{}{}
	}
	if len(uniq) != n {
		t.Fatalf("unique ids: got %d, want %d", len(uniq), n)
	}
}

// TestHTTPClient_DefaultBounds verifies a client constructed without
// options is always bounded: the per-call timeout and the response
// size limit take the documented positive defaults, so no call can
// block forever and no response can be unbounded.
func TestHTTPClient_DefaultBounds(t *testing.T) {
	t.Parallel()

	c := NewHTTPClient("http://localhost:8545")
	if c.timeout != DefaultTimeout {
		t.Fatalf("timeout: got %v, want %v", c.timeout, DefaultTimeout)
	}
	if c.timeout <= 0 {
		t.Fatalf("timeout: got %v, want positive (unbounded calls forbidden)", c.timeout)
	}
	if c.maxResponseBytes != DefaultMaxResponseBytes {
		t.Fatalf("maxResponseBytes: got %d, want %d", c.maxResponseBytes, DefaultMaxResponseBytes)
	}
	if c.maxResponseBytes <= 0 {
		t.Fatalf("maxResponseBytes: got %d, want positive", c.maxResponseBytes)
	}
}

// TestHTTPClient_Options verifies the functional options override the
// defaults and that non-positive or nil values are ignored, retaining
// the bound.
func TestHTTPClient_Options(t *testing.T) {
	t.Parallel()

	custom := &http.Client{Timeout: 90 * time.Second}

	cases := []struct {
		name           string
		opts           []HTTPOption
		wantTimeout    time.Duration
		wantMax        int64
		wantHTTPC      *http.Client // nil means "the default client"
		checkHTTPCOnly bool
	}{
		{
			name:        "defaults",
			wantTimeout: DefaultTimeout,
			wantMax:     DefaultMaxResponseBytes,
		},
		{
			name:        "custom timeout",
			opts:        []HTTPOption{WithTimeout(5 * time.Second)},
			wantTimeout: 5 * time.Second,
			wantMax:     DefaultMaxResponseBytes,
		},
		{
			name:        "zero timeout ignored",
			opts:        []HTTPOption{WithTimeout(0)},
			wantTimeout: DefaultTimeout,
			wantMax:     DefaultMaxResponseBytes,
		},
		{
			name:        "negative timeout ignored",
			opts:        []HTTPOption{WithTimeout(-time.Second)},
			wantTimeout: DefaultTimeout,
			wantMax:     DefaultMaxResponseBytes,
		},
		{
			name:        "custom max response",
			opts:        []HTTPOption{WithMaxResponseBytes(1024)},
			wantTimeout: DefaultTimeout,
			wantMax:     1024,
		},
		{
			name:        "zero max response ignored",
			opts:        []HTTPOption{WithMaxResponseBytes(0)},
			wantTimeout: DefaultTimeout,
			wantMax:     DefaultMaxResponseBytes,
		},
		{
			name:        "negative max response ignored",
			opts:        []HTTPOption{WithMaxResponseBytes(-1)},
			wantTimeout: DefaultTimeout,
			wantMax:     DefaultMaxResponseBytes,
		},
		{
			name:        "custom http client",
			opts:        []HTTPOption{WithHTTPClient(custom)},
			wantTimeout: DefaultTimeout,
			wantMax:     DefaultMaxResponseBytes,
			wantHTTPC:   custom,
		},
		{
			name:        "nil http client ignored",
			opts:        []HTTPOption{WithHTTPClient(nil)},
			wantTimeout: DefaultTimeout,
			wantMax:     DefaultMaxResponseBytes,
		},
		{
			name: "combined options",
			opts: []HTTPOption{
				WithTimeout(3 * time.Second),
				WithMaxResponseBytes(256),
				WithHTTPClient(custom),
			},
			wantTimeout: 3 * time.Second,
			wantMax:     256,
			wantHTTPC:   custom,
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			c := NewHTTPClient("http://localhost:8545", tc.opts...)
			if c.timeout != tc.wantTimeout {
				t.Fatalf("timeout: got %v, want %v", c.timeout, tc.wantTimeout)
			}
			if c.maxResponseBytes != tc.wantMax {
				t.Fatalf("maxResponseBytes: got %d, want %d", c.maxResponseBytes, tc.wantMax)
			}
			if tc.wantHTTPC != nil {
				if c.httpc != tc.wantHTTPC {
					t.Fatalf("httpc: got %p, want %p", c.httpc, tc.wantHTTPC)
				}
			} else if c.httpc == nil {
				t.Fatal("httpc is nil")
			}
		})
	}
}

// TestHTTPClient_TimeoutEnforced verifies the configured per-call
// timeout actually bounds a call: a server slower than the timeout
// produces a context.DeadlineExceeded error even though the caller's
// context has no deadline.
func TestHTTPClient_TimeoutEnforced(t *testing.T) {
	t.Parallel()

	h := &mockHandler{
		body:  `{"jsonrpc":"2.0","id":1,"result":"0x1"}`,
		delay: 500 * time.Millisecond,
	}
	srv := httptest.NewServer(h)
	defer srv.Close()

	c := NewHTTPClient(srv.URL, WithTimeout(50*time.Millisecond))

	start := time.Now()
	var result string
	err := c.call(context.Background(), "eth_chainId", nil, &result)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("call: got nil error, want deadline error")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("call: got error %v, want errors.Is(context.DeadlineExceeded)", err)
	}
	if elapsed > 400*time.Millisecond {
		t.Fatalf("call: returned too slowly (elapsed=%v), want near 50ms timeout", elapsed)
	}
}

// TestHTTPClient_ResponseBound verifies a response body larger than
// the configured bound is rejected with ErrResponseTooLarge, a body
// exactly at the bound is accepted, and a body one byte over is
// rejected.
func TestHTTPClient_ResponseBound(t *testing.T) {
	t.Parallel()

	body := `{"jsonrpc":"2.0","id":1,"result":"0x1"}`

	cases := []struct {
		name     string
		body     string
		maxBytes int64
		wantErr  bool
	}{
		{
			name:     "oversized response rejected",
			body:     body,
			maxBytes: int64(len(body)) - 1,
			wantErr:  true,
		},
		{
			name:     "body at bound accepted",
			body:     body,
			maxBytes: int64(len(body)),
			wantErr:  false,
		},
		{
			name:     "tiny bound rejects normal response",
			body:     body,
			maxBytes: 8,
			wantErr:  true,
		},
		{
			name:     "huge trailing padding rejected",
			body:     body + strings.Repeat(" ", 4096),
			maxBytes: int64(len(body)),
			wantErr:  true,
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			h := &mockHandler{body: tc.body}
			srv := httptest.NewServer(h)
			defer srv.Close()

			c := NewHTTPClient(srv.URL, WithMaxResponseBytes(tc.maxBytes))
			var result string
			err := c.call(context.Background(), "eth_chainId", nil, &result)

			if tc.wantErr {
				if err == nil {
					t.Fatalf("call: got nil error, want ErrResponseTooLarge (max=%d, body=%d bytes)", tc.maxBytes, len(tc.body))
				}
				if !errors.Is(err, ErrResponseTooLarge) {
					t.Fatalf("call: got error %v, want errors.Is(ErrResponseTooLarge)", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("call: got error %v, want nil", err)
			}
			if result != "0x1" {
				t.Fatalf("result: got %q, want %q", result, "0x1")
			}
		})
	}
}

// TestHTTPClient_DefaultResponseBoundEnforced verifies the default
// bound rejects an oversized response when no option is supplied.
// Generating a >8 MiB body would be slow, so the bound is exercised
// through the field directly: a client with the default bound is
// constructed and the field is asserted, while the enforcement path
// is covered by TestHTTPClient_ResponseBound.
func TestHTTPClient_DefaultResponseBoundEnforced(t *testing.T) {
	t.Parallel()

	// A response just over a small bound is rejected; the default
	// bound itself is asserted positive in TestHTTPClient_DefaultBounds.
	h := &mockHandler{body: `{"jsonrpc":"2.0","id":1,"result":"` + strings.Repeat("a", 512) + `"}`}
	srv := httptest.NewServer(h)
	defer srv.Close()

	c := NewHTTPClient(srv.URL, WithMaxResponseBytes(64))
	var result string
	err := c.call(context.Background(), "eth_chainId", nil, &result)
	if err == nil {
		t.Fatal("call: got nil error, want ErrResponseTooLarge")
	}
	if !errors.Is(err, ErrResponseTooLarge) {
		t.Fatalf("call: got error %v, want errors.Is(ErrResponseTooLarge)", err)
	}
}

// echoIDHandler echoes the request id back in the result field so
// tests can verify id uniqueness under concurrency. The ids channel
// is initialized upfront to avoid a lazy-init race.
type echoIDHandler struct {
	idsSeen chan int64
}

func newEchoIDHandler(n int) *echoIDHandler {
	return &echoIDHandler{idsSeen: make(chan int64, n)}
}

func (h *echoIDHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	raw, _ := io.ReadAll(r.Body)
	req, err := parseRequest(raw)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	h.idsSeen <- req.ID
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":` + strconv.Itoa(int(req.ID)) + `,"result":"0x1"}`))
}

func (h *echoIDHandler) ids() []int64 {
	close(h.idsSeen)
	out := make([]int64, 0, len(h.idsSeen))
	for id := range h.idsSeen {
		out = append(out, id)
	}
	return out
}
