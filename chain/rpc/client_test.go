package rpc

import (
	"context"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestRPCError_Error verifies RPCError implements the error interface
// and formats its message as "rpc: code <Code>: <Message>".
func TestRPCError_Error(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		err  *RPCError
		want string
	}{
		{
			name: "server error code",
			err:  &RPCError{Code: -32000, Message: "reverted"},
			want: "rpc: code -32000: reverted",
		},
		{
			name: "positive code",
			err:  &RPCError{Code: 1, Message: "parse error"},
			want: "rpc: code 1: parse error",
		},
		{
			name: "zero code",
			err:  &RPCError{Code: 0, Message: "ok"},
			want: "rpc: code 0: ok",
		},
		{
			name: "empty message",
			err:  &RPCError{Code: -32601, Message: ""},
			want: "rpc: code -32601: ",
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := tc.err.Error()
			if got != tc.want {
				t.Fatalf("Error(): got %q, want %q", got, tc.want)
			}
			// Verify it satisfies the error interface.
			var _ error = tc.err
		})
	}
}

// TestRPCError_ImplementsError verifies RPCError is assignable to the
// error interface and is recoverable via errors.As.
func TestRPCError_ImplementsError(t *testing.T) {
	t.Parallel()
	var err error = &RPCError{Code: -32000, Message: "reverted"}
	if err == nil {
		t.Fatal("error is nil")
	}
	var rpcErr *RPCError
	if !errors.As(err, &rpcErr) {
		t.Fatalf("errors.As: got false, want true")
	}
	if rpcErr.Code != -32000 {
		t.Fatalf("Code: got %d, want %d", rpcErr.Code, -32000)
	}
}

// TestJSONRPCSpec_RequestShape verifies the request object conforms to
// [JSON-RPC 2.0] §4: it has jsonrpc="2.0", a numeric id, a method, and
// params. The params field may be null when the method takes none.
//
// [JSON-RPC 2.0]: https://www.jsonrpc.org/specification
func TestJSONRPCSpec_RequestShape(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name   string
		method string
		params interface{}
	}{
		{name: "nil params", method: "eth_chainId", params: nil},
		{name: "array params", method: "eth_getTransactionCount", params: []interface{}{"0xaddr", "latest"}},
		{name: "empty array params", method: "eth_chainId", params: []interface{}{}},
		{name: "object params", method: "eth_estimateGas", params: []interface{}{map[string]interface{}{"to": "0xto"}}},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			req := rpcRequest{
				JSONRPC: "2.0",
				ID:      1,
				Method:  tc.method,
				Params:  tc.params,
			}
			raw, err := json.Marshal(req)
			if err != nil {
				t.Fatalf("marshal: got error %v, want nil", err)
			}
			var decoded map[string]interface{}
			if err := json.Unmarshal(raw, &decoded); err != nil {
				t.Fatalf("unmarshal: got error %v, want nil", err)
			}
			if decoded["jsonrpc"] != "2.0" {
				t.Fatalf("jsonrpc: got %v, want %q", decoded["jsonrpc"], "2.0")
			}
			if decoded["method"] != tc.method {
				t.Fatalf("method: got %v, want %q", decoded["method"], tc.method)
			}
			id, ok := decoded["id"].(float64)
			if !ok || id != 1 {
				t.Fatalf("id: got %v, want 1", decoded["id"])
			}
			// params must be present (null, array, or object).
			if _, ok := decoded["params"]; !ok {
				t.Fatal("params: missing")
			}
		})
	}
}

// TestJSONRPCSpec_ResponseShape verifies the response object conforms
// to [JSON-RPC 2.0] §5: it has jsonrpc="2.0", an id matching the
// request, and either a result or an error.
//
// [JSON-RPC 2.0]: https://www.jsonrpc.org/specification
func TestJSONRPCSpec_ResponseShape(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		body    string
		wantErr bool
	}{
		{
			name: "result response",
			body: `{"jsonrpc":"2.0","id":1,"result":"0x1"}`,
		},
		{
			name:    "error response",
			body:    `{"jsonrpc":"2.0","id":1,"error":{"code":-32601,"message":"method not found"}}`,
			wantErr: true,
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			h := &mockHandler{body: tc.body}
			srv := httptest.NewServer(h)
			defer srv.Close()

			c := NewHTTPClient(srv.URL)
			var result string
			err := c.call(context.Background(), "eth_chainId", nil, &result)

			if tc.wantErr {
				if err == nil {
					t.Fatal("call: got nil error, want error")
				}
				var rpcErr *RPCError
				if !errors.As(err, &rpcErr) {
					t.Fatalf("error type: got %T, want *RPCError", err)
				}
				if rpcErr.Code != -32601 {
					t.Fatalf("Code: got %d, want %d", rpcErr.Code, -32601)
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

// TestJSONRPCSpec_IdMatching verifies that the response id must match
// the request id. A mismatched id is rejected as a potential
// injection. Per [JSON-RPC 2.0] §5, the id is established by the
// request and echoed in the response.
//
// [JSON-RPC 2.0]: https://www.jsonrpc.org/specification
func TestJSONRPCSpec_IdMatching(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name       string
		idOverride int64
		wantErr    bool
		errSubstr  string
	}{
		{name: "matching id accepted", wantErr: false},
		{name: "mismatched id rejected", idOverride: 99, wantErr: true, errSubstr: "id mismatch"},
		{name: "zero id mismatch", idOverride: 1, wantErr: false}, // override to 1 == request id
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			h := &mockHandler{
				body:       `{"jsonrpc":"2.0","id":1,"result":"0x1"}`,
				idOverride: tc.idOverride,
			}
			srv := httptest.NewServer(h)
			defer srv.Close()

			c := NewHTTPClient(srv.URL)
			var result string
			err := c.call(context.Background(), "eth_chainId", nil, &result)

			if tc.wantErr {
				if err == nil {
					t.Fatal("call: got nil error, want error")
				}
				if tc.errSubstr != "" && !strings.Contains(err.Error(), tc.errSubstr) {
					t.Fatalf("error: got %q, want containing %q", err.Error(), tc.errSubstr)
				}
				return
			}
			if err != nil {
				t.Fatalf("call: got error %v, want nil", err)
			}
		})
	}
}

// TestClient_Interface verifies HTTPClient satisfies the Client
// interface at compile time and via a runtime assignment.
func TestClient_Interface(t *testing.T) {
	t.Parallel()
	var c Client = NewHTTPClient("http://example.invalid")
	if c == nil {
		t.Fatal("Client is nil")
	}
	// The compile-time check var _ Client = (*HTTPClient)(nil) in
	// http.go guards the interface; this runtime check confirms the
	// constructor returns a usable value.
}

// TestNewHTTPClient verifies the constructor sets the endpoint and a
// non-nil HTTP client.
func TestNewHTTPClient(t *testing.T) {
	t.Parallel()
	c := NewHTTPClient("http://localhost:8545")
	if c == nil {
		t.Fatal("NewHTTPClient returned nil")
	}
	if c.endpoint != "http://localhost:8545" {
		t.Fatalf("endpoint: got %q, want %q", c.endpoint, "http://localhost:8545")
	}
	if c.httpc == nil {
		t.Fatal("httpc is nil")
	}
}
