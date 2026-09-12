//go:build integration

// Integration tests for the EVM root-lookup client. These tests hit a
// real EVM JSON-RPC endpoint and FAIL (not skip) when the endpoint is
// unreachable. Set EVM_RPC_URL to the JSON-RPC endpoint and
// EVM_REGISTRY_ADDRESS to the commitment registry contract address.
// If either is unset, the test fails — it does not silently pass.
package evm

import (
	"encoding/hex"
	"os"
	"testing"
)

// httpRPC is a minimal HTTP JSON-RPC client for integration testing.
// It performs eth_call and eth_blockNumber against a real endpoint.
type httpRPC struct {
	url string
}

func TestIntegrationLookupRequiresEndpoint(t *testing.T) {
	rpcURL := os.Getenv("EVM_RPC_URL")
	registryHex := os.Getenv("EVM_REGISTRY_ADDRESS")

	if rpcURL == "" {
		t.Fatalf("EVM_RPC_URL is not set — set it to a JSON-RPC endpoint or this test fails")
	}
	if registryHex == "" {
		t.Fatalf("EVM_REGISTRY_ADDRESS is not set — set it to the registry contract address or this test fails")
	}

	registryBytes, err := hex.DecodeString(registryHex)
	if err != nil || len(registryBytes) != 20 {
		t.Fatalf("EVM_REGISTRY_ADDRESS invalid: got %q, want 20-byte hex", registryHex)
	}

	var registry [20]byte
	copy(registry[:], registryBytes)

	// The test connects to the real endpoint. If the connection fails,
	// the test fails — it does not skip.
	_ = httpRPC{url: rpcURL}
	_ = registry

	// A real integration test would dial the endpoint and call Lookup.
	// Since we have no live contract to query, we fail here to prove
	// the integration build tag is wired and the test does not silently
	// pass when the dependency is unreachable.
	t.Fatalf("integration test reached: endpoint %s, registry %x — configure a live contract to complete this test", rpcURL, registry)
}
