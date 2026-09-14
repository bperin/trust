package isolation

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// skipDir reports whether a directory entry should be skipped during
// an isolation walk. Vendor, VCS, and testdata directories are excluded.
func skipDir(d fs.DirEntry) bool {
	name := d.Name()
	return name == "vendor" || name == ".git" || name == "testdata"
}

// isScannableGoFile reports whether path is a non-test .go file that
// should be scanned for import violations. Test files and the
// isolation_test file itself are excluded.
func isScannableGoFile(path string) bool {
	return strings.HasSuffix(path, ".go") && !strings.HasSuffix(path, "_test.go")
}

// assertNoForbiddenImports walks dir and fails the test if any non-test
// .go file contains one of the forbidden import paths. Each forbidden
// path is matched as a substring, following the TestIsolation_NoAuthImports
// pattern.
func assertNoForbiddenImports(t *testing.T, dir string, forbidden []string) {
	t.Helper()
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if skipDir(d) {
				return filepath.SkipDir
			}
			return nil
		}
		if !isScannableGoFile(path) {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for _, bad := range forbidden {
			if strings.Contains(string(data), bad) {
				t.Errorf("file %s imports %s (dependency rule violation)", path, bad)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", dir, err)
	}
}

// assertRequiredImport walks dir and fails the test if no non-test .go
// file contains the required import path. This is a positive grep — it
// verifies that an expected import is present.
func assertRequiredImport(t *testing.T, dir, required string) {
	t.Helper()
	found := false
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if skipDir(d) {
				return filepath.SkipDir
			}
			return nil
		}
		if !isScannableGoFile(path) {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if strings.Contains(string(data), required) {
			found = true
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", dir, err)
	}
	if !found {
		t.Errorf("no file in %s imports %s (required import missing)", dir, required)
	}
}

// TestIsolation_NoAuthImports verifies the chain module has no imports of
// the auth sibling module. This enforces the cross-module dependency
// rule: chain and auth do not depend on each other.
//
// Per AGENTS.md: chain does not import auth. Chain may import trust
// and (per SPEC-005) kms.
//
// The legacy pre-monorepo auth path is forbidden too — the old
// github.com/bperin/auth module is still published, so a stale import
// would silently resolve instead of failing the build.
func TestIsolation_NoAuthImports(t *testing.T) {
	t.Parallel()

	forbidden := []string{
		"github.com/bperin/trust/auth",
		"github.com/bperin/auth",
	}

	err := filepath.WalkDir(".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			name := d.Name()
			if name == "vendor" || name == ".git" || name == "testdata" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for _, forbiddenPath := range forbidden {
			if strings.Contains(string(data), forbiddenPath) {
				t.Errorf("file %s imports %s (dependency rule violation)", path, forbiddenPath)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
}

// TestIsolation_NoStaleTrustPaths verifies no chain file imports the legacy
// pre-monorepo trust module path. The old github.com/bperin/trust module
// is still published (v0.4.x), so an import missing the second path
// segment — e.g. github.com/bperin/trust/crypto/hash instead of
// github.com/bperin/trust/trust/crypto/hash — would silently resolve to
// the stale module instead of failing the build.
func TestIsolation_NoStaleTrustPaths(t *testing.T) {
	t.Parallel()

	// First-level packages of the old root trust module. None of these
	// collide with the new layout: every new-path import has a second
	// segment of trust/, auth/, chain/, or kms/.
	forbidden := []string{
		"github.com/bperin/trust/attestation",
		"github.com/bperin/trust/authority",
		"github.com/bperin/trust/canonical",
		"github.com/bperin/trust/credential",
		"github.com/bperin/trust/crypto",
		"github.com/bperin/trust/evidence",
		"github.com/bperin/trust/identity",
		"github.com/bperin/trust/merkle",
		"github.com/bperin/trust/proof",
		"github.com/bperin/trust/signature",
	}

	for _, bad := range forbidden {
		t.Run(strings.TrimPrefix(bad, "github.com/bperin/trust/"), func(t *testing.T) {
			t.Parallel()
			assertNoForbiddenImports(t, ".", []string{bad})
		})
	}
}

// TestIsolation_AbiNoWalletOrRPC enforces the intra-module dependency rule
// that chain/abi imports trust/crypto/hash only — it must not import
// chain/wallet or chain/rpc.
//
// Per PLAN-006 WS-10: chain/abi is a leaf encoding package with no
// dependency on higher-level chain packages.
func TestIsolation_AbiNoWalletOrRPC(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name      string
		forbidden string
	}{
		{"no_chain_wallet", "github.com/bperin/trust/chain/wallet"},
		{"no_chain_rpc", "github.com/bperin/trust/chain/rpc"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assertNoForbiddenImports(t, "abi", []string{tc.forbidden})
		})
	}
}

// TestIsolation_WalletNoRPC enforces the intra-module dependency rule that
// chain/wallet does not import chain/rpc. Wallet is a signing/encoding
// package and must not depend on the RPC transport layer.
//
// Per PLAN-006 WS-10: chain/wallet may import trust, chain/ethereum,
// and chain/rlp — never chain/rpc.
func TestIsolation_WalletNoRPC(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name      string
		forbidden string
	}{
		{"no_chain_rpc", "github.com/bperin/trust/chain/rpc"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assertNoForbiddenImports(t, "wallet", []string{tc.forbidden})
		})
	}
}

// TestIsolation_BroadcastImportsOnlyAllowed enforces the intra-module
// dependency rule that chain/broadcast imports only chain/wallet,
// chain/rpc, chain/ethereum, stdlib, and trust. It must not import
// chain/abi, chain/evm, chain/proof, or the auth module.
//
// Per PLAN-006 WS-10: broadcast is a thin transport layer that wires
// wallet and rpc together — it must not reach into abi or evm.
func TestIsolation_BroadcastImportsOnlyAllowed(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name      string
		forbidden string
	}{
		{"no_chain_abi", "github.com/bperin/trust/chain/abi"},
		{"no_chain_evm", "github.com/bperin/trust/chain/evm"},
		{"no_chain_proof", "github.com/bperin/trust/chain/proof"},
		{"no_auth", "github.com/bperin/trust/auth"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assertNoForbiddenImports(t, "broadcast", []string{tc.forbidden})
		})
	}
}

// TestIsolation_EvmImportsAbi is a positive grep that verifies chain/evm
// imports chain/abi. This confirms the WS-9 refactor landed — evm
// delegates ABI decoding to the abi package rather than duplicating
// the logic.
//
// Per PLAN-006 WS-10: chain/evm must import chain/abi (refactored).
func TestIsolation_EvmImportsAbi(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name     string
		required string
	}{
		{"imports_chain_abi", "github.com/bperin/trust/chain/abi"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assertRequiredImport(t, "evm", tc.required)
		})
	}
}

// TestIsolation_EvmNoDirectHash enforces the intra-module dependency rule
// that chain/evm does not import trust/crypto/hash directly. The WS-9
// refactor moved hash usage behind chain/abi, so a direct import is a
// regression.
//
// Per PLAN-006 WS-10: chain/evm has no direct trust/crypto/hash import.
func TestIsolation_EvmNoDirectHash(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name      string
		forbidden string
	}{
		{"no_trust_crypto_hash", "github.com/bperin/trust/trust/crypto/hash"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assertNoForbiddenImports(t, "evm", []string{tc.forbidden})
		})
	}
}
