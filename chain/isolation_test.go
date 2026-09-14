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
// path is matched as a substring.
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

// TestIsolation_NoAuthImports verifies the chain packages have no imports
// of the auth packages. This enforces the dependency rule: chain and
// auth do not depend on each other.
//
// Per AGENTS.md: chain does not import auth. Chain may import the crypto
// core and (per SPEC-005) kms.
func TestIsolation_NoAuthImports(t *testing.T) {
	t.Parallel()

	forbidden := []string{
		"github.com/bperin/trust/auth",
	}

	assertNoForbiddenImports(t, ".", forbidden)
}

// TestIsolation_AbiNoWalletOrRPC enforces the intra-module dependency rule
// that chain/abi imports the crypto core only — it must not import
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
// Per PLAN-006 WS-10: chain/wallet may import the crypto core,
// chain/ethereum, and chain/rlp — never chain/rpc.
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
// chain/rpc, chain/ethereum, stdlib, and the crypto core. It must not
// import chain/abi or the auth module.
//
// Per PLAN-006 WS-10: broadcast is a thin transport layer that wires
// wallet and rpc together — it must not reach into abi.
func TestIsolation_BroadcastImportsOnlyAllowed(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name      string
		forbidden string
	}{
		{"no_chain_abi", "github.com/bperin/trust/chain/abi"},
		{"no_auth", "github.com/bperin/trust/auth"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assertNoForbiddenImports(t, "broadcast", []string{tc.forbidden})
		})
	}
}
