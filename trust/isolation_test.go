package isolation

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestIsolation_NoAuthChainKMSImports verifies the trust module has no
// imports of the auth, chain, or kms sibling modules. This enforces
// the cross-module dependency rule: trust is the cryptographic core and
// must not depend on any consumer module.
//
// Per AGENTS.md: trust must never import auth, chain, or kms.
//
// The legacy pre-monorepo module paths (github.com/bperin/auth,
// github.com/bperin/chain, github.com/bperin/kms) are forbidden too —
// those modules are still published, so a stale import would silently
// resolve to the old module instead of failing the build.
func TestIsolation_NoAuthChainKMSImports(t *testing.T) {
	t.Parallel()

	forbidden := []string{
		// Current monorepo module paths.
		"github.com/bperin/trust/auth",
		"github.com/bperin/trust/chain",
		"github.com/bperin/trust/kms",
		// Legacy pre-monorepo module paths.
		"github.com/bperin/auth",
		"github.com/bperin/chain",
		"github.com/bperin/kms",
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
