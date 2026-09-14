package isolation

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestIsolation_NoChainImports verifies the auth module has no imports of
// the chain sibling module. This enforces the cross-module dependency
// rule: auth and chain do not depend on each other.
//
// Per AGENTS.md: auth does not import chain. Auth may import trust
// and (per SPEC-005) kms.
//
// The legacy pre-monorepo chain path is forbidden too — the old
// github.com/bperin/chain module is still published, so a stale import
// would silently resolve instead of failing the build. The stale
// first-level package paths of the old root trust module
// (github.com/bperin/trust, still published as v0.4.x) are likewise
// forbidden: the trust module now resolves as
// github.com/bperin/trust/trust/... and an import missing the second
// path segment is a regression to the old module.
func TestIsolation_NoChainImports(t *testing.T) {
	t.Parallel()

	forbidden := []string{
		// Current monorepo chain module path.
		"github.com/bperin/trust/chain",
		// Legacy pre-monorepo chain module path.
		"github.com/bperin/chain",
		// Stale first-level packages of the old root trust module.
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
