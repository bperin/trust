package isolation

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestIsolation_NoChainImports verifies the auth packages have no imports
// of the chain packages. This enforces the dependency rule: auth and
// chain do not depend on each other.
//
// Per AGENTS.md: auth does not import chain. Auth may import the crypto
// core and (per SPEC-005) kms.
func TestIsolation_NoChainImports(t *testing.T) {
	t.Parallel()

	forbidden := []string{
		"github.com/bperin/trust/chain",
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
