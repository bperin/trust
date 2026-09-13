package isolation

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestChainNoAuthImports verifies the chain module has no imports of
// the auth sibling module. This enforces the cross-module dependency
// rule: chain and auth do not depend on each other.
//
// Per AGENTS.md: chain does not import auth. Chain may import trust
// and (per SPEC-005) kms.
func TestChainNoAuthImports(t *testing.T) {
	t.Parallel()

	forbidden := []string{
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
