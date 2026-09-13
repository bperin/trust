package kms

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestKMSNoAuthOrChainImports verifies the kms module has no imports
// of the auth or chain sibling modules. This enforces the cross-module
// dependency rule: kms depends on trust only.
//
// Per SPEC-005: kms may import trust only — no chain, no auth.
func TestKMSNoAuthOrChainImports(t *testing.T) {
	t.Parallel()

	forbidden := []string{
		"github.com/bperin/trust/auth",
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
