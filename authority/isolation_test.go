package authority

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestIsolation_NoAuthChainKmsImports verifies the authority package
// has no imports of the auth, chain, or kms packages. This enforces
// the dependency rule: authority may import only canonical and
// signature from this repository.
func TestIsolation_NoAuthChainKmsImports(t *testing.T) {
	t.Parallel()

	forbidden := []string{
		"github.com/bperin/trust/auth",
		"github.com/bperin/trust/chain",
		"github.com/bperin/trust/kms",
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
