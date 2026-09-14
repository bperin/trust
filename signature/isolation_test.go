package signature

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestIsolation_NoAuthChainKmsImports verifies the signature package
// has no imports of the auth, chain, or kms packages. signature is a
// cryptographic core package consumed by both authority and kms —
// importing any of them back would create a dependency cycle. Test
// files are excluded because they may import these packages for
// integration tests.
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
