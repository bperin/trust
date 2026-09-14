package commitment

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func skipDir(d fs.DirEntry) bool {
	name := d.Name()
	return name == "vendor" || name == ".git" || name == "testdata"
}

func isScannableGoFile(path string) bool {
	return strings.HasSuffix(path, ".go") && !strings.HasSuffix(path, "_test.go")
}

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

// TestIsolation_NoAuthOrKms verifies that chain/commitment source files
// do not import auth or kms packages.
func TestIsolation_NoAuthOrKms(t *testing.T) {
	t.Parallel()
	forbidden := []string{
		"github.com/bperin/trust/auth",
		"github.com/bperin/trust/kms",
	}
	assertNoForbiddenImports(t, ".", forbidden)
}

// TestIsolation_TrustCommitmentNoChain verifies that the repo-root
// commitment/ package does not import chain or chain/commitment,
// proving no trust → chain dependency cycle.
func TestIsolation_TrustCommitmentNoChain(t *testing.T) {
	t.Parallel()
	forbidden := []string{
		"github.com/bperin/trust/chain",
		"github.com/bperin/trust/chain/commitment",
	}

	// Walk the repo-root commitment/ directory. The test runs from
	// chain/commitment/, so resolve the repo root via relative path.
	dir := filepath.Join("..", "..", "commitment")
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		t.Skipf("repo-root commitment/ directory not found at %s", dir)
	}
	assertNoForbiddenImports(t, dir, forbidden)
}
