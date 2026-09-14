package commitment

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestIsolation_NoForbiddenImports walks the non-test .go files of this
// package and fails if any imports a forbidden module. The commitment
// package must stay inside the crypto core: no chain, kms, auth, or
// verification imports.
func TestIsolation_NoForbiddenImports(t *testing.T) {
	t.Parallel()

	// Each forbidden module name is matched both as an exact quoted import
	// (".../auth") and as a package path prefix (".../auth/") so subpackage
	// imports are caught too, while "authority" cannot false-positive on
	// the "auth" prefix — the closing quote or slash is required.
	var forbidden []string
	for _, name := range []string{"chain", "kms", "auth", "verification"} {
		forbidden = append(forbidden,
			`"github.com/bperin/trust/`+name+`"`,
			`"github.com/bperin/trust/`+name+`/`,
		)
	}

	err := filepath.WalkDir(".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case "vendor", ".git", "testdata":
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
		for _, pattern := range forbidden {
			if strings.Contains(string(data), pattern) {
				t.Errorf("file %s contains forbidden import matching %q", path, pattern)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk commitment/: got error %v, want nil", err)
	}
}
