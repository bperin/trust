package evidence

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestIsolation_NoForbiddenImports verifies the evidence package has no
// imports of any trust package other than canonical. This enforces the
// dependency rule: evidence is a leaf package with zero coupling to
// authority, claim, or the crypto packages.
//
// Each forbidden path is matched as a full quoted import string — e.g.
// `"github.com/bperin/trust/auth"` — not by raw byte containment on the
// unquoted path. Unquoted matching would false-positive because
// "github.com/bperin/trust/auth" is a strict prefix of
// "github.com/bperin/trust/authority".
func TestIsolation_NoForbiddenImports(t *testing.T) {
	t.Parallel()

	forbidden := []string{
		`"github.com/bperin/trust/authority"`,
		`"github.com/bperin/trust/auth"`,
		`"github.com/bperin/trust/chain"`,
		`"github.com/bperin/trust/kms"`,
		`"github.com/bperin/trust/signature"`,
		`"github.com/bperin/trust/attestation"`,
		`"github.com/bperin/trust/merkle"`,
		`"github.com/bperin/trust/claim"`,
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
		for _, quoted := range forbidden {
			if strings.Contains(string(data), quoted) {
				t.Errorf("file %s imports %s (dependency rule violation)", path, quoted)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
}
