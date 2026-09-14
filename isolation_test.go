package isolation

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestIsolation_NoAuthChainKMSImports verifies the crypto core packages
// have no imports of the auth, chain, or kms packages. This enforces
// the dependency rule: the crypto core must not depend on any consumer
// package.
//
// Per AGENTS.md: crypto core (crypto, identity, merkle, signature,
// attestation, canonical) must never import auth, chain, or kms.
func TestIsolation_NoAuthChainKMSImports(t *testing.T) {
	t.Parallel()

	forbidden := []string{
		"github.com/bperin/trust/auth",
		"github.com/bperin/trust/chain",
		"github.com/bperin/trust/kms",
	}

	// Only check the crypto core directories — auth, chain, and kms
	// are allowed to import the crypto core, not the reverse.
	coreDirs := []string{
		"crypto",
		"identity",
		"merkle",
		"signature",
		"attestation",
		"canonical",
	}

	for _, dir := range coreDirs {
		err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
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
			t.Fatalf("walk %s: %v", dir, err)
		}
	}
}
