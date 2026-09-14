package kms

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestIsolation_NoAuthOrChainImports verifies the kms packages have no
// imports of the auth or chain packages. This enforces the dependency
// rule: kms depends on the crypto core only.
//
// Per SPEC-005: kms may import the crypto core only — no chain, no auth.
func TestIsolation_NoAuthOrChainImports(t *testing.T) {
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

// TestIsolation_NoCloudAdapterReferences verifies no cloud-provider adapter
// references remain in the kms packages. Per PLAN-007 W2 and SPEC-007
// finding A16, the kms/aws and kms/gcp adapter packages moved to the
// private trakt2-crypto repository; the public kms packages keep only
// the RemoteSigner interface and the DER/SPKI parsing core.
func TestIsolation_NoCloudAdapterReferences(t *testing.T) {
	t.Parallel()

	forbidden := []string{
		"github.com/bperin/trust/kms/aws",
		"github.com/bperin/trust/kms/gcp",
		"github.com/aws/aws-sdk-go",
		"github.com/aws/smithy-go",
		"cloud.google.com/go",
		"google.golang.org/api",
		"google.golang.org/genproto",
		"github.com/GoogleCloudPlatform",
	}

	scan := func(path string) {
		t.Helper()
		data, err := os.ReadFile(path)
		if err != nil {
			t.Errorf("read %s: %v", path, err)
			return
		}
		for _, bad := range forbidden {
			if strings.Contains(string(data), bad) {
				t.Errorf("file %s references cloud adapter %s (dependency rule violation)", path, bad)
			}
		}
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
		scan(path)
		return nil
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
}
