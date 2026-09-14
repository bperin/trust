package verification

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// forbiddenImports are the module paths the verification package must
// never import, matched as full quoted import literals.
var forbiddenImports = []string{
	"github.com/bperin/trust/merkle",
	"github.com/bperin/trust/chain",
	"github.com/bperin/trust/kms",
	"github.com/bperin/trust/auth",
}

// skippedDir reports whether the isolation walk skips the named
// directory.
func skippedDir(name string) bool {
	switch name {
	case "vendor", ".git", "testdata":
		return true
	}
	return false
}

// scannedFile reports whether path is a non-test Go source file the
// isolation gate scans.
func scannedFile(path string) bool {
	return strings.HasSuffix(path, ".go") && !strings.HasSuffix(path, "_test.go")
}

// TestIsolation_NoForbiddenImports walks the verification package's
// non-test Go files and fails on any forbidden import. Matching is on
// full quoted import literals, so "auth" never false-positives on
// "authority".
func TestIsolation_NoForbiddenImports(t *testing.T) {
	t.Parallel()
	scanned := 0
	err := filepath.WalkDir(".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if skippedDir(d.Name()) {
				return filepath.SkipDir
			}
			return nil
		}
		if !scannedFile(path) {
			return nil
		}
		scanned++
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for _, imp := range forbiddenImports {
			if strings.Contains(string(data), "\""+imp+"\"") {
				t.Errorf("file %s imports %s (dependency rule violation)", path, imp)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
	if scanned == 0 {
		t.Fatal("walk scanned no non-test Go files; the gate is vacuous")
	}
}

// TestIsolation_HelperTable pins the matcher's behavior: forbidden
// quoted literals match, allowed imports and unquoted text do not.
func TestIsolation_HelperTable(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name   string
		body   string
		forbid bool
	}{
		{"merkle import", "import \"github.com/bperin/trust/merkle\"", true},
		{"chain import", "import \"github.com/bperin/trust/chain\"", true},
		{"kms import", "import \"github.com/bperin/trust/kms\"", true},
		{"auth import", "import \"github.com/bperin/trust/auth\"", true},
		{"authority import", "import \"github.com/bperin/trust/authority\"", false},
		{"canonical import", "import \"github.com/bperin/trust/canonical\"", false},
		{"unquoted mention", "// see github.com/bperin/trust/auth for details", false},
	}
	for _, tc := range cases {
		matched := false
		for _, imp := range forbiddenImports {
			if strings.Contains(tc.body, "\""+imp+"\"") {
				matched = true
				break
			}
		}
		if matched != tc.forbid {
			t.Errorf("%s: matched=%v, want %v", tc.name, matched, tc.forbid)
		}
	}
}

// TestIsolation_WalkFilters pins the walk's exclusions: *_test.go
// files are never scanned and vendor, .git, testdata directories are
// never entered.
func TestIsolation_WalkFilters(t *testing.T) {
	t.Parallel()
	files := []struct {
		path    string
		scanned bool
	}{
		{"engine.go", true},
		{"sub/dir/input.go", true},
		{"engine_test.go", false},
		{"isolation_test.go", false},
		{"README.md", false},
		{"go.mod", false},
	}
	for _, tc := range files {
		if got := scannedFile(tc.path); got != tc.scanned {
			t.Errorf("scannedFile(%q) = %v, want %v", tc.path, got, tc.scanned)
		}
	}
	dirs := []struct {
		name    string
		skipped bool
	}{
		{"vendor", true},
		{".git", true},
		{"testdata", true},
		{"sub", false},
		{"testdatax", false},
	}
	for _, tc := range dirs {
		if got := skippedDir(tc.name); got != tc.skipped {
			t.Errorf("skippedDir(%q) = %v, want %v", tc.name, got, tc.skipped)
		}
	}
}
