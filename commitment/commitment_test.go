package commitment

import (
	"testing"

	"github.com/bperin/trust/canonical"
)

var _ canonical.EncodingDeclarer = (*Commitment)(nil)

func TestCommitmentType_Shape(t *testing.T) {
	c := Commitment{Root: [32]byte{}, Size: 0, LeafHashes: nil, Algorithm: AlgorithmRFC6962SHA256}
	if c.Root != ([32]byte{}) {
		t.Errorf("Root = %x, want zero", c.Root)
	}
	if c.Size != 0 {
		t.Errorf("Size = %d, want 0", c.Size)
	}
	if c.LeafHashes != nil {
		t.Errorf("LeafHashes = %v, want nil", c.LeafHashes)
	}
	if c.Algorithm != "rfc6962-sha256" {
		t.Errorf("Algorithm = %q, want %q", c.Algorithm, "rfc6962-sha256")
	}
	if AlgorithmRFC6962SHA256 != "rfc6962-sha256" {
		t.Errorf("AlgorithmRFC6962SHA256 = %q, want %q", AlgorithmRFC6962SHA256, "rfc6962-sha256")
	}
}

func TestCommitmentCanonicalEncodingDeclarer(t *testing.T) {
	c := &Commitment{}
	if got := c.CanonicalEncoding(); got != canonical.EncodingJSON {
		t.Errorf("CanonicalEncoding() = %v, want %v", got, canonical.EncodingJSON)
	}
}
