package commitment

import (
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/bperin/trust/canonical"
)

// commitmentJSON is the wire DTO of a Commitment: binary digests render as lowercase hex strings so the JCS form stays text-only.
type commitmentJSON struct {
	Root       string   `json:"root"`
	Size       int      `json:"size"`
	LeafHashes []string `json:"leafHashes"`
	Algorithm  string   `json:"algorithm"`
}

// MarshalJSON encodes c as its hex DTO; Root and each LeafHashes entry become lowercase hex strings.
func (c *Commitment) MarshalJSON() ([]byte, error) {
	if c == nil {
		return []byte("null"), nil
	}
	dto := commitmentJSON{
		Root:       hex.EncodeToString(c.Root[:]),
		Size:       c.Size,
		LeafHashes: make([]string, len(c.LeafHashes)),
		Algorithm:  c.Algorithm,
	}
	for i := range c.LeafHashes {
		dto.LeafHashes[i] = hex.EncodeToString(c.LeafHashes[i][:])
	}
	return json.Marshal(dto)
}

// UnmarshalJSON decodes the hex DTO, rejecting malformed or wrong-length hex for the root and every leaf.
func (c *Commitment) UnmarshalJSON(b []byte) error {
	var dto commitmentJSON
	if err := json.Unmarshal(b, &dto); err != nil {
		return fmt.Errorf("commitment: decode JSON: %w", err)
	}
	root, err := decodeHash(dto.Root)
	if err != nil {
		return fmt.Errorf("commitment: decode root: %w", err)
	}
	leaves := make([][32]byte, len(dto.LeafHashes))
	for i, s := range dto.LeafHashes {
		h, err := decodeHash(s)
		if err != nil {
			return fmt.Errorf("commitment: decode leafHashes[%d]: %w", i, err)
		}
		leaves[i] = h
	}
	c.Root = root
	c.Size = dto.Size
	c.LeafHashes = leaves
	c.Algorithm = dto.Algorithm
	return nil
}

// decodeHash decodes s as hex into a 32-byte digest, rejecting malformed hex and any length other than 32 bytes.
func decodeHash(s string) ([32]byte, error) {
	var h [32]byte
	b, err := hex.DecodeString(s)
	if err != nil {
		return h, err
	}
	if len(b) != 32 {
		return h, fmt.Errorf("got %d bytes, want 32", len(b))
	}
	copy(h[:], b)
	return h, nil
}

// Marshal returns the [RFC 8785] JCS canonical bytes of c.
func Marshal(c *Commitment) ([]byte, error) {
	return canonical.Marshal(c, canonical.EncodingJSON)
}

// Unmarshal decodes JCS canonical bytes into a Commitment, the inverse of Marshal.
func Unmarshal(b []byte) (*Commitment, error) {
	c := &Commitment{}
	if err := json.Unmarshal(b, c); err != nil {
		return nil, fmt.Errorf("commitment: unmarshal: %w", err)
	}
	return c, nil
}

// CanonicalHash returns the [FIPS 180-4] SHA-256 digest of c's JCS canonical bytes.
func CanonicalHash(c *Commitment) ([32]byte, error) {
	if c == nil {
		return [32]byte{}, ErrNilCommitment
	}
	return canonical.CanonicalHash(c)
}
