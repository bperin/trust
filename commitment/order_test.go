package commitment

import (
	"bytes"
	"errors"
	"testing"
)

func TestSortLeaves_Ascending(t *testing.T) {
	cases := []struct {
		name   string
		leaves [][32]byte
	}{
		{"reversed", [][32]byte{{0x03}, {0x02}, {0x01}}},
		{"duplicates", [][32]byte{{0x02}, {0x01}, {0x02}, {0x01}}},
		{"last-byte order", [][32]byte{{0x01, 0x00, 0x03}, {0x01, 0x00, 0x02}, {0x01, 0x00, 0x01}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sortLeaves(tc.leaves)
			for i := 1; i < len(tc.leaves); i++ {
				if bytes.Compare(tc.leaves[i-1][:], tc.leaves[i][:]) > 0 {
					t.Errorf("leaves[%d] = %x > leaves[%d] = %x, want ascending order", i-1, tc.leaves[i-1], i, tc.leaves[i])
				}
			}
		})
	}
}

func TestSortLeaves_Empty(t *testing.T) {
	sortLeaves(nil)
	sortLeaves([][32]byte{})
}

func TestSortLeaves_Single(t *testing.T) {
	leaf := [32]byte{0xaa}
	leaves := [][32]byte{leaf}
	sortLeaves(leaves)
	if leaves[0] != leaf {
		t.Errorf("leaves[0] = %x, want %x", leaves[0], leaf)
	}
}

func TestRejectDuplicates_Equal(t *testing.T) {
	h := [32]byte{0x01}
	err := rejectDuplicates([][32]byte{h, h})
	if !errors.Is(err, ErrDuplicateObject) {
		t.Errorf("rejectDuplicates() err = %v, want ErrDuplicateObject", err)
	}
}

func TestRejectDuplicates_Empty(t *testing.T) {
	if err := rejectDuplicates(nil); err != nil {
		t.Errorf("rejectDuplicates(nil) err = %v, want nil", err)
	}
	if err := rejectDuplicates([][32]byte{}); err != nil {
		t.Errorf("rejectDuplicates(empty) err = %v, want nil", err)
	}
}

func TestRejectDuplicates_AdjacentNonEqual(t *testing.T) {
	a := [32]byte{0x01}
	b := [32]byte{0x01}
	b[31] = 0x02
	if err := rejectDuplicates([][32]byte{a, b}); err != nil {
		t.Errorf("rejectDuplicates() err = %v, want nil", err)
	}
}
