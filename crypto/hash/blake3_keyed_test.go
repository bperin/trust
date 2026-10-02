package hash

import (
	"bytes"
	"testing"
)

func TestKeyedSumIsDeterministicPerKey(t *testing.T) {
	key := bytes.Repeat([]byte{0x2a}, 32)
	data := []byte("mClickID-9f3a")
	a, err := KeyedSum(key, data)
	if err != nil {
		t.Fatalf("KeyedSum: %v", err)
	}
	b, err := KeyedSum(key, data)
	if err != nil {
		t.Fatalf("KeyedSum: %v", err)
	}
	if !bytes.Equal(a, b) {
		t.Fatal("same key and input must produce the same digest")
	}
	if len(a) != 32 {
		t.Fatalf("expected 32-byte digest, got %d", len(a))
	}
}

func TestKeyedSumSeparatesKeyContexts(t *testing.T) {
	data := []byte("mClickID-9f3a")
	a, err := KeyedSum(bytes.Repeat([]byte{0x01}, 32), data)
	if err != nil {
		t.Fatalf("KeyedSum: %v", err)
	}
	b, err := KeyedSum(bytes.Repeat([]byte{0x02}, 32), data)
	if err != nil {
		t.Fatalf("KeyedSum: %v", err)
	}
	if bytes.Equal(a, b) {
		t.Fatal("different keys must not produce the same digest")
	}
}

func TestKeyedSumRejectsWrongKeyLength(t *testing.T) {
	for _, n := range []int{0, 16, 31, 33, 64} {
		if _, err := KeyedSum(make([]byte, n), []byte("x")); err == nil {
			t.Fatalf("expected error for %d-byte key", n)
		}
	}
}
