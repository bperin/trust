package hash

import (
	"strings"
	"testing"
)

func BenchmarkKeccak256_Sum(b *testing.B) {
	h := NewKeccak256()
	data := []byte("the quick brown fox jumps over the lazy dog")

	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		_ = h.Sum(data)
	}
}

func BenchmarkKeccak256_Sum_Large(b *testing.B) {
	h := NewKeccak256()
	data := []byte(strings.Repeat("a", 4096))

	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		_ = h.Sum(data)
	}
}

func BenchmarkKeccak256_SumBytes(b *testing.B) {
	h := NewKeccak256()
	data := []byte("the quick brown fox jumps over the lazy dog")

	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		_ = h.SumBytes(data)
	}
}
