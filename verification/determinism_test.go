package verification

import (
	"sync"
	"testing"
)

// resultsEqual reports whether two Results carry identical payload:
// Valid, per-check records, failures, and the provenance digest.
// Comparison is over slices only — never map iteration order.
func resultsEqual(a, b *Result) bool {
	if a.Valid != b.Valid || len(a.Checks) != len(b.Checks) || len(a.Failures) != len(b.Failures) {
		return false
	}
	for i := range a.Checks {
		if a.Checks[i].ID != b.Checks[i].ID || a.Checks[i].Status != b.Checks[i].Status {
			return false
		}
	}
	for i := range a.Failures {
		if a.Failures[i].Check != b.Failures[i].Check ||
			a.Failures[i].Hop != b.Failures[i].Hop ||
			a.Failures[i].Detail != b.Failures[i].Detail {
			return false
		}
	}
	h1, err1 := CanonicalHash(a.Provenance)
	h2, err2 := CanonicalHash(b.Provenance)
	if err1 != nil || err2 != nil || hashRefHex(h1) != hashRefHex(h2) {
		return false
	}
	return true
}

// TestDeterminism_FixedNow verifies repeated Verify runs with identical
// Inputs and a fixed Now produce byte-identical Results.
func TestDeterminism_FixedNow(t *testing.T) {
	t.Parallel()
	f := buildFixture(t)
	in := f.inputs()
	e := NewEngine()

	first, err := e.Verify(in)
	if err != nil {
		t.Fatalf("first Verify: %v", err)
	}
	for run := 0; run < 2; run++ {
		again, err := e.Verify(in)
		if err != nil {
			t.Fatalf("run %d: %v", run, err)
		}
		if !resultsEqual(first, again) {
			t.Fatalf("run %d diverged from the first result", run)
		}
	}
}

// TestDeterminism_Concurrent runs N goroutines against one shared
// engine with a fixed Now; run under -race.
func TestDeterminism_Concurrent(t *testing.T) {
	t.Parallel()
	f := buildFixture(t)
	in := f.inputs()
	e := NewEngine()

	first, err := e.Verify(in)
	if err != nil {
		t.Fatalf("first Verify: %v", err)
	}
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			res, err := e.Verify(in)
			if err != nil {
				t.Errorf("goroutine %d: %v", i, err)
				return
			}
			if !resultsEqual(first, res) {
				t.Errorf("goroutine %d result diverged", i)
			}
		}(i)
	}
	wg.Wait()
}
