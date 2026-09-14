package rand

import (
	"crypto/rand"
	"errors"
	"fmt"
)

// ErrNegativeLength is returned by Bytes when n < 0.
var ErrNegativeLength = errors.New("rand: negative length")

// Reader is the CSPRNG reader. It delegates to crypto/rand.Reader for
// io.Reader consumers that need a streaming random source.
var Reader = rand.Reader

// Bytes returns n cryptographically secure random bytes from the OS
// CSPRNG. Returns an empty slice for n == 0, ErrNegativeLength for
// n < 0. This is a raw primitive — no token formatting or hex encoding.
func Bytes(n int) ([]byte, error) {
	if n < 0 {
		return nil, ErrNegativeLength
	}
	if n == 0 {
		return []byte{}, nil
	}
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return nil, fmt.Errorf("rand: CSPRNG read failed: %w", err)
	}
	return b, nil
}
