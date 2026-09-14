package rand

import (
	"crypto/rand"
	"errors"
	"fmt"
)

// ErrNegativeLength is returned by Bytes, which implements [SP 800-90A],
// when n < 0.
var ErrNegativeLength = errors.New("rand: negative length")

// Reader is the standard [SP 800-90A] CSPRNG reader. It delegates to
// crypto/rand.Reader for io.Reader consumers that need a streaming
// random source.
var Reader = rand.Reader

// Bytes implements [SP 800-90A] — returns n cryptographically secure
// random bytes read from the OS CSPRNG.
//
// Returns an empty (non-nil) slice for n == 0. Returns ErrNegativeLength
// for n < 0. A non-nil error is also returned if the underlying OS CSPRNG
// read fails, though crypto/rand.Read reports such failures by panicking
// on most platforms. This is a raw primitive — no token formatting, no
// hex encoding. Callers needing formatted tokens should use the auth layer.
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
