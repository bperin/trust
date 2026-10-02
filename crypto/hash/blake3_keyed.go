package hash

import (
	"errors"

	"github.com/zeebo/blake3"
)

// KeyedSum returns the keyed BLAKE3 digest of data under key. The key must be
// exactly 32 bytes. Unlike Sum, the same input under two different keys
// produces unrelated digests, so observations cannot be linked across key
// contexts (e.g. pixel-scoped identifier pseudonymization) while staying
// deterministic within one key context.
func KeyedSum(key, data []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, errors.New("blake3 keyed hash requires a 32-byte key")
	}
	h, err := blake3.NewKeyed(key)
	if err != nil {
		return nil, err
	}
	h.Write(data)
	return h.Sum(nil), nil
}
