// Package hash provides wrappers for cryptographic hash functions with a
// consistent API.
//
// All hash functions in this package are deterministic — the same input
// always produces the same output. Hashes are not encryption: the output
// cannot be reversed to recover the input.
package hash
