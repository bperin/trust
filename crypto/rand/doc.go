// Package rand provides cryptographically secure random number
// generation backed by the OS CSPRNG. All key generation, nonce
// generation, and token generation in the trust platform uses this
// package.
//
// This package wraps Go's crypto/rand, which reads from the OS entropy
// pool. No user-space DRBG is implemented.
package rand
