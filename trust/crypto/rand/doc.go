// Package rand provides cryptographically secure random number generation
// backed by the OS CSPRNG via [SP 800-90A]. All key generation, nonce
// generation, and token generation in the trust platform uses this package.
//
// This package wraps Go's crypto/rand, which reads from the OS entropy
// pool (getrandom on Linux, SecRandomCopyBytes on macOS, CryptGenRandom
// on Windows). No user-space DRBG is implemented — the OS CSPRNG is
// FIPS-validated on certified platforms.
package rand
