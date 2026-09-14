// Module github.com/bperin/trust/kms — remote-KMS signing core for
// secp256k1: RemoteSigner interface, DER/SPKI public-key parsing, and
// recovery-id computation for JOSE/COSE ES256K and EVM signing paths.
// Cloud provider adapters live in the private trakt2-crypto repository.
// Depends on trust only.
module github.com/bperin/trust/kms

go 1.27.1

require github.com/bperin/trust/trust v0.1.0

require (
	github.com/decred/dcrd/dcrec/secp256k1/v4 v4.4.1 // indirect
	github.com/klauspost/cpuid/v2 v2.0.12 // indirect
	github.com/zeebo/blake3 v0.2.4 // indirect
	golang.org/x/crypto v0.57.0 // indirect
	golang.org/x/sys v0.48.0 // indirect
)
