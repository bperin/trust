module github.com/bperin/auth

go 1.27.1

replace github.com/bperin/trust => ../trust

require github.com/bperin/trust v0.0.0-20260910123724-b8757b4a1708

require (
	github.com/decred/dcrd/dcrec/secp256k1/v4 v4.4.1 // indirect
	github.com/fxamacker/cbor/v2 v2.9.3 // indirect
	github.com/klauspost/cpuid/v2 v2.0.12 // indirect
	github.com/x448/float16 v0.8.4 // indirect
	github.com/zeebo/blake3 v0.2.4 // indirect
	golang.org/x/crypto v0.57.0 // indirect
	golang.org/x/sys v0.48.0 // indirect
)
