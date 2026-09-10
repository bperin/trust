package main

import (
	"fmt"

	"github.com/bperin/trust/crypto/ed25519"
)

func main() {
	priv, pub, err := ed25519.GenerateKey()
	if err != nil {
		panic(err)
	}

	commitHash := "8befcdee82117635268e5a7beaa72bebb92f8656"
	statement := fmt.Sprintf("Brian Perin | San Francisco, CA | trust platform author attestation for commit %s", commitHash)

	sig := priv.Sign([]byte(statement))
	valid := pub.Verify(sig, []byte(statement))

	fmt.Printf("=== TRUST PLATFORM CRYPTOGRAPHIC PROVENANCE ATTESTATION ===\n")
	fmt.Printf("Author: Brian Perin (San Francisco, CA)\n")
	fmt.Printf("Commit Hash: %s\n", commitHash)
	fmt.Printf("Public Key (hex): %x\n", pub.Bytes())
	fmt.Printf("Signature (hex): %x\n", sig)
	fmt.Printf("Signature Verified: %v\n", valid)
}
