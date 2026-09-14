// Command consumer is a scratch consumer that exercises the exposed
// trust and chain interfaces without copying code. It verifies that
// the public API surface is sufficient for an external consumer
// (trakt2-crypto) to build against.
//
// The program exercises:
//   - Ed25519 and secp256k1 sign/verify via the signature dispatch
//   - Canonical JSON and CBOR encoding
//   - Merkle tree inclusion proof generation and verification
//   - EAT/CBOR token issuance and verification
//   - EIP-712 domain separator hashing
//   - Wallet transaction signing and decoding
//
// It exits non-zero on any failure. No network access, no I/O beyond
// stdout for a success marker.
package main

import (
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"os"
	"time"

	"github.com/bperin/trust/chain/eip712"
	"github.com/bperin/trust/chain/ethereum"
	"github.com/bperin/trust/chain/wallet"
	"github.com/bperin/trust/trust/attestation"
	"github.com/bperin/trust/trust/canonical"
	"github.com/bperin/trust/trust/crypto/ed25519"
	"github.com/bperin/trust/trust/crypto/secp256k1"
	"github.com/bperin/trust/trust/merkle"
	"github.com/bperin/trust/trust/signature"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "consumer: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("consumer: all interface checks passed")
}

func run() error {
	if err := exerciseSignatures(); err != nil {
		return fmt.Errorf("signatures: %w", err)
	}
	if err := exerciseCanonical(); err != nil {
		return fmt.Errorf("canonical: %w", err)
	}
	if err := exerciseMerkle(); err != nil {
		return fmt.Errorf("merkle: %w", err)
	}
	if err := exerciseEAT(); err != nil {
		return fmt.Errorf("eat: %w", err)
	}
	if err := exerciseEIP712(); err != nil {
		return fmt.Errorf("eip712: %w", err)
	}
	if err := exerciseWallet(); err != nil {
		return fmt.Errorf("wallet: %w", err)
	}
	return nil
}

// exerciseSignatures verifies Ed25519 and secp256k1 sign/verify through
// the unified signature dispatch.
func exerciseSignatures() error {
	// Ed25519 via the signature package.
	edPriv, edPub, err := ed25519.GenerateKey()
	if err != nil {
		return fmt.Errorf("ed25519 generate: %w", err)
	}
	msg := []byte("consumer scratch test")
	sig, err := signature.Sign(signature.AlgorithmEdDSA, edPriv, msg)
	if err != nil {
		return fmt.Errorf("ed25519 sign: %w", err)
	}
	ok, err := signature.Verify(signature.AlgorithmEdDSA, edPub, sig, msg)
	if err != nil {
		return fmt.Errorf("ed25519 verify: %w", err)
	}
	if !ok {
		return errors.New("ed25519 verify returned false")
	}

	// secp256k1 via the signature package.
	secPriv, secPub, err := secp256k1.GenerateKey()
	if err != nil {
		return fmt.Errorf("secp256k1 generate: %w", err)
	}
	digest := []byte("0123456789abcdef0123456789abcdef") // 32 bytes
	if len(digest) != 32 {
		return errors.New("digest length bug in scratch consumer")
	}
	sig2, err := signature.Sign(signature.AlgorithmES256K, secPriv, digest)
	if err != nil {
		return fmt.Errorf("secp256k1 sign: %w", err)
	}
	ok2, err := signature.Verify(signature.AlgorithmES256K, secPub, sig2, digest)
	if err != nil {
		return fmt.Errorf("secp256k1 verify: %w", err)
	}
	if !ok2 {
		return errors.New("secp256k1 verify returned false")
	}

	// Algorithm resolution from key types.
	alg, err := signature.AlgorithmForPrivateKey(edPriv)
	if err != nil {
		return fmt.Errorf("algorithm for ed25519 private key: %w", err)
	}
	if alg != signature.AlgorithmEdDSA {
		return fmt.Errorf("ed25519 algorithm: got %s, want EdDSA", alg.JOSE())
	}
	alg2, err := signature.AlgorithmForPublicKey(secPub)
	if err != nil {
		return fmt.Errorf("algorithm for secp256k1 public key: %w", err)
	}
	if alg2 != signature.AlgorithmES256K {
		return fmt.Errorf("secp256k1 algorithm: got %s, want ES256K", alg2.JOSE())
	}

	// JOSE/COSE projections.
	if signature.AlgorithmEdDSA.JOSE() != "EdDSA" {
		return fmt.Errorf("EdDSA.JOSE: got %q", signature.AlgorithmEdDSA.JOSE())
	}
	if signature.AlgorithmEdDSA.COSE() != -8 {
		return fmt.Errorf("EdDSA.COSE: got %d", signature.AlgorithmEdDSA.COSE())
	}
	return nil
}

// exerciseCanonical verifies canonical JSON (JCS) and CBOR encoding.
func exerciseCanonical() error {
	doc := map[string]any{
		"b": 1,
		"a": "hello",
		"c": true,
	}

	// JCS: keys sorted, numbers in shortest form.
	jcs, err := canonical.JSONCanonicalize(doc)
	if err != nil {
		return fmt.Errorf("JSONCanonicalize: %w", err)
	}
	wantJCS := `{"a":"hello","b":1,"c":true}`
	if string(jcs) != wantJCS {
		return fmt.Errorf("JCS: got %s, want %s", jcs, wantJCS)
	}

	// CBOR deterministic encoding.
	cborBytes, err := canonical.CBOREncode(doc)
	if err != nil {
		return fmt.Errorf("CBOREncode: %w", err)
	}
	if len(cborBytes) == 0 {
		return errors.New("CBOR encoding is empty")
	}

	// Canonical hash via the EncodingDeclarer-free path.
	hash, err := canonical.CanonicalHash(doc)
	if err != nil {
		return fmt.Errorf("CanonicalHash: %w", err)
	}
	var zero [32]byte
	if subtle.ConstantTimeCompare(hash[:], zero[:]) == 1 {
		return errors.New("canonical hash is all-zero")
	}

	// Marshal dispatch.
	jcs2, err := canonical.Marshal(doc, canonical.EncodingJSON)
	if err != nil {
		return fmt.Errorf("Marshal JSON: %w", err)
	}
	if string(jcs2) != wantJCS {
		return fmt.Errorf("Marshal JSON: got %s, want %s", jcs2, wantJCS)
	}
	cbor2, err := canonical.Marshal(doc, canonical.EncodingCBOR)
	if err != nil {
		return fmt.Errorf("Marshal CBOR: %w", err)
	}
	if subtle.ConstantTimeCompare(cbor2, cborBytes) != 1 {
		return errors.New("Marshal CBOR mismatch with CBOREncode")
	}
	return nil
}

// exerciseMerkle verifies Merkle tree construction, inclusion proof
// generation, and verification.
func exerciseMerkle() error {
	leaves := [][]byte{
		[]byte("leaf0"),
		[]byte("leaf1"),
		[]byte("leaf2"),
		[]byte("leaf3"),
	}
	tree, err := merkle.New(leaves)
	if err != nil {
		return fmt.Errorf("merkle.New: %w", err)
	}
	if tree.Size() != len(leaves) {
		return fmt.Errorf("tree size: got %d, want %d", tree.Size(), len(leaves))
	}
	root := tree.Root()
	if len(root) != 32 {
		return fmt.Errorf("root length: got %d, want 32", len(root))
	}

	// Inclusion proof for leaf 1.
	path, err := tree.Proof(1)
	if err != nil {
		return fmt.Errorf("tree.Proof(1): %w", err)
	}
	if !merkle.Verify(root, leaves[1], path) {
		return errors.New("merkle.Verify returned false for valid proof")
	}

	// Tampered leaf must fail.
	if merkle.Verify(root, []byte("tampered"), path) {
		return errors.New("merkle.Verify returned true for tampered leaf")
	}

	// Consistency proof.
	cp, err := tree.ConsistencyProof(2, 4)
	if err != nil {
		return fmt.Errorf("ConsistencyProof(2,4): %w", err)
	}
	// Build the old root (tree of first 2 leaves) for consistency verify.
	oldTree, err := merkle.New(leaves[:2])
	if err != nil {
		return fmt.Errorf("merkle.New (old): %w", err)
	}
	if !merkle.VerifyConsistency(oldTree.Root(), root, 2, 4, cp) {
		return errors.New("VerifyConsistency returned false for valid proof")
	}
	return nil
}

// exerciseEAT verifies EAT/CBOR token issuance and verification.
func exerciseEAT() error {
	priv, pub, err := ed25519.GenerateKey()
	if err != nil {
		return fmt.Errorf("ed25519 generate: %w", err)
	}

	claims := map[int64]any{
		attestation.ClaimIssuer:   "did:example:issuer",
		attestation.ClaimSubject:  "did:example:subject",
		attestation.ClaimAudience: "did:example:verifier",
		attestation.ClaimExpiry:   time.Now().Add(time.Hour).Unix(),
		attestation.ClaimNonce:    []byte("nonce-scratch"),
	}

	token, err := attestation.Issue(claims, priv, attestation.IssueOptions{
		VerificationMethod: "did:example:issuer#keys-1",
	})
	if err != nil {
		return fmt.Errorf("attestation.Issue: %w", err)
	}
	if len(token) == 0 {
		return errors.New("EAT token is empty")
	}

	recovered, err := attestation.Verify(token, pub, attestation.VerifyOptions{
		ExpectedIssuer:   "did:example:issuer",
		ExpectedAudience: "did:example:verifier",
	})
	if err != nil {
		return fmt.Errorf("attestation.Verify: %w", err)
	}
	if recovered[attestation.ClaimIssuer] != "did:example:issuer" {
		return fmt.Errorf("EAT issuer: got %v, want did:example:issuer", recovered[attestation.ClaimIssuer])
	}

	// Wrong key must fail.
	_, wrongPub, err := ed25519.GenerateKey()
	if err != nil {
		return fmt.Errorf("ed25519 generate wrong: %w", err)
	}
	if _, err := attestation.Verify(token, wrongPub, attestation.VerifyOptions{}); err == nil {
		return errors.New("EAT verify with wrong key succeeded")
	}
	return nil
}

// exerciseEIP712 verifies EIP-712 domain separator hashing.
func exerciseEIP712() error {
	contract, err := ethereum.ParseAddress("0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC")
	if err != nil {
		return fmt.Errorf("ParseAddress: %w", err)
	}
	domain := eip712.DomainSeparator{
		Name:              "Ether Mail",
		Version:           "1",
		ChainID:           big.NewInt(1),
		VerifyingContract: contract,
		Salt:              [32]byte{},
	}
	domainHash, err := domain.Hash()
	if err != nil {
		return fmt.Errorf("domain.Hash: %w", err)
	}

	// Known domain separator hash from the EIP-712 spec construction.
	wantHash, err := hex.DecodeString("ba1e6aec2f6172251cb55ec0e50442204e0123504810a148c631bf43b74546f2")
	if err != nil {
		return fmt.Errorf("hex decode: %w", err)
	}
	if subtle.ConstantTimeCompare(domainHash[:], wantHash) != 1 {
		return fmt.Errorf("domain hash: got %x, want %x", domainHash[:], wantHash)
	}

	// Struct hash + digest.
	personType := "Person(address owner,uint256 amount)"
	personTypeHash := eip712.HashStruct([]byte(personType), nil)
	owner := make([]byte, 32)
	copy(owner[12:], contract[:])
	amount := make([]byte, 32)
	amount[31] = 100
	encoded := append(owner, amount...)
	structHash := eip712.HashStruct(personTypeHash[:], encoded)
	digest := eip712.Digest(domainHash, structHash)
	var zero [32]byte
	if subtle.ConstantTimeCompare(digest[:], zero[:]) == 1 {
		return errors.New("EIP-712 digest is all-zero")
	}
	return nil
}

// exerciseWallet verifies wallet transaction signing and decoding.
func exerciseWallet() error {
	privBytes, err := hex.DecodeString("ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80")
	if err != nil {
		return fmt.Errorf("hex decode privkey: %w", err)
	}
	priv, err := secp256k1.NewPrivateKey(privBytes)
	if err != nil {
		return fmt.Errorf("secp256k1.NewPrivateKey: %w", err)
	}
	w := wallet.NewWallet(priv)

	addr, err := w.Address()
	if err != nil {
		return fmt.Errorf("wallet.Address: %w", err)
	}
	// Known Hardhat account #0 address.
	wantAddr := "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"
	if addr.Hex() != wantAddr {
		return fmt.Errorf("wallet address: got %s, want %s", addr.Hex(), wantAddr)
	}

	// Sign a legacy transaction and decode it back.
	to, err := ethereum.ParseAddress("0x70997970C51812dc3A010C7d01b50e0d17dc79C8")
	if err != nil {
		return fmt.Errorf("ParseAddress to: %w", err)
	}
	tx := &wallet.LegacyTx{
		ChainID:  big.NewInt(1),
		Nonce:    0,
		GasPrice: big.NewInt(1_000_000_000),
		GasLimit: 21000,
		To:       &to,
		Value:    big.NewInt(1e18),
		Data:     nil,
	}
	raw, err := w.SignTx(tx)
	if err != nil {
		return fmt.Errorf("wallet.SignTx: %w", err)
	}
	if len(raw) == 0 {
		return errors.New("signed transaction is empty")
	}

	decoded, err := wallet.DecodeTransaction(raw)
	if err != nil {
		return fmt.Errorf("wallet.DecodeTransaction: %w", err)
	}
	if decoded.Type != 0 {
		return fmt.Errorf("decoded type: got %d, want 0", decoded.Type)
	}
	if decoded.Sender.Hex() != wantAddr {
		return fmt.Errorf("decoded sender: got %s, want %s", decoded.Sender.Hex(), wantAddr)
	}
	if decoded.Nonce != 0 {
		return fmt.Errorf("decoded nonce: got %d, want 0", decoded.Nonce)
	}
	return nil
}
