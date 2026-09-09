# crypto/secp256k1 — Wycheproof Testing

This package tests against [Project Wycheproof](https://github.com/C2SP/wycheproof)
ECDSA secp256k1 SHA-256 vectors (`testdata/ecdsa_secp256k1_sha256_test.json`).

## Format conversion

Wycheproof secp256k1 vectors use formats our wrapper doesn't accept
directly:

| Wycheproof | Our wrapper |
|-----------|-------------|
| DER-encoded signatures (`30 45 02 20 ...`) | 64-byte `r || s` |
| Uncompressed public keys (65 bytes, `04 || x || y`) | Compressed (33 bytes) |

The test harness (`derToRS`, `uncompressedToCompressed`) converts
between these. Strict DER validation catches ModifiedSignature and
ModifiedInteger cases that test parser leniency.

## EIP-2 low-s vs raw ECDSA

Our wrapper enforces [EIP-2] low-s canonicalization on both Sign
(produce low-s) and Verify (reject high-s where `s > n/2`). This is an
Ethereum-specific malleability defense.

Wycheproof's secp256k1 vectors test **raw ECDSA** — they accept high-s
signatures as valid. These are different contracts, not stricter vs
looser. The test harness detects high-s in valid Wycheproof cases and
expects our Verify to reject them. This is correct: our wrapper has an
EIP-2 contract that Wycheproof's raw ECDSA vectors don't test.

## Test data source

```
testvectors_v1/ecdsa_secp256k1_sha256_test.json
```

From [C2SP/wycheproof](https://github.com/C2SP/wycheproof) master
branch, `testvectors_v1/` directory.
