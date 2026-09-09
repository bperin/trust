# crypto/ed25519 — Wycheproof Testing

This package tests against [Project Wycheproof](https://github.com/C2SP/wycheproof)
EdDSA vectors (`testdata/ed25519_test.json`).

## Test data source

```
testvectors_v1/ed25519_test.json
```

From [C2SP/wycheproof](https://github.com/C2SP/wycheproof) master
branch, `testvectors_v1/` directory.

## Format

Ed25519 Wycheproof vectors use the same formats our wrapper accepts:
32-byte public keys and 64-byte signatures. No conversion needed.

## Result mapping

| Wycheproof result | Our expectation |
|-------------------|-----------------|
| `valid` | Verify returns true |
| `acceptable` | Verify returns true |
| `invalid` | Verify returns false |
