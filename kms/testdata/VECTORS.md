# KMS verification vectors

Committed wire-format vectors for `TestVerifyKMSVectors`. Each vector is a
message, the signature a signing operation produced over it, and the public
key in DER X.509 SubjectPublicKeyInfo form. Nothing here needs network
access; the files are the evidence.

All four messages are the same 36 bytes: `trakt-spec-003-kms-wire-format-probe`.

## Recorded from Cloud KMS (live)

Captured 2026-09-16 from project `trakt-agentic-platform`, region
`us-central1`, key ring `trakt-org-keys`, key version 1. Both signatures were
verified independently under OpenSSL 3.x on the capture date
(`openssl dgst -verify <pubkey.pem>` for Ed25519,
`openssl dgst -sha384 -verify <pubkey.pem> -signature <sig.der>` for P-384)
before being committed here.

| Files                     | Key resource                                       | Algorithm                            | Protection | Wire format                                                     |
| ------------------------- | -------------------------------------------------- | ------------------------------------ | ---------- | --------------------------------------------------------------- |
| `kms_ed25519_*`           | `cryptoKeys/trakt-org-root-dev/cryptoKeyVersions/1` | `EC_SIGN_ED25519`                    | SOFTWARE   | raw 64-byte Ed25519 signature over the unhashed message         |
| `kms_p384_*`              | `cryptoKeys/trakt-org-root-dev-p384/…/1`            | `EC_SIGN_P384_SHA384`                | HSM        | 102-byte DER `ECDSA-Sig-Value` (`r`, `s` 48 bytes each) over SHA-384 |

Each group is three files: `_msg`, `_signature`, and the public key —
`kms_ed25519_pubkey` and `kms_p384_der_pubkey`. All four public keys are DER
X.509 SubjectPublicKeyInfo, which is what the provider returns.

## Synthetic (no KMS key provisioned)

`kms_p256_*` and `kms_es256k_*` were **not** produced by Cloud KMS — no P-256
or secp256k1 key exists in the ring. They are locally generated key pairs,
signed with the same wire format the provider uses for that family (DER
`ECDSA-Sig-Value` over the curve's mandated digest: SHA-256 for both), and
committed so the DER-to-`r||s` conversion and the P-256 SPKI decode paths have
committed vectors too. Treat them as format fixtures, not as provider
evidence.

| Files            | Origin    | Algorithm              | Wire format                                          |
| ---------------- | --------- | ---------------------- | ---------------------------------------------------- |
| `kms_p256_*`     | synthetic | ECDSA P-256 + SHA-256  | DER `ECDSA-Sig-Value` (70 bytes) over SHA-256        |
| `kms_es256k_*`   | synthetic | ECDSA secp256k1 + SHA-256 | DER `ECDSA-Sig-Value` (71 bytes), low-s, over SHA-256 |

`ES256K`'s wire format is raw `r||s`, not DER, so `TestVerifyKMSVectors`
converts the stored secp256k1 DER with `kms/der.ParseECDSASignature` and
`NormalizeLowS` before verifying — the provider-to-wire conversion is therefore
covered by committed bytes too.

## Verification commands

```sh
go test ./kms/... -run TestVerifyKMSVectors -v
go test ./kms/... -run TestParsePublicKeyDER -v
```
