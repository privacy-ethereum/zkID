# zkID Circuit Specification

This document describes the Circom circuits in this directory.

## Overview

The circuits verify Taiwan Citizen Digital Certificate (MOICA) X.509
certificates signed with RSA-SHA256, plus a per-session user-device signature
over arbitrary data (the "TBS" sent to the HiPKI card). They also assert
non-revocation against a Sparse Merkle Tree (SMT).

## Active circuits

| Circuit              | Template           | Description                                                              |
| -------------------- | ------------------ | ------------------------------------------------------------------------ |
| `certChainRS2048`  | `CertChainRSA256`  | Circuit A — cert chain + revocation + pkCommit (MOICA-G2)               |
| `certChainRS4096`  | `CertChainRSA256`  | Circuit A — cert chain + revocation + pkCommit (MOICA-G3)               |
| `userSigRS2048`  | `UserSigRSA256`  | Circuit B — device signature + nullifier + appIdPacked + pkCommit       |

The two-circuit split replaces the former monolithic `FullCertRSA256VerifyWithRevocation`.
Circuit A and Circuit B are linked via `pkCommit`: the verifier checks
`pkCommit_A == pkCommit_B` to bind both proofs to the same user key.

## What the circuits prove

### Circuit A — CertChain (`CertChainRSA256`)

1. **Cert chain verify** — `issuerRsaModulus` (MOICA) verifies
   `issuerRsaSignature` over `issuerTbs` (the TBS portion of the user's
   cert). Proves that MOICA certified the user's public key.
2. **DER parsing** — `VerifyTBSinCert`, `VerifySerialNumber`
   check that the user cert contains the claimed TBS and serial number at the
   prover-supplied offsets.
3. **Revocation** — `SMTNonMembershipVerifier` proves `serialNumber` is **not**
   in the revocation tree rooted at `smtRoot`.
4. **Linking** — `pkCommit = ChunkedPoseidonP256(userRsaExtractedModulus ‖ pkBlind)`,
   where `pkBlind` is a per-session uniform 248-bit value sampled by the
   prover. The same value is used in Circuit B; the verifier checks
   `pkCommit_A == pkCommit_B`. See §"Why per-session randomness for `pkBlind`"
   below.

### Circuit B — UserSig (`UserSigRSA256`)

1. **App-id binding** — the public output `appIdPacked` is constrained to
   equal `tbs[0..31]` (the SHA-256-padded payload the card signs) packed
   little-endian into one field element. The verifier unpacks and byte-compares
   against the issued challenge's `app_id`.
2. **Device signature verify** — `userPkLimbs` verifies `userRsaSignature`
   over `tbs`. Proves the holder of the user's private key signed the app-id bytes.
3. **Linking** — same `pkCommit` formula as Circuit A, using the same
   `pkBlind` value.
4. **Nullifier** — `nullifier = ChunkedPoseidonP256(userRsaSignature)`
   (public output). PKCS#1 v1.5 signing is deterministic and the signature
   never leaves the card, so the nullifier is deterministic per
   `(card, app_id)` and unforgeable without the card's private key.

## Public inputs / outputs

### Circuit A — CertChain

| Signal                  | Visibility    | Notes                                                  |
| ----------------------- | ------------- | ------------------------------------------------------ |
| `issuerRsaModulus[k]`   | public input  | MOICA's RSA public key (trust anchor)                  |
| `smtRoot`               | public input  | Revocation SMT root                                    |
| `pkCommit`              | public output | Links to Circuit B                                     |

Public-value vector layout (in declaration order, outputs first):
- RS2048: `[pkCommit, issuerRsaModulus[17], smtRoot]` — 19 elements
- RS4096: `[pkCommit, issuerRsaModulus[34], smtRoot]` — 36 elements

### Circuit B — UserSig

| Signal         | Visibility    | Notes                                                              |
| -------------- | ------------- | ------------------------------------------------------------------ |
| `challenge`    | public input  | Verifier-issued per-session nonce; bound via dummy square          |
| `pkCommit`     | public output | Must match Circuit A's `pkCommit`                                  |
| `nullifier`    | public output | `ChunkedPoseidonP256(userRsaSignature)`; per-(card, app_id) ID    |
| `appIdPacked`  | public output | `tbs[0..31]` packed little-endian into one field element           |

Public-value vector layout: `[pkCommit, nullifier, appIdPacked, challenge]` — 4 elements.

All other signals (user cert bytes, RSA signatures, SMT proof path,
`tbs`, `pkBlind`) are private.

## Revocation

Revocation uses a Sparse Merkle Tree non-membership proof against the SMT
maintained by the
[`moica-revocation-smt`](https://github.com/moven0831/moica-revocation-smt)
service. Circuit A verifies that the cert's `serialNumber` is not present in
the tree rooted at `smtRoot`.

## Why per-session randomness for `pkBlind`

`pkCommit` must hide the user's RSA modulus from anyone who sees only the
public proof outputs (`pkCommit`, `nullifier`, `appIdPacked`,
`issuerRsaModulus`, `smtRoot`). The assumed adversary holds the full MOICA
cert directory — every citizen's `userPkLimbs`. Any deterministic derivation of
`pkBlind` from public or leaked inputs lets that adversary recompute
`pkCommit` for each `userPkLimbs` and match against the observed value.

A per-session uniform 248-bit `pkBlind` removes that attack: every `userPkLimbs`
candidate is equally consistent with the observed `pkCommit`.

`pkCommit` only needs to link Circuits A and B within a single submission,
so it doesn't need to be reproducible. Sybil resistance per `(card, app_id)`
is carried by `nullifier = ChunkedPoseidonP256(userRsaSignature)` instead,
whose secrecy rests on the RSA private key never leaving the card.

## See also

- [`../ecdsa-spartan2/README.md`](../ecdsa-spartan2/README.md) — Rust prover CLI
- `circuits/components/smtNonmembership.circom` — SMT non-membership verification
- `circuits/components/smtVerifierP256.circom` — SMT verifier with Poseidon-P256 hash
- `circuits/components/poseidonP256.circom` — Poseidon hash over secq256r1
- `circuits/components/pkCommit.circom` — `ChunkedPoseidonP256` for `pkCommit`
- `circuits/utils/utils.circom` — cert parsing helpers (`VerifyTBSinCert`, `VerifySerialNumber`, `ExtractModulus`, `PackBytes`, `PoseidonBytes`)
