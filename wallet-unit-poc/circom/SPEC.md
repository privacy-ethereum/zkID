# zkID Circuit Specification

This document describes the Circom circuits in this directory.

## Overview

The circuits verify Taiwan Citizen Digital Certificate (MOICA) X.509
certificates signed with RSA-SHA256, plus a per-session user-device signature
over arbitrary data (the "TBS" sent to the HiPKI card). They also assert
non-revocation against a Sparse Merkle Tree (SMT).

## Active circuits

| Circuit              | Template           | Description                                                            |
| -------------------- | ------------------ | ---------------------------------------------------------------------- |
| `cert_chain_rs2048`  | `CertChainRSA256`  | Circuit A — cert chain + revocation + pk_commit (MOICA-G2)             |
| `cert_chain_rs4096`  | `CertChainRSA256`  | Circuit A — cert chain + revocation + pk_commit (MOICA-G3)             |
| `device_sig_rs2048`  | `DeviceSigRSA256`  | Circuit B — device signature + nullifier + app_id binding + pk_commit  |

The two-circuit split replaces the former monolithic `FullCertRSA256VerifyWithRevocation`.
Circuit A and Circuit B are linked via `pk_commit`: the verifier checks
`pk_commit_A == pk_commit_B` to bind both proofs to the same user key.

## What the circuits prove

### Circuit A — CertChain (`CertChainRSA256`)

1. **Cert chain verify** — `issuer_rsa_modulus` (MOICA) verifies
   `issuer_rsa_signature` over `issuer_tbs` (the TBS portion of the user's
   cert). Proves that MOICA certified the user's public key.
2. **DER parsing** — `VerifyTBSinCert`, `VerifySubjectDN`, `VerifySerialNumber`
   check that the user cert contains the claimed TBS, subject DN, and serial
   number at the prover-supplied offsets.
3. **Revocation** — `SMTNonMembershipVerifier` proves `serialNumber` is **not**
   in the revocation tree rooted at `smtRoot`.
4. **Linking** — `pk_commit = ChunkedPoseidonP256(user_pk_limbs ‖ pk_blind)`,
   where `pk_blind` is a per-session uniform 248-bit value sampled by the
   prover. The same value is used in Circuit B; the verifier checks
   `pk_commit_A == pk_commit_B`. See §"Why per-session randomness for `pk_blind`"
   below.

### Circuit B — DeviceSig (`DeviceSigRSA256`)

1. **App-id binding** — the public input `app_id_bytes[31]` is constrained to
   equal the first 31 bytes of `tbs` (the SHA-256-padded payload the card
   signs). The verifier byte-compares against the issued challenge's `app_id`.
2. **Device signature verify** — `user_pk_limbs` verifies `user_rsa_signature`
   over `tbs`. Proves the holder of the user's private key signed `app_id_bytes`.
3. **Linking** — same `pk_commit` formula as Circuit A, using the same
   `pk_blind` value.
4. **Nullifier** — `nullifier = ChunkedPoseidonP256(user_rsa_signature)`
   (public output). PKCS#1 v1.5 signing is deterministic and the signature
   never leaves the card, so the nullifier is deterministic per
   `(card, app_id)` and unforgeable without the card's private key.

## Public inputs / outputs

### Circuit A — CertChain

| Signal                  | Visibility    | Notes                                                  |
| ----------------------- | ------------- | ------------------------------------------------------ |
| `issuer_rsa_modulus[k]` | public input  | MOICA's RSA public key (trust anchor)                  |
| `smtRoot`               | public input  | Revocation SMT root                                    |
| `pk_commit`             | public output | Links to Circuit B                                     |

Public-value vector layout (in declaration order, outputs first):
- RS2048: `[pk_commit, issuer_rsa_modulus[17], smtRoot]` — 19 elements
- RS4096: `[pk_commit, issuer_rsa_modulus[34], smtRoot]` — 36 elements

### Circuit B — DeviceSig

| Signal             | Visibility    | Notes                                                              |
| ------------------ | ------------- | ------------------------------------------------------------------ |
| `app_id_bytes[31]` | public input  | 31-byte relying-party identifier; verifier byte-compares           |
| `pk_commit`        | public output | Must match Circuit A's `pk_commit`                                 |
| `nullifier`        | public output | `ChunkedPoseidonP256(user_rsa_signature)`; per-(card, app_id) ID   |

Public-value vector layout: `[pk_commit, nullifier, app_id_bytes[31]]` — 33 elements.

All other signals (user cert bytes, RSA signatures, SMT proof path,
`subject_dn`, `tbs`, `pk_blind`) are private.

## Revocation

Revocation uses a Sparse Merkle Tree non-membership proof against the SMT
maintained by the
[`moica-revocation-smt`](https://github.com/moven0831/moica-revocation-smt)
service. Circuit A verifies that the cert's `serialNumber` is not present in
the tree rooted at `smtRoot`.

## Why per-session randomness for `pk_blind`

`pk_commit` must hide the user's RSA modulus from anyone who sees only the
public proof outputs (`pk_commit`, `nullifier`, `app_id_bytes`,
`issuer_rsa_modulus`, `smtRoot`). The assumed adversary holds the full MOICA
cert directory — every citizen's `user_pk`. Any deterministic derivation of
`pk_blind` from public or leaked inputs lets that adversary recompute
`pk_commit` for each `user_pk` and match against the observed value.

A per-session uniform 248-bit `pk_blind` removes that attack: every `user_pk`
candidate is equally consistent with the observed `pk_commit`.

`pk_commit` only needs to link Circuits A and B within a single submission,
so it doesn't need to be reproducible. Sybil resistance per `(card, app_id)`
is carried by `nullifier = ChunkedPoseidonP256(user_rsa_signature)` instead,
whose secrecy rests on the RSA private key never leaving the card.

## See also

- [`../ecdsa-spartan2/README.md`](../ecdsa-spartan2/README.md) — Rust prover CLI
- `circuits/components/smt-nonmembership.circom` — SMT verification template
- `circuits/components/poseidon_p256.circom` — Poseidon hash over secq256r1
- `circuits/components/pk_commit.circom` — `ChunkedPoseidonP256` for pk_commit
- `circuits/utils/utils.circom` — cert parsing helpers (`VerifyTBSinCert`, `VerifySubjectDN`, `VerifySerialNumber`, `ExtractModulus`, `PackBytes`, `PoseidonBytes`)
