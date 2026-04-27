# zkID Circuit Specification

This document describes the Circom circuits in this directory.

## Overview

The circuits verify Taiwan Citizen Digital Certificate (MOICA) X.509
certificates signed with RSA-SHA256, plus a per-session user-device signature
over arbitrary data (the "TBS" sent to the HiPKI card). They also assert
non-revocation against a Sparse Merkle Tree (SMT).

## Active circuits

| Circuit              | Template           | Description                                                    |
| -------------------- | ------------------ | -------------------------------------------------------------- |
| `cert_chain_rs2048`  | `CertChainRSA256`  | Circuit A — cert chain + revocation + pk_commit (MOICA-G2)     |
| `cert_chain_rs4096`  | `CertChainRSA256`  | Circuit A — cert chain + revocation + pk_commit (MOICA-G3)     |
| `device_sig_rs2048`  | `DeviceSigRSA256`  | Circuit B — device signature + packed_tbs + pk_commit          |

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
   binding this proof to the same user key used in Circuit B.
5. **Nullifier** — `PoseidonBytesWithField(subject_dn, app_id) → nullifier`
   (public output). Binds the identity hash to a specific application so that a
   proof generated for one relying party cannot be replayed at another.

### Circuit B — DeviceSig (`DeviceSigRSA256`)

1. **Device signature verify** — `user_pk_limbs` verifies `user_rsa_signature`
   over `tbs` (arbitrary bytes the HiPKI card signs). Proves the holder of the
   user's private key signed `tbs`.
2. **Linking** — same `pk_commit` formula as Circuit A, using the same
   `pk_blind` value.
3. **TBS commitment** — `PackBytes(tbs) → packed_tbs` (public output).

## Public inputs / outputs

### Circuit A — CertChain

| Signal                  | Visibility    | Notes                                         |
| ----------------------- | ------------- | --------------------------------------------- |
| `issuer_rsa_modulus[k]` | public input  | MOICA's RSA public key (trust anchor)         |
| `smtRoot`               | public input  | Revocation SMT root                           |
| `app_id`                | public input  | Application binding; `nullifier` commits to this value |
| `nullifier`             | public output | `Poseidon(packed subject_dn, app_id)`         |
| `pk_commit`             | public output | Links to Circuit B                            |

### Circuit B — DeviceSig

| Signal          | Visibility    | Notes                                         |
| --------------- | ------------- | --------------------------------------------- |
| `pk_commit`     | public output | Must match Circuit A's `pk_commit`            |
| `packed_tbs` | public output | `PackBytes(31, …)(tbs)` — commitment to user-signed bytes |

All other signals (user cert bytes, RSA signatures, SMT proof path,
`subject_dn`, `tbs`, `pk_blind`) are private.

## Revocation

Revocation uses a Sparse Merkle Tree non-membership proof against the SMT
maintained by the
[`moica-revocation-smt`](https://github.com/moven0831/moica-revocation-smt)
service. Circuit A verifies that the cert's `serialNumber` is not present in
the tree rooted at `smtRoot`.

## See also

- [`../ecdsa-spartan2/README.md`](../ecdsa-spartan2/README.md) — Rust prover CLI
- `circuits/components/smt-nonmembership.circom` — SMT verification template
- `circuits/components/poseidon_p256.circom` — Poseidon hash over secq256r1
- `circuits/components/pk_commit.circom` — `ChunkedPoseidonP256` for pk_commit
- `circuits/utils/utils.circom` — cert parsing helpers (`VerifyTBSinCert`, `VerifySubjectDN`, `VerifySerialNumber`, `ExtractModulus`, `PackBytes`, `PoseidonBytes`, `PoseidonBytesWithField`)
