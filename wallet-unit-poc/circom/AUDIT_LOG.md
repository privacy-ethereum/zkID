# Circom Audit Log

Index of internal audit passes over `wallet-unit-poc/circom/`. Each entry
points to the full report and captures the circuit state, methodology, and
top-level verdict so the history is readable without diffing reports.

Methodology: Circom adaptation of
[`noir-claude-auditor`](https://github.com/0xvikasrushi/noir-claude-auditor)
(6-phase protocol — Read, Map, Analyze, Compare, Verify, Report).

| # | Date | Report | Circuit commit | Strategy | Confirmed (Crit/High/Med) | Advisory | Overall |
|---|------|--------|----------------|----------|---------------------------|----------|---------|
| 1 | 2026-05-08 | [`audit_report.md`](./audit_report.md) | pre-#69 (snake_case) | FOCUSED | 1 / 1 / 0 | 3 (M/L/L) | CRITICAL |
| 2 | 2026-05-14 | [`audit_report_v2.md`](./audit_report_v2.md) | post-#71 (`ec9a73d`) | FOCUSED | 1 / 1 / 0 | 3 (L/L/INFO) | CRITICAL |
| 3 | 2026-05-14 | [`audit_report_v3.md`](./audit_report_v3.md) | post-fix (`ced3ba6`, branch `fix/audit-v2`) | FOCUSED | 0 / 0 / 0 | 3 (L/L/INFO) | LOW |

## Audit 1 — 2026-05-08

**Scope:** `cert_chain.circom`, `device_sig.circom`, `rs256.circom`, `utils/utils.circom`, `components/*` (snake_case layout).

**Confirmed findings:**

- **[CRITICAL] Identity forgery via unbound DER offsets in `CertChainRSA256`** — `user_modulus_offset`, `subject_dn_offset`, `serial_number_offset` were prover-supplied with no constraint binding them to the MOICA-signed TBS region; `actual_user_cert_length` was unused so the padding region was unconstrained. Allowed an attacker holding any `(TBS, MOICA-σ)` pair to mint a `pk_commit` over an attacker-chosen RSA key.
- **[HIGH] Sybil bypass on `nullifier`** — `tbs[31..tbs_length]` was unconstrained, so one card could mint unlimited distinct `nullifier`s for a fixed `(card, app_id)`.

**Resolution status (as of Audit 2):**

- CRITICAL #1 — **FIXED.** Extractions moved to `issuerTbs`; `AssertSliceInTBS` bounds the offsets; `AssertZeroPadding` on `userCertZeroPadded`; `issuerTbsLength` ↔ `actualIssuerTbsLength + [0, 128]` band added.
- HIGH #1 — **NOT FIXED.** `tbsLength` was bounded to `≤ 64` but not pinned; the malleability surface is reduced from ~1500 bytes to ~33 bytes but the bug class is unchanged. Re-reported as Audit 2 Finding 2.

## Audit 2 — 2026-05-14

**Scope:** `certChain.circom`, `userSig.circom`, `rs256.circom`, `utils/utils.circom`, `components/*` (post-#69 camelCase, post-#71 length-band binding).

**Confirmed findings:**

- **[CRITICAL] Revocation bypass via `tbsSerialNumberOffset` ambiguity** — the offset is prover-supplied with only a local `cert[offset-2]==0x02` + `0 < cert[offset-1] ≤ 20` check. Real MOICA TBSes contain multiple ASN.1 INTEGER tags satisfying both checks; empirically verified against `inputs/cert_chain_rs2048/input.json` that offsets 8 (version), 10, and 512 (RSA exponent → serial=65537) all pass every constraint. A revoked card-holder bypasses revocation by pointing at the exponent.
- **[HIGH] Residual nullifier malleability** — `tbs[31..tbsLength]` is still unconstrained; `tbsLength ∈ [0, 64]` allows ~33 free bytes; PKCS#1 v1.5 determinism converts each variation into a distinct nullifier. Sybil resistance broken.

**Advisories:** decoupled `tbsModulusOffset` / `tbsModulusTagOffset` (LOW, not exploitable); redundant `VerifyTBSinCert` + `userCertZeroPadded` after the extraction refactor (LOW cleanup); Poseidon 128-bit security note (INFO).

**Resolution status (as of 2026-05-14, branch `fix/audit-v2`):**

- **CRITICAL — FIXED.** `tbsSerialNumberOffset` dropped as a prover input. `CertChainRSA256` walks the outer SEQUENCE header + optional `[0] EXPLICIT` version block to derive the canonical serial-INTEGER offset and feeds it to `VerifySerialNumber`. Empirical canary tests for offsets 8 / 10 / 512 (values 2 / 5214 / 65537) all reject post-fix — see `tests/circuits/auditV2Regression.test.ts` § [CRITICAL].
- **HIGH — FIXED.** `tbsLength` dropped as a prover input and hard-coded to 64. `tbs[31] === 0x80`, `tbs[32..63] === 0`, `tbs[63] === 0xF8` pin the SHA-256-padded payload to the canonical 31-byte-message form, so `σ = sign(SHA256(app_id_bytes))` is fully determined by `(card, app_id)` and `nullifier = Hash(σ)` is per-`(card, app_id)` unique. Canary test verifies a `tbs[31] = 0x42` variant is rejected — see § [HIGH].
- **LOW (#1) — FIXED.** `tbsModulusOffset` dropped as a prover input. `CertChainRSA256` enforces the canonical DER long-form prefix bytes `[0x82, 0x01, 0x01, 0x00]` at `issuerTbs[tbsModulusTagOffset + {1..4}]` and derives `tbsModulusOffset = tbsModulusTagOffset + 5`. Canary test verifies `tbsModulusTagOffset = 510` (RSA exponent INTEGER tag) is rejected — see § [LOW].
- **LOW (#2) — FIXED.** Dead `VerifyTBSinCert` + `userCertZeroPadded` + `actualUserCertLength` removed from `CertChainRSA256` and the template definition deleted from `circuits/utils/utils.circom`. ~1,500 R1CS rows freed.
- **INFO — ACKNOWLEDGED.** One-line annotation added to `circuits/components/poseidonP256Constants.circom` recording the 128-bit security target per Hadeshash §5.3.

## Audit 3 — 2026-05-14

**Scope:** `certChain.circom`, `userSig.circom`, `rs256.circom`, `utils/utils.circom`, `components/*` at HEAD `ced3ba6` on branch `fix/audit-v2` (post audit-v2 fixes and cleanup pass). Fresh full pass through the noir-claude-auditor 6-phase protocol; not a diff-against-v2 review.

**Confirmed findings:** None.

**Advisories:**

- **[LOW] DER-prefix uniqueness depends on MOICA's cert-issuance practice** — the 5-byte pattern `[0x02, 0x82, 0x01, 0x01, 0x00]` that `CertChainRSA256` pins at `issuerTbs[tbsModulusTagOffset + {0..4}]` is empirically unique within both bundled fixtures, but uniqueness is an environmental property of how MOICA formats its v3 user TBSes, not a constraint. Soundness misalignment with no realizable exploit against MOICA's current issuance. Recommended hardening: walk the SubjectPublicKeyInfo DER structure inside the circuit, or pin `tbsModulusTagOffset` to a constant once production layout is locked.
- **[LOW] Dead helper templates in `utils.circom`** — `VerifySubjectDN`, `PoseidonBytes`, and `PoseidonBytesWithField` are defined but no longer instantiated by any production circuit or test wrapper. Cleanup candidate; deletion saves no R1CS rows but removes a maintenance hazard (a future contributor could re-introduce one of these without re-deriving its security role).
- **[INFO] Implicit acceptance of X.509 v1 issuer TBSes** — when `issuerTbs[4] ≠ 0xa0` the version-block check disables and `serialValueOff` becomes `6`. MOICA-G2 / G3 are documented as v3-only, so the v1 branch is unreachable in practice. Optional hardening: hard-pin `issuerTbs[4..8]` to the canonical v3 version block (saves ~10 conditional constraints, tightens the spec).

**Verification of prior findings:** every audit-v2 finding (CRITICAL, HIGH, LOW#1, LOW#2, INFO) was re-checked against the post-fix code and traced to the specific fix location and (where applicable) regression test. All are confirmed FIXED / ACKNOWLEDGED as recorded in the Audit 2 resolution-status section above.

**Overall verdict:** **LOW.** The protocol's core security guarantees — (i) chain-of-trust binding from MOICA's signature to `pkCommit`, (ii) revocation enforcement via the canonical serial offset and SMT non-membership, (iii) per-`(card, app_id)` uniqueness of `nullifier`, and (iv) replay prevention via the Semaphore-style challenge binding — are faithfully encoded by the current constraints.

---

## Adding a new audit

1. Run the 6-phase protocol from
   [`noir-claude-auditor`](https://github.com/0xvikasrushi/noir-claude-auditor)
   adapted for Circom (`<==` / `<--` / `===`, secq256r1 field, `circomspect` in
   place of `nargo --pedantic-solving`).
2. Write the report to `audit_report_v{N}.md` next to this log.
3. Append a row to the table above and a section below summarising scope,
   confirmed findings, and the resolution status of every prior finding still
   open. **Do not modify older reports** — they are the historical record.
