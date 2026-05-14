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

**Recommended follow-ups:**

1. Pin `tbsLength === 31` (or move the nullifier off the signature) — closes the HIGH.
2. Bind `tbsSerialNumberOffset` structurally (parse the version `[0]` block in-circuit) or make it a hard-coded constant — closes the CRITICAL.
3. Remove `userCertZeroPadded` / `VerifyTBSinCert` — eliminates ~1500 dead constraints.
4. Run `circomspect` (complementary to this manual audit's business-logic focus).

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
