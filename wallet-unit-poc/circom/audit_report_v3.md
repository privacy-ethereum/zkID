# Circom Circuit Security Audit — zkID (v3)

**Project:** `wallet-unit-poc/circom/` (zkID — Privacy Stewards of Ethereum)
**Circuits:** `CertChainRSA256` (rs2048 / rs4096), `UserSigRSA256` (rs2048)
**Circom version:** 2.2.3 (declared in every file)
**Constraint field:** `secq256r1` (set in `circomkit.json`; p ≈ 2²⁵⁶ − 2²²⁴ + 2¹⁹² + 2⁹⁶ − 1)
**Proving protocol:** Spartan2 / Hyrax (per `ecdsa-spartan2/`); `circomkit.json` sets `"protocol": "groth16"` only for the compile pipeline
**Audited by:** Circom adaptation of [`noir-claude-auditor`](https://github.com/0xvikasrushi/noir-claude-auditor) methodology (Claude Code, Opus 4.7)
**Audit date:** 2026-05-14 (post-fix re-audit)
**Circuit commit:** `ced3ba6` on branch `fix/audit-v2`
**Scope:** Business-logic and mathematical soundness bugs in circuit constraints.
**Out of scope:** `circomlib`, `@zk-email/circuits` (trusted libraries), the Rust input builder (`zkid-input-builder`), the Spartan2 prover, the Go verifier, smart-contract integration, and underconstrained-signal classes that `circomspect` / Picus / Ecne target.

---

## Files Audited

| File | Lines | Description |
|---|---|---|
| `circuits/certChain.circom` | 155 | Circuit A: cert-chain RSA verify + DER walk + SMT non-membership + `pkCommit` |
| `circuits/userSig.circom` | 80 | Circuit B: user RSA signature over canonical SHA-256-padded `tbs` + `pkCommit` + `nullifier` + `appIdPacked` + challenge binding |
| `circuits/rs256.circom` | 67 | `CertRSA256Verify`: SHA-256 + RSA-65537 verify glue; `Bits2Limbs` |
| `circuits/utils/utils.circom` | 323 | `AssertSliceInTBS`, `VerifySubjectDN`†, `VerifySerialNumber`, `ExtractModulus`, `PackBytes`, `PoseidonBytes`†, `PoseidonBytesWithField`† (†: defined but not called by any production circuit — see Finding 2) |
| `circuits/components/poseidonP256.circom` | 87 | Standard (non-optimised) Poseidon over secq256r1 (t=3, t=4) |
| `circuits/components/poseidonP256Constants.circom` | (~3 K constants) | RF=8, RP_{t=3}=57, RP_{t=4}=56 |
| `circuits/components/pkCommit.circom` | 48 | `ChunkedPoseidonP256(N)` sponge wrapper |
| `circuits/components/smtHashP256.circom` | 31 | `SMTHash1P256(key,value,1)`, `SMTHash2P256(L,R)` |
| `circuits/components/smtVerifierP256.circom` | 145 | Circomlib SMT verifier with hash swapped to PoseidonP256 |
| `circuits/components/smtNonmembership.circom` | 19 | Wrapper hard-coding `enabled=1`, `value=0`, `fnc=1` |
| `circuits/main/certChainRS2048.circom` | 7 | `CertChainRSA256(1536, 121, 17, 2048, 17, 2048, 128, 20)`, `public[issuerRsaModulus, smtRoot]` |
| `circuits/main/certChainRS4096.circom` | 7 | `CertChainRSA256(1536, 121, 34, 4096, 17, 2048, 128, 20)`, `public[issuerRsaModulus, smtRoot]` |
| `circuits/main/userSigRS2048.circom` | 7 | `UserSigRSA256(1536, 121, 17)`, `public[challenge]` |

**Total project-authored Circom:** 13 files, ~1 000 lines excluding the Poseidon constants table and `circuits/test/*` fixtures.

**Strategy chosen:** **MEDIUM / FOCUSED**, with **empirical verification** of the new DER-prefix uniqueness assumption against the bundled `inputs/cert_chain_rs2048/input.json` and `inputs/cert_chain_rs4096/input.json` fixtures.

**Files NOT audited:** `circuits/test/*.circom` (test wrappers), `node_modules/**`, build outputs, the Poseidon round-constant table contents (formal soundness of values is trusted to the Hadeshash reference implementation).

---

## Assumptions

- Default circom semantics for `<==` (assign + constrain), `<--` (assign only), and `===` (constrain).
- `circomlib`'s `SMTVerifierSM`, `SMTLevIns`, `Multiplexer`/`Decoder`, `Num2Bits`, `LessThan`, `LessEqThan`, `GreaterThan`, `IsEqual`, `IsZero`, `Switcher`, `MultiAND`, `ForceEqualIfEnabled` are sound. `Multiplexer(wIn, nIn).sel` is constrained via `Decoder.success === 1` to lie in `[0, nIn)`.
- `@zk-email/circuits`'s `Sha256Bytes` / `Sha256General` expect a **pre-padded** input buffer of `paddedInLength` bytes and process it in 64-byte blocks; the constraint `paddedInLength === inBlockIndex * 512` (in bits) forces `paddedInLength` to be a multiple of 64 bytes, and a separate `LessEqThan(maxBitsPaddedBits)` bounds it by `maxBitLength = maxByteLength * 8`. `RSAVerifier65537` runs PKCS#1 v1.5 with `e = 65537` and `BigLessThan`-checks the signature against the modulus. `ItemAtIndex(N).index` is constrained to `[0, N)` via the `sum(eq.out) === 1` aggregate.
- Poseidon over secq256r1 with `RF=8`, `RP=57 (t=3) / 56 (t=4)` provides ≈ 128-bit security per the Hadeshash recommendation (annotated in `poseidonP256Constants.circom`).
- MOICA only issues v3 X.509 certs whose initial bytes are `[0x30, 0x82, lenHi, lenLo, 0xa0, 0x03, 0x02, 0x01, 0x02, …]` followed by the serial-number INTEGER at offset 9. User RSA keys are always 2048-bit, so the SubjectPublicKey modulus INTEGER carries the canonical DER prefix `[0x02, 0x82, 0x01, 0x01, 0x00, …256 modulus bytes…]`. This 5-byte prefix is **empirically unique** within both the rs2048 and rs4096 fixture TBSes (scan run during this audit; the only hit is at the documented `tbsModulusTagOffset = 249`).
- `pkCommit_A == pkCommit_B` and `appIdPacked == pack_LE_31(verifier_app_id)` are enforced by the Go verifier *outside* the circuits.

---

## Executive Summary

Re-audited the three production circuits and supporting utilities at HEAD `ced3ba6` of branch `fix/audit-v2`, the state after the team's audit-v2 remediations (commits `a4d5927`, `1d9b048`, `ea2d33e`, plus the cleanup pass in `61f65a4`).

**All audit-v2 findings are verified fixed in the current code:**

1. **v2 CRITICAL — Revocation bypass via `tbsSerialNumberOffset` ambiguity** — `tbsSerialNumberOffset` has been removed as a prover input. `CertChainRSA256` now hard-checks `issuerTbs[0..1] === [0x30, 0x82]` for the outer SEQUENCE header, uses `IsEqual(issuerTbs[4], 0xa0)` plus `ForceEqualIfEnabled` over `issuerTbs[5..8] === [0x03, 0x02, 0x01, 0x02]` to detect the optional `[0] EXPLICIT` version block, and derives the canonical serial-INTEGER value offset as `serialValueOff <== 4 + hasVersion.out * 5 + 2`. `VerifySerialNumber` then operates at this fixed offset. The audit-v2 attack offsets (8, 10, 512) that produced `serialNumber ∈ {2, 5214, 65537}` against the real `cert_chain_rs2048` fixture are now rejected by the circuit (asserted by `tests/circuits/auditV2Regression.test.ts` § "[CRITICAL] forged serialNumber is rejected").

2. **v2 HIGH — Sybil bypass on `nullifier` via unconstrained `tbs[31..tbsLength]`** — `tbsLength` has been removed as a prover input and replaced by the literal `64` in the `CertRSA256Verify` call. The circuit now pins `tbs[31] === 0x80`, `tbs[32..62] === 0`, and `tbs[63] === 0xF8`, which is the canonical SHA-256 single-block padding for a 31-byte app-id payload (bit length 248 = 0xF8). Together with `AssertZeroPadding(tbs, 64)` from `CertRSA256Verify`, every byte of the signed payload is bound to either `appIdPacked` (via `PackBytes` over `tbs[0..31]`) or a constant. `σ = RSA_sign(SHA-256(app_id_bytes))` is therefore a function of `(card, app_id)`, and `nullifier = ChunkedPoseidonP256(σ)` is per-`(card, app_id)` unique. The Sybil-attack canary (signing `app_id ‖ 0x42`, producing `tbs[31] = 0x42`) is rejected by the new constraint (asserted by `auditV2Regression.test.ts` § "[HIGH] non-canonical SHA-256 padding is rejected").

3. **v2 LOW #1 — `tbsModulusOffset` and `tbsModulusTagOffset` not bound together** — `tbsModulusOffset` has been removed as a prover input. `CertChainRSA256` enforces `issuerTbs[tbsModulusTagOffset + {1..4}] === [0x82, 0x01, 0x01, 0x00]` (the canonical DER long-form prefix for an unsigned 2048-bit RSA modulus INTEGER) using four `ItemAtIndex` constraints, then derives `tbsModulusOffset <== tbsModulusTagOffset + 5`. `ExtractModulus` still asserts `issuerTbs[tbsModulusTagOffset] === 0x02` for the INTEGER tag. The "tag at offset 510 / 65537 exponent" reroute that audit-v2 enumerated is rejected (asserted by `auditV2Regression.test.ts` § "[LOW] forged tbsModulusTagOffset is rejected").

4. **v2 LOW #2 — Redundant `VerifyTBSinCert` + `userCertZeroPadded` after the refactor** — `userCertZeroPadded`, `actualUserCertLength`, the `VerifyTBSinCert` call, and the `AssertZeroPadding(userCertZeroPadded, …)` call have all been removed from `CertChainRSA256`. The `VerifyTBSinCert` template itself has also been removed from `circuits/utils/utils.circom`.

5. **v2 INFO — Poseidon round counts target 128-bit security** — A one-line annotation has been added at the top of `circuits/components/poseidonP256Constants.circom` documenting the target security level (`RF=8 full, RP={57 for t=3, 56 for t=4} partial; target 128-bit security per Hadeshash §5.3 (α=5, |F|≈256 bits)`).

**No new CRITICAL or HIGH soundness bugs were found in the post-fix code.** Two LOW advisories and one INFO note are reported below; they describe non-exploitable soundness considerations worth tracking for cleanup or future hardening.

**Overall risk: LOW.** The circuit's stated security properties — (i) the chain-of-trust binding from MOICA's RSA signature to `pkCommit`, (ii) revocation enforcement via the canonical serial offset and SMT non-membership, (iii) Sybil resistance via the per-`(card, app_id)` deterministic `nullifier`, and (iv) replay prevention via the Semaphore-style challenge binding — are all faithfully encoded by the current constraints.

Confirmed: 0 · Advisory: 3 · Dropped near-misses: 7

---

## Findings

---

### [LOW] DER-prefix uniqueness depends on MOICA's cert-issuance practice — SPEC_MISMATCH (advisory)

**Location:**
- `circuits/certChain.circom:109-123` — the prover-supplied `tbsModulusTagOffset` is constrained by `AssertSliceInTBS()(tbsModulusTagOffset, 1, actualIssuerTbsLength)`, the constant prefix check `issuerTbs[tbsModulusTagOffset + {1..4}] === [0x82, 0x01, 0x01, 0x00]`, and the INTEGER-tag check `in[tbsModulusTagOffset] === 0x02` inside `ExtractModulus` at `circuits/utils/utils.circom:180-185`.

**Status:** CONFIRMED as a soundness gap; **not exploitable for MOICA's actual cert issuance**. Empirically the 5-byte sequence `02 82 01 01 00` appears exactly once in each of the bundled rs2048 and rs4096 fixture TBSes — at `tbsModulusTagOffset = 249`.

**Bug class:** SPEC_MISMATCH (advisory).

---

**What the circuit should prove:**
"`userRsaExtractedModulus` is the 2048-bit RSA modulus carried by the `SubjectPublicKeyInfo` field of the MOICA-signed `issuerTbs`."

**What the constraints actually enforce:**
"`userRsaExtractedModulus` is `issuerTbs[o+5 .. o+5+256]` decoded big-endian into 17 × 121-bit limbs, where `o = tbsModulusTagOffset` is *some* offset in `[0, actualIssuerTbsLength)` such that `issuerTbs[o..o+5] === [0x02, 0x82, 0x01, 0x01, 0x00]`."

**The gap:**
The circuit pins the value byte sequence at `[o..o+5]` but not the structural role of `o` as the SubjectPublicKeyInfo's modulus INTEGER. The argument that "`o` must be the modulus tag offset because `02 82 01 01 00` only appears at that position" is an *empirical* property of MOICA-signed TBSes, not a constraint enforced by the circuit. If MOICA ever issues a cert containing another byte run matching this pattern — e.g., an extension whose value happens to be a 257-byte buffer starting with `00` — the prover could redirect `tbsModulusTagOffset` to it and inject a different 256-byte sequence as the "user modulus".

---

**Why it is not exploitable today.** The pattern `02 82 01 01 00` decodes structurally as "ASN.1 INTEGER, long-form length 257 bytes, sign byte 0x00." Within a MOICA v3 user TBS:

- The outer SEQUENCE (~600–800 byte content length) uses length encoding `82 02 hh` or `82 03 hh`, never `82 01 01`.
- The serial INTEGER's length byte is in `(0, 20]` per `VerifySerialNumber`; never 257.
- Signature algorithm OIDs and other small INTEGERs have short-form length.
- The issuer/subject DNs use SEQUENCE/SET, not INTEGER.
- Validity uses `UTCTime`/`GeneralizedTime`, not INTEGER.
- The only INTEGER of exactly 257 bytes with leading `0x00` is the RSA modulus inside the `SubjectPublicKeyInfo`.

Empirical scan against the bundled fixtures confirms this: the 5-byte pattern is unique within `actualIssuerTbsLength` in both `cert_chain_rs2048/input.json` and `cert_chain_rs4096/input.json`. The SHA-256 padding region at `[actualIssuerTbsLength, issuerTbsLength)` cannot host the pattern either — its first byte is `0x80` and the rest is zeros / bit-length encoding.

Furthermore, even if a duplicate prefix existed elsewhere, the prover would need to satisfy two additional constraints to convert the misalignment into a forgery: (a) `pkCommit_A == pkCommit_B`, which forces `userPkLimbs` (Circuit B) to equal the extracted limbs, and (b) `RSAVerifier65537` (Circuit B), which forces the prover to hold the private exponent for those limbs. The chance that 256 contiguous TBS bytes form a smooth/factorable composite for which the prover knows the factorization is astronomically small.

For these reasons, the gap is a **soundness misalignment** rather than an exploit path. It is reported because (i) future cert-format changes by MOICA could break the uniqueness assumption, and (ii) the circuit reads as more permissive than the security argument actually requires.

---

**Malicious witness (hypothetical, not realizable against MOICA).**

```
issuerRsaModulus = MOICA_pk_limbs                                   // public
issuerTbs        = a hypothetical MOICA-signed TBS containing       // private
                   the 5-byte pattern 02 82 01 01 00 at TWO offsets
                   (canonical SPKI o₁ and some other o₂)
issuerRsaSignature = MOICA_signature_on_issuerTbs                   // private
tbsModulusTagOffset = o₂ (≠ canonical o₁)                           // attack
serialNumber, smt* = honest                                          // private

Satisfies constraints: YES (every constraint checks bytes/structure that is locally satisfied)
Violates intended property: YES — modulus extracted from o₂ is not the SPKI modulus.
Realizable: NO — no real MOICA cert exhibits the duplicate pattern.
```

---

**Fix.** Two layered options, either suffices.

**(a) Walk the DER structure inside the circuit** to derive `tbsModulusTagOffset` from `issuerTbs` constants. The SubjectPublicKeyInfo for an MOICA v3 cert (with 2048-bit user key, e=65537) is structurally fixed:

```
SubjectPublicKeyInfo SEQUENCE [tag 0x30, long-form length]
  AlgorithmIdentifier SEQUENCE
    OID rsaEncryption  (1.2.840.113549.1.1.1)
    NULL
  BIT STRING [tag 0x03, sign byte 0x00, ...]
    SEQUENCE [tag 0x30, long-form length 0x82 0x01 0x0A]
      INTEGER [tag 0x02, long-form length 0x82 0x01 0x01]
        00 ⟨256 modulus bytes⟩
      INTEGER [tag 0x02, length 0x03]
        01 00 01    -- exponent 65537
```

The SPKI offset is a function of (a) the serial length and (b) the issuer/subject DN sizes, both of which vary across users. Walking the structure inside the circuit is non-trivial. A pragmatic middle ground:

**(b) Pin `tbsModulusTagOffset` to the *exact* fixture-derived offset** (e.g., `249` for MOICA-G2 with the current cert template) once the team has confirmed all production certs share the same layout. If the layout ever diverges, the circuit hard-fails (visible, not silent), and the team intentionally re-bakes the constant.

Even simpler — and almost as strong — is to add a defence-in-depth check that the *first* occurrence of `02 82 01 01 00` in `issuerTbs[0..actualIssuerTbsLength)` is what `tbsModulusTagOffset` selects. That would require an O(n²) sub-circuit; given the empirical uniqueness, it is probably overkill.

---

**Severity rationale.** Soundness misalignment with no realizable exploit against MOICA's current issuance. The chain-of-trust binding survives because Circuit B's RSA verify forces `userPkLimbs` to be a real RSA key the prover holds the private exponent for. **LOW** advisory.

---

### [LOW] Dead helper templates left in `utils.circom` after the refactor — SPEC_MISMATCH (advisory)

**Location:** `circuits/utils/utils.circom`. Three templates are defined but never instantiated by any production circuit (`certChain.circom`, `userSig.circom`, `rs256.circom`, the `main/*` wrappers, or any `circuits/test/*.circom`):

- `VerifySubjectDN` at `circuits/utils/utils.circom:37-51` — likely dead since the v2 refactor (the Subject DN binding was removed when `userCertZeroPadded` was dropped; cf. audit-v2 § "Dead and dual length signals").
- `PoseidonBytes` at `circuits/utils/utils.circom:279-299` — never referenced.
- `PoseidonBytesWithField` at `circuits/utils/utils.circom:303-323` — never referenced.

**Status:** CONFIRMED — dead code, no security impact; flagged for cleanup.

**Bug class:** SPEC_MISMATCH (advisory) — the file *appears* to expose a set of byte-array verification helpers ("VerifySubjectDN") and byte-Poseidon helpers ("PoseidonBytes", "PoseidonBytesWithField") that any future caller would assume are sound and audited. They have no callers and are not under test.

---

**Why it matters.** Dead code in an audited shared module is a maintenance hazard:

1. A future contributor adding subject-DN binding back into the circuit may copy-paste `VerifySubjectDN` without re-deriving the binding's role — the same mistake audit-v1 caught (prover-supplied `subject_dn_offset` with no relationship to authenticated payload).
2. `PoseidonBytes` / `PoseidonBytesWithField` use `PackBytes(N_BYTES, N_BYTES)` followed by a *non-chunked* `Poseidon(N_FIELDS)`. For `N_FIELDS > 16` this would exceed the arity bounds shipped in `poseidonP256.circom` (which only ships `t=3` and `t=4`); for inputs in the typical range (≤ 31 bytes / 1 field) the templates work but produce a hash distinct from `ChunkedPoseidonP256` (different padding semantics). A future caller mixing the two would compromise the `pkCommit` linking.

---

**Fix.** Delete the three templates. Restore them from git history only if and when a caller is genuinely added — at which point the caller's audit can re-cover the helper's semantics.

```circom
// To delete:
//   template VerifySubjectDN(MAX_CERT_LEN, MAX_SUBJECT_LEN) { ... }
//   template PoseidonBytes(N_BYTES) { ... }
//   template PoseidonBytesWithField(N_BYTES) { ... }
```

The remaining production-relevant templates are `AssertSliceInTBS`, `VerifySerialNumber`, `ExtractModulus`, and `PackBytes`. The file's header docstring should also be updated to drop the deleted helpers from its inventory.

---

**Severity rationale.** No exploitable bug. Pure code-hygiene; relevant because the file is referenced by `rs256.circom`'s include chain and was a target of the recent simplification pass. **LOW** advisory.

---

### [INFO] Implicit acceptance of X.509 v1 issuer TBSes — SPEC_MISMATCH (informational)

**Location:**
- `circuits/certChain.circom:87-101` — `hasVersion = IsEqual(issuerTbs[4], 0xa0)` with `ForceEqualIfEnabled` over `issuerTbs[5..8]` is conditional on `hasVersion.out`. When `hasVersion.out = 0` (i.e., `issuerTbs[4] ≠ 0xa0`), the four `versionCheck[i]` constraints disable, and `serialTagOff` becomes `4`. `VerifySerialNumber` is then driven with `serialValueOff = 6` and parses `issuerTbs[4]` as the serial INTEGER tag (`tagCheck.out === 1` requires `issuerTbs[4] === 0x02`).

**Status:** CONFIRMED — depends on MOICA's issuance practice.

**Bug class:** SPEC_MISMATCH (informational only).

---

**What this means.** The circuit accepts two distinct TBS shapes:

- **v1 / no version block:** `issuerTbs[0..3]` = `[0x30, 0x82, lenHi, lenLo]`, `issuerTbs[4]` = `0x02` (serial INTEGER tag), `issuerTbs[5]` = serial length.
- **v3 with explicit version=2:** `issuerTbs[0..3]` = `[0x30, 0x82, lenHi, lenLo]`, `issuerTbs[4..8]` = `[0xa0, 0x03, 0x02, 0x01, 0x02]`, `issuerTbs[9]` = `0x02`, `issuerTbs[10]` = serial length.

It rejects v2 (value=1) by virtue of `ForceEqualIfEnabled` pinning the version INTEGER value to `2`.

If MOICA only ever signs v3 user certs, the v1 branch is unreachable in practice — `issuerRsaSignature` would never validate against a v1 TBS that MOICA didn't actually sign. The SPEC.md narrative is also v3-specific. So this is informational, not a soundness gap.

That said, a defensive `issuerTbs[4] === 0xa0` (replacing the optional check with a hard one) makes the protocol's MOICA-G2/G3 assumption explicit at the circuit boundary, simplifies the reasoning, and prevents a future contributor from being misled into thinking v1 is a valid path. If the team plans to ever support v1 certs (e.g., for legacy root certs), the current code is correct as-is.

---

**Fix (optional).** If MOICA's issuance policy is provably v3-only, hard-pin:

```circom
issuerTbs[4] === 0xa0;
issuerTbs[5] === 0x03;
issuerTbs[6] === 0x02;
issuerTbs[7] === 0x01;
issuerTbs[8] === 0x02;

// serial INTEGER tag at offset 9, value at offset 11
var serialValueOff = 11;
VerifySerialNumber(maxMessageLength, maxSerialNumberLength)(
    issuerTbs, serialValueOff, serialNumber
);
```

This deletes ~10 R1CS rows (the `IsEqual` + 4 `ForceEqualIfEnabled`) and replaces them with 5 cheap equality constraints. Net: roughly the same constraint count, with a tighter spec.

---

**Severity rationale.** Informational only. No exploitable soundness gap given MOICA's current v3-only issuance. **INFO** advisory.

---

## Verification of v2 Findings — Code & Test References

For traceability, each prior finding is mapped to the specific post-fix code line(s) and canary test that locks in the fix:

| v2 Finding | Status | Fix location (this audit) | Regression test |
|---|---|---|---|
| **CRITICAL** — Revocation bypass via `tbsSerialNumberOffset` ambiguity | FIXED | `certChain.circom:81-107` — outer SEQUENCE + version-block walk + canonical `serialValueOff` | `auditV2Regression.test.ts` § "[CRITICAL] forged serialNumber is rejected" (rejects `serialNumber ∈ {2, 5214, 65537}`) |
| **HIGH** — Sybil bypass on `nullifier` via unconstrained `tbs[31..tbsLength]` | FIXED | `userSig.circom:41-49` — canonical SHA-256 padding pinned, `messageLength=64` hard-coded | `auditV2Regression.test.ts` § "[HIGH] non-canonical SHA-256 padding is rejected" (rejects `tbs[31] = 0x42` tail) |
| **LOW #1** — `tbsModulusOffset` / `tbsModulusTagOffset` decoupled | FIXED | `certChain.circom:109-123` — DER long-form prefix `[0x82, 0x01, 0x01, 0x00]` pinned at `+{1..4}`, `tbsModulusOffset <== tbsModulusTagOffset + 5` | `auditV2Regression.test.ts` § "[LOW] forged tbsModulusTagOffset is rejected" (rejects offset 510) |
| **LOW #2** — Redundant `VerifyTBSinCert` + `userCertZeroPadded` | FIXED | `certChain.circom` no longer declares `userCertZeroPadded` / `actualUserCertLength` and no longer calls `VerifyTBSinCert`; `utils.circom` has `VerifyTBSinCert` deleted | No targeted test; tested indirectly by `certChainRS2048.test.ts` continuing to pass |
| **INFO** — Poseidon round counts target 128-bit security | ACKNOWLEDGED | `poseidonP256Constants.circom:1-5` — annotation block added | N/A |

---

## Areas for Further Investigation

The following patterns did not meet the threshold for a finding but deserve a second look. The first four are carried over from audit-v2 with status unchanged (the corresponding code did not change in the v2 → v3 window); the last two are new.

1. **Limb-canonicality of `userPkLimbs` in `userSig.circom` (carried from v2).** `RSAVerifier65537`'s `Num2Bits(n)` only enforces `userPkLimbs[i] < 2ⁿ` (n=121). The top limb has 9 unused high bits (modulusBits=2048 vs n·k=2057); a malicious prover could supply non-canonical limbs that hash to a different `pkCommit` than the canonical decomposition. The cross-circuit binding kills any exploit (`pkCommit_A` is built from canonical limbs produced by `ExtractModulus`, so `pkCommit_B` is forced to match canonical), but a one-line range check at the top of `UserSigRSA256` would harden the property unconditionally: `Num2Bits(modulusBitsUser - n*(kUser-1))(userPkLimbs[kUser-1])`.

2. **`smtIsOld0` boolean enforcement (carried from v2).** `circuits/components/smtNonmembership.circom:14` passes `smtIsOld0` as `is0` into `SMTVerifierSM`. The composite `st_na + st_iold + st_inew + st_i0 === 1` *should* indirectly force `is0 ∈ {0, 1}` via the state-machine algebra, but a focused review of every boolean input to `SMTVerifierSM` (notably `is0`, `enabled`, `levIns`) remains worthwhile, especially since the circuit was ported from BN254 to secq256r1.

3. **`Bits2Limbs(256, 121, 17)` zero-padding (carried from v2).** `circuits/rs256.circom:18-35` zero-pads bit positions `i*n + j ≥ 256`. Manual trace is consistent with `RSAPad`'s expectations, but a unit test pinning `limb[3..16] === 0` after `Bits2Limbs` for the SHA-256 input would harden against future changes.

4. **`pkBlind` randomness assumption (carried from v2).** The circuit imposes no range or non-zero check on `pkBlind`. This is correct because hiding is a prover-side property — but `zkid-input-builder` should sample uniformly from `[0, p)`. Worth a one-line review there.

5. **Outer SEQUENCE-length consistency.** `issuerTbs[0..1] === [0x30, 0x82]` is hard-pinned, but `issuerTbs[2..3]` (the embedded SEQUENCE length) is never compared to `actualIssuerTbsLength - 4`. The signature check effectively forces consistency in practice (MOICA's real TBSes have consistent length encoding), but adding `256 * issuerTbs[2] + issuerTbs[3] === actualIssuerTbsLength - 4` would surface any future drift between the prover's claimed length and the cert's embedded length at the constraint layer.

6. **DER-prefix-uniqueness regression canary.** Because Finding 1's argument is empirical, a unit test that scans `actualIssuerTbsLength` bytes of `issuerTbs` for occurrences of `[0x02, 0x82, 0x01, 0x01, 0x00]` and asserts the count is exactly 1 would lock in the assumption. If MOICA ever rotates cert templates and the count becomes > 1, the test fires before the circuit silently mis-extracts.

---

## Scope and Limitations

This audit covers business-logic and mathematical vulnerabilities in the constraints of the three top-level circuits and their direct dependencies inside this repo. The following are explicitly out of scope:

- Underconstrained-signal classes that automated tools (Picus, Ecne, `circomspect`) target. **Strongly recommend running `circomspect` on `circuits/certChain.circom`, `circuits/userSig.circom`, and `circuits/utils/utils.circom` as a follow-up.**
- The `circomlib` and `@zk-email/circuits` library code, treated as trusted (the audit traced `Sha256Bytes`/`Sha256General`, `RSAVerifier65537`, `Multiplexer`/`Decoder`, `ItemAtIndex`, `AssertZeroPadding`, `LessThan`/`LessEqThan`, `IsEqual`, `ForceEqualIfEnabled` enough to confirm their semantics match the assumptions made in this report, but did not re-audit them).
- The Spartan2 prover/verifier (`ecdsa-spartan2/`) and the Go verifier (`go-zkid-verifier`).
- The Rust input builder (`zkid-input-builder`); see Areas §4.
- Trusted-setup assumptions. The project uses Spartan2/Hyrax for proving, which has no toxic-waste setup. The `"protocol": "groth16"` line in `circomkit.json` only configures the compile tooling and does not imply a Groth16 setup is shipped to production.

This audit is a manual analysis and does not constitute a formal verification.

---

```yaml
---
benchmark:
  circuit:
    name: zkID (CertChainRSA256 + UserSigRSA256) — post-audit-v2 fixes
    files: 13
    lines: ~1000
    complexity: MEDIUM
    strategy_used: FOCUSED

  results:
    confirmed: 0
    unconfirmed: 0
    advisory: 3
    dropped: 7
    classes_triggered: [2]              # SPEC_MISMATCH (all three advisories)

  false_positives:
    near_misses: 7
    descriptions:
      - "issuerTbsLength upper-bound vs maxMessageLength: feared the prover could set issuerTbsLength > 1536 and bypass AssertZeroPadding's scope. Resolved: Sha256General's internal LessEqThan(maxBitsPaddedBits) bounds paddedInLength * 8 by maxBitLength = maxByteLength * 8 = 1536 * 8, so issuerTbsLength is implicitly capped. Dropped."
      - "actualIssuerTbsLength can be set to 8191 (Num2Bits(13) bound): feared AssertSliceInTBS bounds become loose enough to point tbsModulusTagOffset outside the maxMessageLength buffer. Resolved: Multiplexer / ItemAtIndex internally constrain their selectors to [0, nIn), so reads past maxLen=1536 are rejected at the selector level. Dropped."
      - "LessThan(12) in ExtractModulus.bytesel could overflow if modulusOffset+i ≥ 5632: traced. AssertSliceInTBS bounds modulusOffset+256 ≤ actualIssuerTbsLength, so modulusOffset+i < actualIssuerTbsLength ≤ 8191; Num2Bits(13) inside LessThan(12) further fails for in[0]+(1<<12) ≥ 8192 → modulusOffset+i must be < 4096+1536 = 5632. For real fixtures, modulusOffset ≈ 254; comfortably bounded. Dropped."
      - "hasVersion.out non-booleanness: feared the prover could synthesize a fractional hasVersion value to skip the version-block check while still passing serialTagOff = 9. Resolved: IsEqual.out is forced to {0, 1} by IsZero.out's `in*out === 0` + `out <== 1 - in*inv`. Dropped."
      - "Sha256Bytes double-padding on tbs[0..64] for the user signature: feared SHA-256 would re-pad the 64-byte input and yield SHA256(canonical_pad_31 ‖ second_pad), not SHA256(app_id). Resolved by reading @zk-email/circuits/lib/sha.circom: Sha256Bytes takes a pre-padded buffer and Sha256General processes 64-byte blocks without further padding; with paddedInLength=64 the result is SHA256(app_id_bytes). Dropped."
      - "`challengeSquared` dead signal in userSig.circom: at first glance looked like an unused output that should be removed. Resolved: <== both assigns AND constrains, and `challenge` is a public input declared in the main wrapper, so the constraint forces `challenge` into the R1CS public-input vector (Semaphore reference linked in the file). Sound. Dropped."
      - "SMT path uses only bits[0..127] of the serial via Num2Bits(254); feared two distinct serials sharing a 128-bit prefix could collide on the SMT path and allow a revoked holder with the same path-prefix as an unrevoked leaf to pass non-membership. Resolved: hash1Old / hash1New use the full key (the leaf hash is over the entire serial), and `areKeyEquals.out === 0` (when isOld0=0) explicitly forces `oldKey ≠ key`. The SMT non-membership correctly differentiates serials with shared path-prefixes. Dropped."

  skill_gaps:
    rationalizations_caught:
      - "'The previous audit's findings are fixed, so the circuit is probably clean' — initial read of the new constraints felt 'safe' because the v2 attacks are obviously blocked, but the new constraints introduce their own structural dependencies (the DER prefix uniqueness assumption). Catching the LOW required treating the v3 code as a fresh audit subject, not just diffing against v2."
      - "'I should report something to justify the audit' — the temptation to manufacture a CRITICAL/HIGH finding after the team did the right thing. Rejected: the clean state of the circuits is the audit outcome, and inflating the report would erode trust in real findings."
    missing_from_taxonomy:
      - pattern: "Structural assumption on the *contents* of a cryptographically-authenticated buffer that is not enforced by constraints — e.g., 'the byte pattern X uniquely identifies position Y in the buffer' where the uniqueness is an empirical property of how the signer formats its outputs rather than a circuit invariant."
        detection_heuristic: "For every constant-byte constraint pattern `buf[o+δ] === const`, ask whether the spec requires *the unique* offset matching that pattern or any offset matching it. If the spec implies uniqueness, scan a real fixture and confirm the pattern is empirically unique; flag if a future format change could break the uniqueness."
        false_positive_risk: LOW
      - pattern: "Dead templates / helpers left behind by a refactor in a shared utils file (analogue of audit-v2's dead-signal finding, but at the template granularity)."
        detection_heuristic: "After every refactor that removes a caller, grep for the no-longer-called template name across all production circuits and tests. Zero hits = candidate for deletion."
        false_positive_risk: LOW

    phases_that_struggled:
      - phase: 3
        issue: "Phase 3 analysis of the new SHA-256 padding constraints in userSig required cross-checking the zk-email Sha256Bytes vs Sha256General to determine whether internal SHA-256 padding is added on top of the prover-supplied canonical padding. The methodology document for noir-claude-auditor doesn't directly translate to circom's 'pre-padded input' convention (Noir's stdlib sha256 typically pads internally). Worth a note in the circom adaptation guide that 'Sha256Bytes-pre-padded' and 'Sha256-internal-padded' templates exist in the @zk-email ecosystem and the caller's intent must be cross-checked."

  new_patterns:
    - bug_class: 2     # SPEC_MISMATCH
      pattern: "Constant-byte equality constraints over a prover-supplied offset (`buf[o+δ] === const`) where the *uniqueness* of the matching offset is required for soundness but is an empirical property of the authenticated payload's format, not a constraint."
      detection_heuristic: "Enumerate every byte pattern (const₀, const₁, …, const_{m-1}) the circuit pins at consecutive offsets from a prover-supplied base. Scan a real fixture for all occurrences of that pattern; if > 1, flag immediately. If exactly 1, document the structural argument for why the format guarantees uniqueness — and flag as LOW if the argument depends on external issuance practice."
      false_positive_risk: LOW

  human_feedback:
    true_positives_confirmed:
    false_positives_reported:
    missed_bugs_human_found:
    notes: ""
---
```
