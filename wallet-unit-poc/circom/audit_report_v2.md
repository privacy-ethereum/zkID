# Circom Circuit Security Audit — zkID

**Project:** `wallet-unit-poc/circom/` (zkID — Privacy Stewards of Ethereum)
**Circuits:** `CertChainRSA256` (rs2048 / rs4096), `UserSigRSA256` (rs2048)
**Circom version:** 2.2.3 (declared in every file)
**Constraint field:** `secq256r1` (set in `circomkit.json` — base field of secp256r1, p ≈ 2²⁵⁶ − 2²²⁴ + 2¹⁹² + 2⁹⁶ − 1)
**Proving protocol:** Groth16 (per `circomkit.json`), but consumed by Spartan2-Hyrax in `ecdsa-spartan2/`
**Audited by:** Circom adaptation of [`noir-claude-auditor`](https://github.com/0xvikasrushi/noir-claude-auditor) methodology (Claude Code)
**Audit date:** 2026-05-14
**Scope:** Business-logic and mathematical soundness bugs in circuit constraints.
**Out of scope:** the `circomlib` and `@zk-email/circuits` library code (treated as trusted), the Rust input builder (`zkid-input-builder`), the Spartan2 prover, the Go verifier, smart-contract integration, and underconstrained-signal classes that `circomspect` / Picus / Ecne detect.

---

## Files Audited

| File | Lines | Description |
|---|---|---|
| `circuits/certChain.circom` | 162 | Circuit A: cert-chain RSA verify + DER parsing + SMT non-membership + `pkCommit` |
| `circuits/userSig.circom` | 82 | Circuit B: user RSA signature + `pkCommit` + `nullifier` + `appIdPacked` + challenge binding |
| `circuits/rs256.circom` | 67 | `CertRSA256Verify`: SHA-256 + RSA-65537 verify glue; `Bits2Limbs` |
| `circuits/utils/utils.circom` | 346 | `AssertSliceInTBS`, `VerifyTBSinCert`, `VerifySubjectDN`, `VerifySerialNumber`, `ExtractModulus`, `PackBytes`, `PoseidonBytes`, `PoseidonBytesWithField` |
| `circuits/components/poseidonP256.circom` | 87 | Standard (non-optimised) Poseidon over secq256r1 (t=3, t=4) |
| `circuits/components/poseidonP256Constants.circom` | (~3 K constants) | RF=8, RP_t=3=57, RP_t=4=56 |
| `circuits/components/pkCommit.circom` | 48 | `ChunkedPoseidonP256(N)` sponge wrapper |
| `circuits/components/smtHashP256.circom` | 31 | `SMTHash1P256(key,value,1)`, `SMTHash2P256(L,R)` |
| `circuits/components/smtVerifierP256.circom` | 145 | Circomlib SMT verifier with hash swapped to PoseidonP256 |
| `circuits/components/smtNonmembership.circom` | 19 | Wrapper hard-coding `enabled=1`, `value=0`, `fnc=1` |
| `circuits/main/certChainRS2048.circom` | 7 | `CertChainRSA256(1536, 121, 17, 2048, 17, 2048, 128, 20)`, `public[issuerRsaModulus, smtRoot]` |
| `circuits/main/certChainRS4096.circom` | 7 | `CertChainRSA256(1536, 121, 34, 4096, 17, 2048, 128, 20)`, `public[issuerRsaModulus, smtRoot]` |
| `circuits/main/userSigRS2048.circom` | 7 | `UserSigRSA256(1536, 121, 17)`, `public[challenge]` |

**Total project-authored Circom:** 13 files, ~1 050 lines excluding the Poseidon constants table and `circuits/test/*` fixtures.

**Strategy chosen:** **MEDIUM / FOCUSED** — prioritise public entry points, prover-supplied offsets, hash composition, and length signals. Circomlib + `@zk-email/circuits` treated as trusted.

**Files NOT audited:** `circuits/test/*.circom` (test wrappers), `node_modules/**`, build outputs, and the Poseidon round-constant table.

---

## Assumptions

- Default circom semantics for `<==` (assign + constrain), `<--` (assign only), and `===` (constrain).
- `circomlib`'s `SMTVerifierSM`, `SMTLevIns`, `Multiplexer`, `Num2Bits`, `LessThan`, `LessEqThan`, `GreaterThan`, `GreaterEqThan`, `IsEqual`, `ItemAtIndex`, `Switcher`, `MultiAND`, `ForceEqualIfEnabled` are sound.
- `@zk-email/circuits`'s `Sha256Bytes`, `AssertZeroPadding`, `RSAVerifier65537` (RSA-PKCS#1 v1.5 with e=65537), and `SelectSubArray` are sound; in particular `Sha256Bytes` byte-range-checks each input byte to `[0, 255]`.
- Poseidon over secq256r1 with `RF=8`, `RP=57 (t=3) / 56 (t=4)` provides ≈128-bit security per the Hadeshash recommendation. (See [INFO] finding.)
- The MOICA cert directory is partially public — `(TBS, MOICA-signature-on-TBS)` pairs leak under realistic threat models.
- `pkCommit_A == pkCommit_B` is enforced by the Go verifier *outside* the circuits.
- The verifier compares the public `appIdPacked` output against an issued `app_id` after the same little-endian byte packing.

---

## Executive Summary

Reviewed three production circuits (`CertChainRSA256`, `UserSigRSA256`) covering RSA-SHA256 X.509 verification, SMT-based revocation, device signing, app-id binding, and a Semaphore-style challenge binding. Compared with the previous audit (which found one CRITICAL identity-forgery bug from unbound DER offsets and one HIGH nullifier-malleability bug), the team has correctly refactored extraction to operate on `issuerTbs` rather than the outer `userCertZeroPadded`, added `AssertSliceInTBS` to bound `tbsModulusOffset` / `tbsModulusTagOffset`, equated `issuerTbsLength` to `actualIssuerTbsLength + [0, 128]`, and added `AssertZeroPadding` on `userCertZeroPadded`. The original CRITICAL identity-forgery bug is **closed**.

However, **one new CRITICAL bug and one residual HIGH bug** survive:

1. **CRITICAL — Revocation bypass via `tbsSerialNumberOffset` ambiguity.** The serial-number offset is prover-supplied. The circuit only checks `tbs[offset−2] == 0x02` and `0 < tbs[offset−1] ≤ 20`. Real X.509 TBSes contain multiple ASN.1 INTEGERs that satisfy both checks — the version field (value=2) and the RSA exponent (value=65537) are present in every MOICA-G2 cert at offsets 8 and 512 respectively (verified against the bundled `cert_chain_rs2048/input.json` fixture). A revoked card-holder can point the offset at any of these, get `serialNumber ∈ {2, 65537, …}`, and produce a valid SMT non-membership proof — bypassing revocation completely.

2. **HIGH — Nullifier malleability via `tbs[31..tbsLength]`.** The fix from the previous audit constrained `tbsLength ≤ 64` but did not pin it. Bytes `tbs[31..tbsLength]` are still free (only forced to lie in `[0, 255]` by the SHA-256 byte range-check). With `tbsLength` variable in `[31, 64]`, a card-holder can ask their card to sign up to `256^33 ≈ 2²⁶⁴` distinct `(app_id, tail)` payloads, each producing a distinct deterministic signature and therefore a distinct `nullifier`. Per-`(card, app_id)` uniqueness is broken; Sybil resistance fails.

Three additional MEDIUM/LOW advisories cover: a soundness gap from decoupled `tbsModulusOffset` / `tbsModulusTagOffset` (not exploitable in practice — see Finding 3), the fact that `VerifyTBSinCert` + `userCertZeroPadded` are now redundant after the refactor (dead constraints), and a Poseidon-parameter note (128-bit security target).

**Overall risk: CRITICAL.** Finding 1 alone breaks the revocation property — the core protocol guarantee that revoked cards cannot mint valid identity proofs. Finding 2 breaks Sybil resistance for honest-but-curious card-holders.

Confirmed: 2 · Advisory: 3 · Dropped near-misses: 4

---

## Findings

---

### [CRITICAL] Revocation bypass via `tbsSerialNumberOffset` pointing at non-serial INTEGER fields — SPEC_MISMATCH + COMPOSITION_FLAW

**Location:**
- `CertChainRSA256` in `circuits/certChain.circom:45` — `tbsSerialNumberOffset` is a private input.
- `circuits/certChain.circom:113-118` — only constraints are `tbsSerialNumberOffset ≥ 2` and `tbsSerialNumberOffset + maxSerialNumberLength ≤ actualIssuerTbsLength`.
- `VerifySerialNumber` in `circuits/utils/utils.circom:77-159` — checks `cert[offset−2] == 0x02` and `0 < cert[offset−1] ≤ MAX_SERIAL_LEN (20)`, then reconstructs `target` as a big-endian integer of length `actual_len`.

**Status:** CONFIRMED — concrete attack values verified against the real `circom/inputs/cert_chain_rs2048/input.json` fixture (an actual MOICA-G2 cert).

**Bug class:** SPEC_MISMATCH (the SPEC §"DER parsing" claims "VerifySerialNumber checks that the user cert contains the claimed TBS and serial number" — but the offset is prover-chosen, so the constraint is "*some* INTEGER value lives inside the TBS at the prover-supplied offset", not "*the* serial number").

---

**What the circuit should prove:**
"`serialNumber` is the ASN.1 INTEGER value at the canonical serial-number position of the user's MOICA-signed TBS, and `serialNumber` is not in the revocation SMT rooted at `smtRoot`."

**What the constraints actually enforce:**
"There exists *some* offset `o` in `[2, actualIssuerTbsLength − 20]` such that `issuerTbs[o−2] == 0x02`, `issuerTbs[o−1] = L ∈ (0, 20]`, and `serialNumber = bigendian_decode(issuerTbs[o..o+L])` — and `serialNumber` is non-member of the SMT."

**The gap:**
X.509 TBS structure contains many ASN.1 INTEGER fields beyond the serial number: the version field, the RSA modulus, the RSA exponent, and possibly INTEGER values inside extensions (CRL number, basic-constraints `pathLenConstraint`, …). Any of those whose length byte fits in `(0, 20]` is a valid alternate witness for "the serial".

---

**Concrete attack scenario.** A card-holder whose certificate has been revoked still possesses the physical card and its private key. They want to authenticate as a non-revoked holder. They:

1. Use their own (revoked) MOICA TBS as `issuerTbs` — the MOICA signature `σ` is real.
2. Look at their own TBS. It contains, at minimum:
   - The version INTEGER `02 01 02` (offset ≈ 8, length=1, value=2).
   - The actual serial INTEGER `02 14 ⟨20 bytes⟩` (offset = 11, length=20, value = the real serial in the revocation tree).
   - The RSA exponent INTEGER `02 03 01 00 01` (offset ≈ 512, length=3, value=65537).
3. Set `tbsSerialNumberOffset = 8` (or 10, or 512). All checks pass.
4. Compute the SMT non-membership proof for `serialNumber = 2` (or 5214, or 65537) — trivially valid because none of these field-element values is the real revoked cert serial.
5. Generate Circuit A and Circuit B with their real key. `pkCommit_A == pkCommit_B`, `nullifier` is fresh (because previously generated nullifiers used different `tbs`), `appIdPacked` matches the verifier-issued challenge.
6. Verifier accepts.

**Empirical confirmation** — running the offset scan against the bundled `circom/inputs/cert_chain_rs2048/input.json`:

```
actualIssuerTbsLength = 613
real tbsSerialNumberOffset = 11   (actual_len=20, value=538421965321809317787525307687845558446490054026)

Alternative offsets that ALSO satisfy circuit constraints:
  offset =   8   actual_len = 1    value = 2          ← version
  offset =  10   actual_len = 2    value = 5214       ← overlap of version length + serial header bytes
  offset = 512   actual_len = 3    value = 65537      ← RSA exponent
```

All three (8, 10, 512) satisfy:
- `cert[offset−2] == 0x02`
- `0 < cert[offset−1] ≤ 20`
- `offset ≥ 2` and `offset + 20 ≤ 613`

so all three produce a witness that passes every constraint in `CertChainRSA256` while emitting a `serialNumber` that is not the cert's real serial.

---

**Malicious witness (using the exponent at offset 512 → serialNumber = 65537):**

```
// Public inputs
issuerRsaModulus = MOICA_G2_modulus_limbs                   // real
smtRoot           = current revocation SMT root              // real

// Private inputs
issuerTbs[0..613] = real_TBS_of_revoked_cert                 // real
issuerTbs[613..1536] = 0
actualIssuerTbsLength = 613
issuerTbsLength       = 640                                  // SHA-256-padded length, satisfies the [613, 613+128] window
issuerRsaSignature    = real MOICA signature over real_TBS

userCertZeroPadded[0..3]    = real DER outer header
userCertZeroPadded[4..617]  = real_TBS_of_revoked_cert
userCertZeroPadded[617..]   = 0
actualUserCertLength        = 617

tbsModulusOffset    = 254       // real, points at real modulus
tbsModulusTagOffset = 249       // real, points at real modulus tag
tbsSerialNumberOffset = 512    // ATTACK: points 2 bytes past the exponent INTEGER tag

// Forged "serial"
serialNumber = 65537            // not in the revocation tree

// SMT non-membership proof for 65537 against current smtRoot
smtSiblings, smtOldKey, smtOldValue, smtIsOld0   = standard non-membership witness for 65537

// Linking blinder
pkBlind = uniform random field element

// Outputs
pkCommit = ChunkedPoseidonP256(real_user_modulus_limbs ‖ pkBlind)

Satisfies constraints: YES
  - VerifyTBSinCert      ✓ (userCertZeroPadded[4..617] == issuerTbs[0..613])
  - AssertZeroPadding    ✓ (zero past 617)
  - tbsLenLB / tbsLenUB  ✓ (613 ≤ 640 ≤ 613+128)
  - AssertSliceInTBS     ✓ for tbsModulusTagOffset, tbsModulusOffset
  - tbsSerialNumberOffset ≥ 2 ✓
  - AssertSliceInTBS     ✓ for tbsSerialNumberOffset (512 + 20 = 532 ≤ 613)
  - VerifySerialNumber   ✓ (issuerTbs[510]=0x02, issuerTbs[511]=0x03, decode → 65537)
  - ExtractModulus       ✓ (real modulus)
  - CertRSA256Verify     ✓ (real MOICA signature on real TBS)
  - SMTNonMembershipVerifier ✓ (65537 is genuinely not in the tree)

Violates intended property: YES — the *real* serial (revoked) is never read; the prover used a different INTEGER value as "the serial" and passed the non-membership check on that value instead.
```

---

**Fix.** Two layered options; either suffices, both recommended.

**(a) Bind `tbsSerialNumberOffset` to the canonical serial position.** In a v3 MOICA cert the serial is always at TBS offset 4 + (1 if version is implicit / 0 if explicit-`[0]`). Specifically, after the outer SEQUENCE header (4 bytes) and the optional `[0] EXPLICIT INTEGER (version)` wrapper (5 bytes for v3), the serial's INTEGER tag is at TBS offset 9 or 4. The input builder already computes this (`find_serial_offset_in_tbs` in `zkid-input-builder/src/cert.rs:135`). Encode the parsing in the circuit:

```circom
// Hard-code: version is always present in v3 (DER tag 0xa0, length 0x03, contents 0x02 0x01 0x02)
issuerTbs[0]  === 0xa0;  // [0] EXPLICIT
issuerTbs[1]  === 0x03;
issuerTbs[2]  === 0x02;  // INTEGER (version)
issuerTbs[3]  === 0x01;
issuerTbs[4]  === 0x02;  // v3

// Then serial INTEGER starts at offset 5
issuerTbs[5]  === 0x02;  // INTEGER tag
// length byte at offset 6, value bytes 7..7+len
// Drive VerifySerialNumber with offset=7 (hard-coded, not a private input)
VerifySerialNumber(maxMessageLength, maxSerialNumberLength)(
    issuerTbs,
    7,                  // hard-coded
    serialNumber
);
```

This removes `tbsSerialNumberOffset` from the private-input set entirely. (If MOICA-G3 has a different version-encoding convention, parameterise.)

**(b) Make `serialNumber` a public input, not a prover-supplied value.** If you genuinely want a private serial (which is debatable — the SMT root being public already constrains it), you must at minimum constrain the offset structurally. The strongest version-agnostic fix is to walk the DER structure inside the circuit:

```circom
// Outer SEQUENCE header is constant 4 bytes (tag, len_of_len, 2 len bytes)
// Version [0] block, if present, is the 5-byte sequence above
component hasVersion = IsEqual();
hasVersion.in[0] <== issuerTbs[0];
hasVersion.in[1] <== 0xa0;

// serial-tag offset = 4 (always — note this assumes you stripped the outer SEQUENCE in the input builder)
//                    OR 4 + (hasVersion.out * 5)
signal serialTagOff <== hasVersion.out * 5;
issuerTbs[serialTagOff] === 0x02;

// length byte at serialTagOff+1, value bytes at serialTagOff+2
component serialLen = ItemAtIndex(maxMessageLength);
serialLen.in <== issuerTbs;
serialLen.index <== serialTagOff + 1;

VerifySerialNumber(maxMessageLength, maxSerialNumberLength)(
    issuerTbs,
    serialTagOff + 2,
    serialNumber
);
```

Both fixes close the gap because the offset is no longer a free witness the prover can re-aim at any INTEGER in the TBS.

---

**Severity rationale.** The bug allows complete bypass of the revocation mechanism. Once a card is revoked, the holder still has the card, the private key, and the cert — and with this bug they can produce valid non-revocation proofs forever, pointing at the version or exponent INTEGER instead of the real serial. The protocol's core invariant ("only non-revoked cards can mint identity proofs") is broken. **CRITICAL.**

---

### [HIGH] Sybil bypass on `nullifier` via unconstrained `tbs[31..tbsLength]` — SPEC_MISMATCH

**Location:**
- `UserSigRSA256` in `circuits/userSig.circom:21-81`. Specifically:
  - Lines 22-23 — `tbs[maxMessageLength]` and `tbsLength` are private inputs.
  - Lines 40-46 — `tbsLength` range-checked to 7 bits (`≤ 127`) and bounded `≤ 64`.
  - Lines 48-53 — `CertRSA256Verify` enforces `tbs[i] === 0` for `i ≥ tbsLength` (via `AssertZeroPadding`) and that `signature^65537 mod modulus == PKCS1v15(SHA256(tbs[0..tbsLength]))`.
  - Lines 58-62 — `appIdPacked = PackBytes(31, …)(tbs[0..31])` — only the first 31 bytes are bound to a public output.
  - Lines 76-80 — `nullifier = ChunkedPoseidonP256(userRsaSignature)`.

**Status:** CONFIRMED.

**Bug class:** SPEC_MISMATCH — the SPEC §"Nullifier" claims "the nullifier is deterministic per `(card, app_id)`", but the circuit's actual binding is "deterministic per `(card, tbs)`" where `tbs[31..tbsLength]` is free.

---

**What the circuit should prove:**
"For each `(card, app_id)` pair there is at most one valid `nullifier`, so two valid proofs from the same card on the same app_id collide on `nullifier` and the verifier can de-dupe."

**What the constraints actually enforce:**
"`nullifier = Hash(σ)` where `σ` is some valid PKCS#1 v1.5 RSA signature, under the prover's `userPkLimbs`, of any byte string `tbs[0..tbsLength]` with `0 ≤ tbsLength ≤ 64` whose first 31 bytes equal the public `appIdPacked`."

**The gap:**
For fixed `(card, app_id)`, the prover can vary `tbsLength ∈ [0, 64]` and `tbs[31..tbsLength]` arbitrarily (only constrained to byte-range `[0, 255]` by `Sha256Bytes`'s internal `Num2Bits(8)`). PKCS#1 v1.5 signing is deterministic in its input, so distinct inputs yield distinct signatures yield distinct nullifiers. The number of independently valid `(tbs_i, σ_i, nullifier_i)` triples is bounded by the number of payloads the card will sign — in practice unlimited.

(`tbsLength < 31` is also accepted by every constraint; `AssertZeroPadding` then forces `tbs[tbsLength..1536] = 0`, so `appIdPacked` becomes a truncated app_id padded with zeros. If the protocol-side `app_id` happens to end with zero bytes, this is another malleability axis. With `tbsLength ≥ 31`, only `tbs[31..tbsLength]` is free.)

---

**Concrete attack scenario.** A malicious card-holder wants two valid proofs for the same `app_id` (e.g., to double-vote in an anti-Sybil application). They:

1. Build `payload₁ = app_id (31 bytes) ‖ 0x00` with `tbsLength = 32` and ask the card to sign it → `σ₁`.
2. Build `payload₂ = app_id (31 bytes) ‖ 0x01` with `tbsLength = 32` and ask the card to sign it → `σ₂ ≠ σ₁`.
3. Generate two `(Circuit A, Circuit B)` bundles, both using the same MOICA cert and the same `pkBlind`. Both bundles share `pkCommit` and `appIdPacked`, but `nullifier₁ = Hash(σ₁) ≠ nullifier₂ = Hash(σ₂)`.
4. Submit both proofs. Verifier sees two distinct nullifiers → no de-dup → both accepted as distinct identities.

The card's signing oracle produces a fresh signature for any byte string the host hands it, so the attacker can produce arbitrarily many `(tbs_i, σ_i)` and thus arbitrarily many `nullifier_i` — bounded only by the host's willingness to ask the card to sign.

---

**Malicious witness (one of the pair):**

```
// Public
challenge       = verifier-issued nonce               // bound via the challenge*challenge constraint

// Private
userPkLimbs     = the card's real RSA modulus K       // 17 limbs of 121 bits
tbs[0..31]      = app_id_bytes                        // 31 bytes, bound to public appIdPacked
tbs[31]         = 0x00                                // free byte — the attack vector
tbs[32..1536]   = 0                                   // forced by AssertZeroPadding (tbsLength = 32)
tbsLength       = 32                                  // any value in [31, 64]
userRsaSignature = card.sign_PKCS1v15_SHA256(tbs[0..32])
pkBlind         = same as Circuit A

// Outputs
pkCommit    = ChunkedPoseidonP256(K_limbs ‖ pkBlind)
nullifier   = ChunkedPoseidonP256(userRsaSignature)
appIdPacked = pack_LE_31(tbs[0..31]) = pack_LE_31(app_id_bytes)

A second witness identical except tbs[31] = 0x01 yields a different σ' and a different nullifier',
both with identical (pkCommit, appIdPacked, challenge).

Satisfies constraints: YES (both witnesses)
Violates intended property: YES — per-(card, app_id) uniqueness of nullifier is broken.
```

---

**Fix.** Two options.

**(a) Canonicalise the signing payload.** Force `tbs` to be a circuit-defined function of `appIdPacked` only. Easiest version:

```circom
// Pin tbsLength to a constant (31) so AssertZeroPadding zero-fills the rest of tbs.
tbsLength === 31;
// Drop the Num2Bits(7) + LessEqThan(7) bound (replaced by ===).
```

After this, `tbs` is fully determined by `appIdPacked` (`tbs[0..31] = app_id_bytes`, `tbs[31..1536] = 0`), so `σ` is fully determined by `(K, app_id)`, so `nullifier = Hash(σ)` is fully determined by `(card, app_id)`. **Recommended** because it preserves the SPEC's stated nullifier semantics.

**(b) Move the nullifier off the signature.** Compute the nullifier from data the prover cannot vary while keeping `(card, app_id)` fixed:

```circom
component nullifierHash = ChunkedPoseidonP256(k + 1);
for (var i = 0; i < k; i++) {
    nullifierHash.inputs[i] <== userPkLimbs[i];
}
nullifierHash.inputs[k] <== appIdPacked;
nullifier <== nullifierHash.out;
```

This yields `nullifier = H(K_user, app_id_packed)`, which is deterministic in `(card, app_id)` by construction. Trade-off: anyone who learns `K_user` can recompute the nullifier — `K_user` only appears inside the proof in committed form (`pkCommit`), so this is acceptable for most ZK-identity protocols. If the protocol relies on nullifier secrecy against an adversary holding the cert directory, option (a) is required.

The current SPEC text suggests the intent was option (a) — "PKCS#1 v1.5 signing is deterministic and the signature never leaves the card, so the nullifier is deterministic per `(card, app_id)`" — but the code does not enforce a canonical `tbs`.

This closes the gap because once `tbs` is a deterministic function of `app_id_bytes` (or once the nullifier doesn't depend on `tbs` at all), `(card, app_id) ↦ nullifier` becomes a function rather than a relation.

---

**Severity rationale.** The protocol's anti-Sybil property is carried by per-`(card, app_id)` nullifier uniqueness (SPEC §"Why per-session randomness for `pkBlind`" calls out the nullifier as the carrier of Sybil resistance). The bug breaks that property generally for any honest verifier policy, but the attacker still needs a valid card — so the impact is bounded by "one card-holder can forge unlimited identities for one app_id" rather than "anyone can forge". **HIGH.**

---

### [LOW] `tbsModulusOffset` and `tbsModulusTagOffset` not bound to a fixed DER offset — SPEC_MISMATCH (advisory)

**Location:**
- `circuits/certChain.circom:40-41, 108-109`. `tbsModulusOffset` and `tbsModulusTagOffset` are independent private inputs.
- `circuits/utils/utils.circom:192-277`. `ExtractModulus` checks `tbs[tbsModulusTagOffset] == 0x02` then reads `modulusBytes` bytes starting at `tbsModulusOffset`. There is no constraint that `tbsModulusOffset = tbsModulusTagOffset + DER_PREFIX_LEN` (for RSA-2048 with leading sign byte: 5 → tag + 0x82 + 2 length bytes + 0x00 sign byte).

**Status:** CONFIRMED as a soundness gap; **dropped from CRITICAL/HIGH** because no exploitable forgery is possible.

**Bug class:** SPEC_MISMATCH (advisory).

**Why this is a soundness gap.** A prover can:
- Set `tbsModulusTagOffset = 512` (the RSA exponent tag, `0x02` ✓) and `tbsModulusOffset = 254` (the real modulus location). `ExtractModulus` will pass: tag is 0x02, the 256 "modulus" bytes are the real modulus.
- Set `tbsModulusTagOffset = 249` (the real modulus tag) and `tbsModulusOffset = 0` (any 256-byte window inside the TBS). `ExtractModulus` will pass: tag is 0x02, the 256 "modulus" bytes are non-modulus TBS contents.

**Why it is not exploitable.** Circuit B verifies `userRsaSignature^65537 ≡ PKCS1v15(SHA256(tbs)) (mod userPkLimbs)` and `pkCommit_B = H(userPkLimbs ‖ pkBlind)`. For the Go verifier's `pkCommit_A == pkCommit_B` check to pass with `pkCommit_A` computed over non-modulus TBS bytes `N'`, the prover must produce a signature `σ'` such that `σ'^65537 ≡ … (mod N')`. Random 256-byte windows of the TBS do not coincide with any RSA key for which the prover knows the private exponent, so no valid signature exists. Concretely, the existence of an exploit depends on finding 256 contiguous bytes inside an MOICA TBS that decode to a smooth/factorable composite — which is astronomically unlikely.

**The misalignment is still a soundness gap** because the circuit's claim is "I extracted *the* user modulus from *the* SubjectPublicKeyInfo of the MOICA-signed TBS", whereas the constraints prove "I extracted *some* 256 bytes from the TBS adjacent to *some* 0x02 byte". The gap is unexploitable today but increases blast radius if the surrounding code changes (e.g. if a future feature lets `userPkLimbs` be partially prover-chosen).

---

**Fix.** Bind the two offsets together by parsing the DER length field inside the circuit:

```circom
// For 2048-bit RSA: DER prefix is `02 82 01 01 00` (tag + 2-byte length encoding + sign byte).
// The full prefix length is 5 bytes, so tbsModulusOffset = tbsModulusTagOffset + 5.
component lenByte0 = ItemAtIndex(maxMessageLength);
lenByte0.in <== issuerTbs;
lenByte0.index <== tbsModulusTagOffset + 1;
lenByte0.out === 0x82;  // long-form, 2-byte length follows

component lenByte1 = ItemAtIndex(maxMessageLength);
lenByte1.in <== issuerTbs;
lenByte1.index <== tbsModulusTagOffset + 2;
lenByte1.out === 0x01;

component lenByte2 = ItemAtIndex(maxMessageLength);
lenByte2.in <== issuerTbs;
lenByte2.index <== tbsModulusTagOffset + 3;
lenByte2.out === 0x01;  // length = 257 = 0x0101

component signByte = ItemAtIndex(maxMessageLength);
signByte.in <== issuerTbs;
signByte.index <== tbsModulusTagOffset + 4;
signByte.out === 0x00;

tbsModulusOffset === tbsModulusTagOffset + 5;
```

(The values `0x82 0x01 0x01 0x00` are constant for an unsigned 2048-bit RSA modulus and may need to be parameterised for 4096-bit issuer keys — but `ExtractModulus` is only called for the *user* modulus in Circuit A, which is always 2048-bit.)

**Severity rationale.** Soundness gap with no known exploit; the protocol's chain-of-trust binding survives because Circuit B's RSA verify forces `userPkLimbs` to be a real RSA key for which the prover holds the secret. **LOW** advisory.

---

### [LOW] `VerifyTBSinCert` and `userCertZeroPadded` are redundant after the refactor — SPEC_MISMATCH (advisory)

**Location:**
- `circuits/certChain.circom:34, 71-79`. `userCertZeroPadded`, `actualUserCertLength`, `VerifyTBSinCert(...)`, and `AssertZeroPadding(...)` together account for ≈ 1530 byte-equality constraints plus the zero-padding check.

**Status:** CONFIRMED — dead code, no security impact; flagged for cleanup.

**Bug class:** SPEC_MISMATCH (advisory) — the circuit *appears* to authenticate the outer cert, but in fact the outer cert plays no role in the security argument.

**Why it's dead.** After the refactor:
- `ExtractModulus` now reads from `issuerTbs` (line 131-133).
- `VerifySerialNumber` now reads from `issuerTbs` (line 122-125).
- `CertRSA256Verify` reads from `issuerTbs` (line 137-141).

`userCertZeroPadded` is *only* referenced by `VerifyTBSinCert` (to bind `userCertZeroPadded[4..4+L] == issuerTbs[0..L]`) and by `AssertZeroPadding`. Removing both, along with the two private inputs, would eliminate ≈ 1 500+ constraints without changing what the circuit proves.

If the intent is "the proof attests that a full DER-encoded user certificate exists", that property is *not* enforced (the outer SEQUENCE header at `userCertZeroPadded[0..3]` is never byte-checked, the outer length is not bound to `actualIssuerTbsLength + 4`, and extensions following the TBS are not parsed). So `userCertZeroPadded` adds neither soundness nor a meaningful integrity claim.

---

**Fix.** Remove `userCertZeroPadded`, `actualUserCertLength`, `VerifyTBSinCert`, the `AssertZeroPadding(userCertZeroPadded, …)` call, and the `VerifyTBSinCert` template definition (after auditing all other call sites). Saves R1CS rows and removes a misleading signal name.

If a full-cert binding is desired later, it must include outer-SEQUENCE header verification and post-TBS extension parsing.

**Severity rationale.** No exploitable bug; constraints are merely unnecessary. **LOW** advisory.

---

### [INFO] Poseidon round counts target 128-bit security — CRYPTO_MISUSE (informational)

**Location:** `circuits/components/poseidonP256.circom:26-28` — `var N_ROUNDS_P[2] = [57, 56]; var nRoundsF = 8;`.

**Status:** UNVERIFIED — depends on the project's intended security level.

**Bug class:** CRYPTO_MISUSE (informational only).

The Poseidon instance ships `RF = 8`, `RP_t=3 = 57`, `RP_t=4 = 56`. These match the **128-bit security** parameters from the original Poseidon paper (Hadeshash, §5.3) with α = 5 over a ≈ 256-bit prime. 256-bit security with the same field and α would need `RP_t=3 ≈ 84` and `RP_t=4 ≈ 83`.

Most ZK-identity protocols (Semaphore, Tornado Cash, etc.) target 128-bit security, in which case these parameters are correct. The Spartan2 backend's commitment scheme also targets 128-bit security. **No action required**; consider adding a one-line note in `poseidonP256Constants.circom`:

```circom
// Round counts: RF=8 full, RP={57 for t=3, 56 for t=4} partial.
// Target 128-bit security per Hadeshash §5.3 (α=5, |F|≈256 bits).
```

---

## Areas for Further Investigation

The following patterns did not meet the threshold for a finding but deserve a second look.

1. **Limb-canonicality of `userPkLimbs`.** `userPkLimbs[i]` is a private input. The circuit does not range-check `userPkLimbs[i] < 2ⁿ` (n=121). `RSAVerifier65537` from `@zk-email/circuits` presumably range-checks limbs internally (via its `BigMultModP` / Barrett reduction); if not, a prover could submit non-canonical limbs that hash to a different `pkCommit` than the canonical representation, allowing a single key to mint multiple `pkCommit` values. Worth a focused read of `RSAVerifier65537`'s limb-validation behaviour. Filed against `@zk-email/circuits`, not this codebase.

2. **`smtIsOld0` boolean enforcement.** `circuits/components/smtNonmembership.circom:14` passes `smtIsOld0` as `is0` into `SMTVerifierSM`. The state machine uses `is0` and `(1 - is0)` arithmetically; the composite `st_na + st_iold + st_inew + st_i0 === 1` *should* indirectly force `is0 ∈ {0, 1}`, but a non-boolean `is0` combined with non-boolean other state bits could in principle satisfy the sum-to-one via cancellations in F_p. Circomlib's SMT verifier has been used widely without reported soundness issues, but a one-time review of every boolean input to `SMTVerifierSM` (notably `is0`, `enabled`, `levIns`) is worth doing.

3. **`Bits2Limbs(256, 121, 17)` zero-padding.** `circuits/rs256.circom:18-35` zero-pads bit positions `i*n + j ≥ totalBits`. The assumption is that bits 256..2056 of the limbs end up matching whatever `RSAPad` expects (zero everywhere outside hash bytes 0..255). Manual trace agrees, but a small unit test pinning `limb[3..16] === 0` after `Bits2Limbs` for the SHA-256 input would harden against future changes.

4. **`tbsLength < 31` malleability of `appIdPacked`.** If the verifier accepts `app_id` values whose canonical packing ends in zero bytes, a prover could pick `tbsLength = 28` (say) and have `tbs[28..31] = 0` (forced by `AssertZeroPadding`), producing a `appIdPacked` for a truncated app_id. The verifier's app-id whitelist almost certainly rules this out in practice, but pinning `tbsLength === 31` (per the Finding 2 fix) also closes this.

5. **`pkBlind` randomness assumption.** The circuit imposes no range or non-zero check on `pkBlind`. This is correct because hiding is a prover-side property — but the input-builder layer (`zkid-input-builder`) should sample uniformly from the secq256r1 scalar field. Worth a one-line review there.

6. **`Bits2Limbs` vs `ExtractModulus`.** `rs256.circom`'s `Bits2Limbs(256, n, k)` and `utils.circom`'s `ExtractModulus(..., n, k, modulusBits)` both produce k limbs of n bits from a fixed-bit input. They handle the top-limb zero-padding consistently (both pad bits beyond the explicit size). The implementations are independent — refactoring one without the other could introduce drift. Consider unifying.

---

## Scope and Limitations

This audit covers business-logic and mathematical vulnerabilities in the constraints of the three top-level circuits and their direct dependencies inside this repo. The following are explicitly out of scope:

- Underconstrained-signal classes that automated tools (Picus, Ecne, `circomspect`) target. **Strongly recommend running `circomspect` on `circuits/certChain.circom`, `circuits/userSig.circom`, and `circuits/utils/utils.circom` as a follow-up.**
- The `circomlib` and `@zk-email/circuits` library code, treated as trusted.
- The Spartan2 prover/verifier (`ecdsa-spartan2/`) and the Go verifier (`go-zkid-verifier`).
- The Rust input builder (`zkid-input-builder`); however, see Areas for Further Investigation §5.
- Trusted-setup assumptions for Groth16. The project uses Spartan2/Hyrax for proving, which has no toxic-waste setup — verify with the team that `circomkit.json`'s `"protocol": "groth16"` is purely for compilation tooling and that no Groth16 setup is shipped to production.

This audit is a manual analysis and does not constitute a formal verification.

---

```yaml
---
benchmark:
  circuit:
    name: zkID (CertChainRSA256 + UserSigRSA256)
    files: 13
    lines: ~1050
    complexity: MEDIUM
    strategy_used: FOCUSED

  results:
    confirmed: 2
    unconfirmed: 0
    advisory: 3
    dropped: 4
    classes_triggered: [2, 3]      # SPEC_MISMATCH, COMPOSITION_FLAW; CRYPTO_MISUSE informational only

  false_positives:
    near_misses: 4
    descriptions:
      - "Modulus offset/tag-offset decoupling initially looked CRITICAL (matches the previous audit's bug class), but Circuit B's RSA verify forces userPkLimbs to be a real key the prover knows the private exponent for — no exploit. Demoted to LOW advisory."
      - "challengeSquared <== challenge * challenge: at first glance the dead `challengeSquared` signal looked like unused state. Resolved: <== both assigns AND constrains, and `challenge` is a public input in the main wrapper, so the constraint forces `challenge` to enter the R1CS public-input vector. Sound per the Semaphore reference linked in the comment."
      - "issuerTbsLength range-checking: feared field-element wraparound on the [actualIssuerTbsLength, actualIssuerTbsLength + 128] upper-bound. Traced LessEqThan(14)'s internal Num2Bits(15) — any issuerTbsLength near p fails the bit decomposition. Sound."
      - "PackBytes(31, …) injectivity: 31 bytes pack to 248 bits, well below the secq256r1 prime (~256 bits). Injective. Dropped."

  skill_gaps:
    rationalizations_caught:
      - "'The previous audit's CRITICAL was already fixed, so the circuit is probably clean' — initial read of certChain.circom seemed safe given the new AssertSliceInTBS. The serial-offset bug only surfaced after enumerating all 0x02 INTEGER positions in a real TBS fixture."
      - "'VerifyTBSinCert is doing useful work' — bias from the previous audit's structure (VerifyTBSinCert was the bound that *should* have caught the original CRITICAL). After the refactor it does nothing security-relevant; only spotted by tracing every user of userCertZeroPadded."
    missing_from_taxonomy:
      - pattern: "Prover-supplied offset into a structured byte buffer (DER, protobuf, etc.) where the circuit checks a local tag/length signature but not the offset's *role* — e.g. constraining `cert[offset-2]==0x02` does not pin the offset to *the* INTEGER you want, because the structure contains multiple matching tags."
        detection_heuristic: "For every `*_offset` private input, enumerate every byte pattern in the constrained buffer that satisfies the local check. If the count is > 1 across realistic buffers, the offset is ambiguous and is a SPEC_MISMATCH candidate. Empirical check against fixtures is faster than symbolic analysis."
        false_positive_risk: LOW
      - pattern: "Nullifier or commitment over a deterministic-but-malleable secret-side value (e.g. RSA signature whose input has unbound bytes). Even if the function is deterministic, the *input* may not be uniquely determined by the public binding."
        detection_heuristic: "For every public output of the form `H(secret_function(K, X))`, check every byte/limb of X is bound to (a) a constant, (b) a public input, or (c) an unrelated private input that the protocol fixes. Free bytes in X = malleable output."
        false_positive_risk: LOW
    phases_that_struggled:
      - phase: 2
        issue: "Mapping which signals are public vs private required reading `circuits/main/*.circom` for the `public[...]` annotation; the inner template uses `signal input`/`signal output` uniformly. The SPEC.md public-input table was authoritative this time but only because the previous audit had flagged it."
      - phase: 5
        issue: "Confirming the CRITICAL needed running a Python script over the real TBS fixture — the methodology should explicitly recommend dumping `inputs/*/input.json` and enumerating tag positions for offset-style bugs."

  new_patterns:
    - bug_class: 2     # SPEC_MISMATCH
      pattern: "Constraint of the form `buffer[prover_offset - K] === tag` where the protocol-relevant byte sequence has known structural position(s). The constraint authenticates the local byte but does not pin the offset, and the buffer contains structurally-identical but semantically-different tag occurrences (e.g. multiple ASN.1 INTEGER tags in an X.509 TBS)."
      detection_heuristic: "Enumerate every (offset, value) pair in a representative buffer that satisfies the constraint. If > 1, flag."
      false_positive_risk: LOW
    - bug_class: 3     # COMPOSITION_FLAW
      pattern: "Refactor leaving redundant/dead constraint scaffolding that *looks* like it authenticates state but no longer does (e.g. VerifyTBSinCert + userCertZeroPadded after extractions moved to issuerTbs). Readers — including future auditors — may assume the dead path carries security weight."
      detection_heuristic: "For every signal-input chain, trace whether its bound value reaches any public output. If not, the binding is dead. Particularly common after architectural refactors."
      false_positive_risk: MEDIUM (may reflect intentional defensive constraints)

  human_feedback:
    true_positives_confirmed:
    false_positives_reported:
    missed_bugs_human_found:
    notes: ""
---
```
