# Circom Circuit Security Audit — zkID

**Project:** `wallet-unit-poc/circom/` (zkID — Privacy Stewards of Ethereum)
**Circuits:** `CertChainRSA256` (rs2048 / rs4096), `DeviceSigRSA256` (rs2048)
**Circom version:** 2.2.3
**Constraint field:** `secq256r1` (= scalar field of secq256r1 = base field of secp256r1, p ≈ 2²⁵⁶ − 2²²⁴ + 2¹⁹² + 2⁹⁶ − 1)
**Proving system:** Groth16 (per `circomkit.json`)
**Audited by:** Circom adaptation of [`noir-claude-auditor`](https://github.com/0xvikasrushi/noir-claude-auditor) methodology (Claude Code)
**Scope:** Business‑logic and mathematical bugs in the circuit constraints.
Out of scope: underconstrained‑signal classes detected by external tools (`circomspect`, Picus, Ecne), the `circomlib`/`@zk-email/circuits` library code itself (treated as trusted), the Spartan2 backend, the input‑builder Rust crate, the Go verifier, and any smart‑contract integration.

---

## Files Audited

| File | Lines | Description |
|---|---|---|
| `circuits/cert_chain.circom` | ~120 | Circuit A: cert‑chain RSA verify + DER parsing + SMT non‑membership + `pk_commit` |
| `circuits/device_sig.circom` | ~72 | Circuit B: device RSA signature + `pk_commit` + nullifier + `app_id_packed` + `challenge` binding |
| `circuits/rs256.circom` | ~70 | `CertRSA256Verify`: SHA‑256 + RSA‑65537 verify glue; `Bits2Limbs` |
| `circuits/utils/utils.circom` | ~320 | `VerifyTBSinCert`, `VerifySubjectDN`, `VerifySerialNumber`, `ExtractModulus`, `PackBytes`, `PoseidonBytes`, `PoseidonBytesWithField` |
| `circuits/components/poseidon_p256.circom` | ~87 | Standard Poseidon over secq256r1 (t=3, t=4) |
| `circuits/components/poseidon_p256_constants.circom` | (constants) | RF=8, RP_t=3=57, RP_t=4=56 |
| `circuits/components/pk_commit.circom` | ~48 | `ChunkedPoseidonP256(N)` sponge wrapper |
| `circuits/components/smt_hash_p256.circom` | ~30 | `SMTHash1P256(key,value,1)`, `SMTHash2P256(L,R)` |
| `circuits/components/smt_verifier_p256.circom` | ~145 | Circomlib SMT verifier ported to P‑256 Poseidon |
| `circuits/components/smt-nonmembership.circom` | ~27 | Wrapper hard‑coding `enabled=1`, `value=0`, `fnc=1` |
| `circuits/main/cert_chain_rs2048.circom` | 6 | `CertChainRSA256(1536, 121, 17, 2048, 17, 2048, 128, 128, 20)` |
| `circuits/main/cert_chain_rs4096.circom` | 6 | `CertChainRSA256(1536, 121, 34, 4096, 17, 2048, 128, 128, 20)` |
| `circuits/main/device_sig_rs2048.circom` | 6 | `DeviceSigRSA256(1536, 121, 17)` |

**Total project‑authored Circom:** ~14 files, ~900 lines (excluding constants tables and test wrappers).

**Strategy chosen:** **MEDIUM / FOCUSED** — prioritise public entry points, prover‑supplied offsets, hash composition, and unconstrained signals. Circomlib + `@zk-email/circuits` treated as trusted.

**Files NOT audited:** circuit `circuits/test/*.circom` (test fixtures), `node_modules/**`, build outputs.

---

## Assumptions

- The default circom backend semantics for `<==` (assign + constrain) and `<--` (assign only — no constraint) are honoured.
- `circomlib` `SMTVerifierP256` (a copy of `circomlib`'s SMT verifier with the hash swapped to `PoseidonP256`) is sound when used with the SMT library's standard `enabled / fnc / is0` convention.
- `@zk-email/circuits` `RSAVerifier65537` and `Sha256Bytes` are sound; in particular `RSAPad`+`FpPow65537Mod` correctly verify PKCS#1 v1.5 RSA‑SHA256, and `Sha256Bytes` byte‑range‑checks each input byte.
- `Poseidon` over secq256r1 with `RF=8`, `RP=57 (t=3) / 56 (t=4)` provides ≈128‑bit security per the Hadeshash recommendation. (See LOW finding.)
- The MOICA cert directory is partially public — at minimum, `(TBS, MOICA‑signature‑on‑TBS)` pairs for individual citizens are derivable from a single published or leaked cert.
- `pk_commit` is matched across Circuit A and Circuit B externally by the Go verifier (per SPEC).

---

## Executive Summary

Reviewed three production circuits implementing privacy‑preserving X.509 (RSA‑SHA256) certificate verification with revocation and device signing. **Two confirmed critical/high‑severity soundness bugs** were found, both in the binding between certificate parsing and the public outputs (`pk_commit`, `nullifier`):

1. **CRITICAL — Identity forgery via unbound DER offsets in `CertChainRSA256`.** The user's RSA modulus, subject DN and serial are extracted from `user_cert_zero_padded` at *prover‑supplied* byte offsets that are never constrained to fall inside the MOICA‑signed TBS region. A prover holding any single `(TBS, MOICA‑signature)` pair can mint a `pk_commit` over an attacker‑chosen RSA key.
2. **HIGH — Sybil bypass on `nullifier`.** `nullifier = ChunkedPoseidonP256(user_rsa_signature)` is computed over the RSA signature, which is determined by the bytes the card actually signs. Bytes `tbs[31..tbs_length]` are unconstrained by the circuit, so a single card can produce unboundedly many distinct `(tbs, signature, nullifier)` triples for the same `(card, app_id)` — defeating per‑(card, app_id) uniqueness.

Three additional MEDIUM/LOW findings cover dead/dual signals (`subject_dn`, `actual_user_cert_length`, `issuer_tbs_length` vs `actual_issuer_tbs_length`) that compound the CRITICAL, and a Poseidon‑parameter note (RP corresponds to 128‑bit security).

**Overall risk: CRITICAL.** The CRITICAL finding breaks the protocol's core security property (only a non‑revoked MOICA‑certified holder can prove possession of `pk_commit`). The HIGH finding breaks Sybil resistance.

Confirmed: 2 · High‑confidence: 0 · Medium / Low advisories: 3.

---

## Findings

---

### [CRITICAL] Identity forgery via unbound DER offsets in `CertChainRSA256` — COMPOSITION_FLAW + SPEC_MISMATCH

**Location:**
`CertChainRSA256` in `circuits/cert_chain.circom` (whole template), exploiting:
- `circuits/cert_chain.circom:38–47` — `user_modulus_offset`, `user_modulus_tag_offset`, `subject_dn_offset`, `serial_number_offset` are private inputs with no upper/lower bound constraints.
- `circuits/utils/utils.circom:10–30` — `VerifyTBSinCert` constrains *only* `user_cert[4 .. 4+actual_issuer_tbs_length]` to equal `issuer_tbs`. Bytes 0–3 and bytes ≥ `4+actual_issuer_tbs_length` of `user_cert_zero_padded` are unconstrained.
- `circuits/cert_chain.circom:37` — `actual_user_cert_length` is declared but is **never used** in any constraint, so there is no zero‑padding check on `user_cert_zero_padded`.
- `circuits/utils/utils.circom:166–251` — `ExtractModulus` operates on `user_cert_zero_padded` directly, with prover‑supplied offsets, and only verifies that one byte at `modulusTagOffset` equals `0x02`.

**Status:** CONFIRMED.

**Bug class:** COMPOSITION_FLAW (the modulus/serial/DN extractions are not bound to the signed payload they should belong to) combined with SPEC_MISMATCH (the circuit's actual claim is "I extracted some DER bytes from user_cert" rather than "from the bytes MOICA signed").

---

**What the circuit should prove:**
"There exists an RSA key `K` such that (i) MOICA signed an X.509 TBS containing `K` as the SubjectPublicKey, with serial `S`, (ii) `S` is not revoked in the SMT at `smtRoot`, and (iii) `pk_commit = ChunkedPoseidonP256(K_limbs ‖ pk_blind)`."

**What the constraints actually enforce:**
"There exist values `K`, `S`, and a byte buffer `user_cert` such that:
- `user_cert[4 .. 4+L]` matches `issuer_tbs`, and `(issuer_rsa_modulus, issuer_rsa_signature)` is a valid RSA‑SHA256 signature over `issuer_tbs`,
- there exists *some* offset in `user_cert` whose preceding byte is `0x02` and whose following 256 bytes encode `K`,
- there exist *some* offset in `user_cert` decoding to a serial `S` that is non‑member of the SMT,
- `pk_commit = ChunkedPoseidonP256(K_limbs ‖ pk_blind)`,

with **no constraint that those 'some offsets' fall inside `[4, 4+L)`** and no constraint zero‑padding the rest of `user_cert`."

**The gap:**
The MOICA signature only authenticates `issuer_tbs`. The circuit binds `user_cert[4..4+L]` to `issuer_tbs`, but allows `K` and `S` to be read from anywhere else in `user_cert` — bytes the prover fully controls.

---

**Concrete attack scenario.** Adversary holds a single `(TBS_real, σ_real)` pair where `σ_real = RSA_sign(MOICA_sk, TBS_real)`. Because publishing one's own MOICA cert is common (e.g., for signing JWTs / DIDs), this is realistic for any participant.

The adversary builds a "user cert" buffer of length `maxMessageLength = 1536`:

```
offset 0..3   : 30 82 hh ll              (outer SEQUENCE header — unconstrained, can be anything that decodes consistently
                                          with len fields, but circuit doesn't even check this)
offset 4..4+L : TBS_real                  (the bytes MOICA signed; bound by VerifyTBSinCert)
offset 4+L+0 : 02 82 01 01 00            (DER prefix: INTEGER tag, 257-byte length, sign byte)
offset 4+L+5 : K_attacker (256 bytes)    (attacker's chosen 2048-bit modulus, big-endian)
offset 4+L+261 : 02 14                   (INTEGER tag, length=20)
offset 4+L+263 : S_attacker (20 bytes)   (any serial NOT in the public SMT — easy)
remainder    : zeros                     (no constraint, but byte-range pass via Num2Bits(8))
```

Then set:
- `issuer_tbs = TBS_real`, `issuer_tbs_length = actual_issuer_tbs_length = len(TBS_real)`
- `issuer_rsa_modulus = MOICA_pk` (real public key — public input, has to match anyway)
- `issuer_rsa_signature = σ_real`
- `user_modulus_tag_offset = 4 + L + 0` (points at attacker's `0x02`)
- `user_modulus_offset = 4 + L + 5`
- `subject_dn_offset = anywhere`, `subject_dn` = matching bytes (private, irrelevant)
- `serial_number_offset = 4 + L + 263`, `serialNumber = decode(S_attacker)`
- `smt*` — supply a valid non‑membership proof of `S_attacker` against the public `smtRoot` (trivial because `S_attacker` is freely chosen)
- `pk_blind = anything` (private, prover‑chosen)

All constraints pass:
- `VerifyTBSinCert` ✓ — `user_cert[4..4+L] == TBS_real`.
- `CertRSA256Verify` ✓ — RSA‑SHA256 of `TBS_real` under `MOICA_pk` matches `σ_real`.
- `ExtractModulus` ✓ — `user_cert[user_modulus_tag_offset] == 0x02`, the next 256 bytes decode as `K_attacker`.
- `VerifySerialNumber` ✓ — `cert[offset−2] = 0x02`, `cert[offset−1] = 0x14`, bytes reconstruct to `S_attacker`.
- `VerifySubjectDN` ✓ — trivially, prover supplies matching bytes.
- `SMTNonMembershipVerifier` ✓ — `S_attacker` is fresh, not revoked.
- `pk_commit = ChunkedPoseidonP256(K_attacker_limbs ‖ pk_blind)`.

Then in **Circuit B** (`DeviceSigRSA256`), the adversary uses `K_attacker` (whose private key they hold) to sign any `tbs` of their choosing, producing a `pk_commit` matching Circuit A's. The Go verifier checks `pk_commit_A == pk_commit_B` — passes.

**Result:** The verifier accepts a proof of "non‑revoked MOICA‑certified key" for an RSA key the adversary fully controls, with a serial they fabricated. The chain‑of‑trust binding from MOICA's signature to the user's public key is severed.

**Malicious witness:**

```
issuer_rsa_modulus = MOICA_pk_limbs               // real (public input)
issuer_rsa_signature = sigma_real_limbs           // any real MOICA signature
issuer_tbs = TBS_real (zero-padded)               // any real TBS MOICA signed
issuer_tbs_length = L                             // real length
actual_issuer_tbs_length = L

user_cert_zero_padded[0..3] = 30 82 hh ll         // unconstrained header
user_cert_zero_padded[4..4+L] = TBS_real
user_cert_zero_padded[4+L..4+L+5] = 02 82 01 01 00
user_cert_zero_padded[4+L+5..4+L+261] = K_attacker (big-endian, 256 bytes)
user_cert_zero_padded[4+L+261..4+L+263] = 02 14
user_cert_zero_padded[4+L+263..4+L+283] = S_attacker
user_cert_zero_padded[rest] = 00

actual_user_cert_length = anything                // unused, doesn't matter
user_modulus_tag_offset = 4 + L
user_modulus_offset = 4 + L + 5
subject_dn_offset = anywhere consistent
serial_number_offset = 4 + L + 263
serialNumber = bigendian_decode(S_attacker)

smtRoot = current public revocation root
smtSiblings, smtOldKey, smtOldValue, smtIsOld0 = standard non-membership witness for S_attacker
                                                  (computable from the public SMT in O(depth))

pk_blind = uniform random field element

Output: pk_commit = ChunkedPoseidonP256(K_attacker_limbs ‖ pk_blind)

Satisfies constraints: YES
Violates intended property: YES — the public key K_attacker was never certified by MOICA.
```

---

**Fix.** Two layered changes; both should be applied.

**(a) Bind extraction offsets to the signed TBS region.** In `cert_chain.circom`, after binding `actual_issuer_tbs_length`, add bounds on every prover‑supplied offset:

```circom
// modulusTagOffset and the modulusOffset+modulusBytes window must lie inside [4, 4+actual_issuer_tbs_length)
component modTagLB = GreaterEqThan(12);
modTagLB.in[0] <== user_modulus_tag_offset;
modTagLB.in[1] <== 4;  // TBS_OFFSET
modTagLB.out === 1;

component modWinUB = LessEqThan(12);
modWinUB.in[0] <== user_modulus_offset + (modulusBitsUser \ 8);  // 256 for 2048
modWinUB.in[1] <== 4 + actual_issuer_tbs_length;
modWinUB.out === 1;

// And bind tag-offset to modulus-offset (PKCS-style: tag, len-of-len byte, len bytes, optional 0x00 sign byte).
// Either constrain modulusOffset = modulusTagOffset + 5 (for 2048-bit moduli with leading 0x00 sign byte),
// or extract the length field inside the circuit.

// Same pattern for subject_dn_offset + subject_dn_length and for (serial_number_offset - 2 ... serial_number_offset + actual_len).
```

**(b) Better: extract from `issuer_tbs`, not `user_cert`.** Since `VerifyTBSinCert` already enforces `user_cert[4..4+L] == issuer_tbs[0..L]`, calling `ExtractModulus`, `VerifySubjectDN`, `VerifySerialNumber` on `issuer_tbs` (with offsets relative to TBS, not user_cert) eliminates the unbounded‑offset surface entirely. The surrounding `user_cert` bytes become irrelevant to the security argument — and should also be bound by `AssertZeroPadding(user_cert_zero_padded, actual_user_cert_length)` for hygiene.

This closes the gap because the only modulus, serial, and DN bytes that can satisfy the constraints will be ones MOICA actually signed.

---

**Severity rationale:** The bug allows complete impersonation of the certification chain — an attacker proves "I am a non‑revoked MOICA cert holder" while in fact they hold no MOICA‑certified key. Every downstream property (Sybil resistance, single‑identity binding, revocation enforcement) collapses. CRITICAL.

---

### [HIGH] Sybil bypass on nullifier via unconstrained `tbs` tail in `DeviceSigRSA256` — SPEC_MISMATCH

**Location:**
`DeviceSigRSA256` in `circuits/device_sig.circom:21–71`. Specifically:
- Lines 22–23 — `tbs[maxMessageLength]` and `tbs_length` are private inputs.
- Lines 38–43 — `CertRSA256Verify(tbs, tbs_length, user_pk_limbs, user_rsa_signature)` enforces `tbs[i] === 0` for `i ≥ tbs_length` (via `AssertZeroPadding`) and that `signature^65537 mod modulus == PKCS1v15(SHA256(tbs[0..tbs_length]))`.
- Lines 48–52 — only `tbs[0..31]` is bound to `app_id_packed` (via `PackBytes(31, …)`). Bytes `tbs[31..tbs_length]` are entirely unconstrained.
- Lines 66–70 — `nullifier = ChunkedPoseidonP256(user_rsa_signature)`.

**Status:** CONFIRMED.

**Bug class:** SPEC_MISMATCH (the SPEC claims "deterministic per `(card, app_id)`" but the circuit's actual binding is "deterministic per `(card, tbs)`").

---

**What the circuit should prove:**
"For each `(card, app_id)` pair there is exactly one valid `nullifier`, so two valid proofs from the same card on the same app_id collide on `nullifier` and the verifier can dedupe."

**What the constraints actually enforce:**
"`nullifier = Hash(σ)` where `σ` is some valid PKCS#1 v1.5 RSA signature, under the prover's `user_pk`, of *any* byte string `tbs` of length `tbs_length` whose first 31 bytes equal the public `app_id_packed`."

**The gap:**
For fixed `(card, app_id)`, the prover can vary `tbs[31..tbs_length]` arbitrarily. PKCS#1 v1.5 is deterministic in its input, so distinct inputs yield distinct signatures yield distinct nullifiers — all of which are independently valid.

---

**Concrete attack scenario.** A malicious holder of a real MOICA card wants two valid proofs for the same `app_id` (e.g., to vote twice in an anti‑Sybil application). They:

1. Build `payload_1 = app_id (31 bytes) || 0x00` (`tbs_length = 32`) and ask the card to sign it. Get `σ_1`.
2. Build `payload_2 = app_id || 0x01` and ask the card to sign it. Get `σ_2 ≠ σ_1`.
3. Generate two Circuit‑A+B proof bundles, both using the same MOICA cert + same `pk_blind`. The two bundles share `pk_commit` and `app_id_packed`, but `nullifier_1 = Hash(σ_1) ≠ nullifier_2 = Hash(σ_2)`.
4. Submit both proofs. Verifier sees two distinct nullifiers → no dedup → both accepted.

The card's signing oracle produces a fresh signature for any byte string the host hands it, so the attacker can produce arbitrarily many `(tbs_i, σ_i)` and thus arbitrarily many `nullifier_i` — bounded only by the host's willingness to ask the card to sign.

**Malicious witness (one of the pair):**

```
user_pk_limbs = card's real RSA modulus K
tbs[0..31] = app_id_bytes (31 bytes)            // bound to public app_id_packed
tbs[31] = 0x00 (or any byte; not constrained)
tbs[32..maxMessageLength-1] = 0                 // forced by AssertZeroPadding only past tbs_length
tbs_length = 32                                 // any value 31 ≤ tbs_length ≤ maxMessageLength
user_rsa_signature = card_sign_PKCS1v15_SHA256(tbs[0..tbs_length], K_priv)
challenge = verifier's challenge
pk_blind = same as Circuit A

Output: nullifier = ChunkedPoseidonP256(user_rsa_signature)

A second witness with tbs[31] = 0x01 yields a different valid σ' and a different nullifier',
both with identical (pk_commit, app_id_packed).

Satisfies constraints: YES (both witnesses)
Violates intended property: YES — per-(card, app_id) uniqueness of nullifier is broken.
```

---

**Fix.** Two clean options.

**(a) Canonicalize the signing payload.** Force `tbs` to be a circuit‑defined function of `app_id_bytes` only:

```circom
// Pin tbs_length to a constant (e.g. 31) so AssertZeroPadding zero-fills the rest.
tbs_length === 31;
// (No other change needed — AssertZeroPadding already handles tbs[31..maxMessageLength].)
```

If a longer payload is needed (e.g. an SHA‑256 SubjectPublicKeyInfo prefix to harden replay), assemble it inside the circuit from `app_id_bytes` and constants, then run `CertRSA256Verify` on that assembled payload.

**(b) Move nullifier off the signature.** Compute the nullifier from data the prover cannot vary while keeping `(card, app_id)` fixed:

```circom
component nullifierHash = ChunkedPoseidonP256(k + 1);
for (var i = 0; i < k; i++) {
    nullifierHash.inputs[i] <== user_pk_limbs[i];
}
nullifierHash.inputs[k] <== app_id_packed;
nullifier <== nullifierHash.out;
```

This yields `nullifier = H(K_user, app_id_packed)`, which is deterministic in `(card, app_id)` by construction. The trade‑off is that anyone who learns `K_user` can recompute the nullifier — but `K_user` only appears inside the proof in committed form (`pk_commit`), so this is acceptable for most ZK‑identity protocols. Note: if the protocol relies on nullifier *secrecy* against an adversary holding the cert directory, option (a) is required.

The current SPEC text suggests the intent was option (a) (see SPEC.md §"What the circuits prove", "PKCS#1 v1.5 signing is deterministic and the signature never leaves the card, so the nullifier is deterministic per `(card, app_id)`") — but the code does not enforce a canonical `tbs`.

This closes the gap because once `tbs` is a deterministic function of `app_id_bytes` (or once the nullifier doesn't depend on `tbs` at all), `(card, app_id) ↦ nullifier` becomes a function rather than a relation.

---

**Severity rationale:** The protocol's anti‑Sybil property relies on per‑`(card, app_id)` nullifier uniqueness (SPEC §"Why per‑session randomness for `pk_blind`" calls out nullifier as the carrier of Sybil resistance). The bug breaks that property generally for any honest verifier policy, but the attacker still needs a valid card — so the impact is bounded by "one cardholder can forge unlimited identities for one app_id" rather than "anyone can forge". HIGH, not CRITICAL.

---

### [MEDIUM] Dead and dual length signals in `CertChainRSA256` — SPEC_MISMATCH

**Location:** `circuits/cert_chain.circom:37, 51, 52` and the call sites at lines 70–101.

**Status:** CONFIRMED (advisory — these are not directly exploitable beyond the CRITICAL bug above, but they materially worsen its blast radius and signal incomplete development).

**Bug class:** SPEC_MISMATCH.

**Three coupled issues:**

1. **`actual_user_cert_length`** (line 37) is declared as a private input but never appears in any constraint, sub‑template call, or expression in the entire `CertChainRSA256` template. The most likely intended use was an `AssertZeroPadding(maxMessageLength)(user_cert_zero_padded, actual_user_cert_length)` to mirror what `CertRSA256Verify` does for `issuer_tbs`. Without it, `user_cert_zero_padded` bytes outside `[4, 4+actual_issuer_tbs_length)` are unconstrained — exactly the precondition of the CRITICAL finding above.

2. **`subject_dn`** is bound only via `VerifySubjectDN(user_cert_zero_padded, subject_dn, subject_dn_offset, subject_dn_length)` and never enters any other constraint — not the public output, not the `pk_commit`, nothing. Since `subject_dn` is private, the prover can supply *any* `subject_dn` together with a matching offset/length triple. Functionally, this constraint adds zero security: it only reads bytes back into a private witness the prover already controls. It also encourages the offset bug above (the developer treats `user_cert` as freely indexable).

3. **`issuer_tbs_length` vs `actual_issuer_tbs_length`.** Both are private inputs, both nominally describe the length of `issuer_tbs`. `issuer_tbs_length` is consumed by `CertRSA256Verify` (drives the SHA‑256 padded length and the `AssertZeroPadding` boundary on `issuer_tbs`); `actual_issuer_tbs_length` is consumed by `VerifyTBSinCert` (drives the byte‑equality range against `user_cert`). **There is no constraint `issuer_tbs_length === actual_issuer_tbs_length`.** If they diverge, `user_cert[4 + min(...) .. 4 + max(...))` is unconstrained relative to `issuer_tbs` (or vice versa), enlarging the attack surface for the CRITICAL finding.

---

**Concrete witness (illustrative, not standalone exploitable):**

For (3): set `issuer_tbs_length = 1000`, `actual_issuer_tbs_length = 800`. `VerifyTBSinCert` only enforces equality on bytes 4..804 of `user_cert`. `CertRSA256Verify` hashes `issuer_tbs[0..1000]`, with `issuer_tbs[i] === 0` for `i ≥ 1000`. Bytes `issuer_tbs[800..1000]` are forced to whatever the prover puts in `issuer_tbs` — but bytes `user_cert[804..1004]` are not bound to those. This gives the prover an extra 200 free bytes inside what looks like the TBS region from `user_cert`'s vantage.

---

**Fix.**

```circom
// (1) Constrain user_cert zero-padding (also helps the CRITICAL fix).
AssertZeroPadding(maxMessageLength)(user_cert_zero_padded, actual_user_cert_length);

// (3) Collapse the two length signals or equate them.
issuer_tbs_length === actual_issuer_tbs_length;
// (preferred: delete one signal entirely; pick whichever is exposed at the API boundary).

// (2) Either delete subject_dn / subject_dn_offset / subject_dn_length entirely, or
// fold subject_dn into a meaningful binding, e.g. include it in pk_commit:
//   pkCommit.inputs[k_user + 1] <== PoseidonBytes(subject_dn_max)(subject_dn);
// and grow ChunkedPoseidonP256 by one slot.
```

**Severity rationale:** Each on its own is "dead code / API smell". Together they enlarge the attack surface of the CRITICAL bug from "outside `user_cert[4..4+L]`" to "anywhere in `user_cert` plus a 200‑byte hole inside it." MEDIUM.

---

### [LOW] Poseidon round counts target 128‑bit security, not 256‑bit — CRYPTO_MISUSE (advisory)

**Location:** `circuits/components/poseidon_p256.circom:26` and `poseidon_p256_constants.circom` header comment.

**Status:** HIGH CONFIDENCE UNCONFIRMED — depends on the project's security target.

**Bug class:** CRYPTO_MISUSE.

The Poseidon instance ships `RF = 8`, `RP_t=3 = 57`, `RP_t=4 = 56`. These match the **128‑bit security** parameters from the original Poseidon paper (Hadeshash, §5.3, with α=5 and field size ≈ 256 bits). 256‑bit security with the same field and α would require approximately `RP_t=3 ≈ 84–85` and `RP_t=4 ≈ 83–84`.

Most ZK‑identity protocols (including Semaphore, Tornado, etc.) target 128‑bit security, in which case these parameters are correct. zkID's threat model and the Spartan2 backend should be checked: if the proof system is configured for ≥128‑bit security and the protocol does not require collision resistance > 128 bits, this is fine.

**Suggested action.** Confirm 128‑bit security is the intended target (it almost certainly is) and add a one‑line comment in `poseidon_p256_constants.circom` stating "128‑bit security per Hadeshash recommendation, secq256r1 field, RF=8, RP={57,56}". No code change otherwise.

---

## Areas for Further Investigation

The following patterns did not reach the threshold for a finding but deserve a second look.

1. **`smtIsOld0` boolean enforcement.** `circuits/components/smt-nonmembership.circom:21` forwards `smtIsOld0` as `is0` into the `circomlib`‑style state machine `SMTVerifierSM`. That state machine uses `is0` and `(1 - is0)` arithmetically (e.g. `st_iold <== prev_top_lev_ins_fnc * (1 - is0)`). The composite final constraint `st_na + st_iold + st_inew + st_i0 === 1` *should* indirectly force `is0 ∈ {0,1}` for honest paths, but a non‑boolean `is0` combined with non‑boolean other state bits could in principle satisfy the sum‑to‑one with cancellations in F_p. Circomlib's SMT verifier has been used widely without reported soundness issues, but reviewing the boolean enforcement of every input to `SMTVerifierSM` (notably `is0`, `enabled`, `levIns`) is worth doing once.

2. **`Bits2Limbs(256, 121, 17)` zero‑padding.** `circuits/rs256.circom:18–35` zero‑pads bits beyond `totalBits = 256` for bit positions `i*n+j ≥ 256`. The implicit assumption is that bits 256..2056 of the limbs end up matching whatever `RSAPad` expects (zero everywhere outside the hash bytes 0..255). Manual trace agrees, but a small unit test pinning `limb[3..16] === 0` after `Bits2Limbs` for the SHA‑256 input would be useful.

3. **`PackBytes(31, …)`** assumes `BYTES_PER_FIELD = 31` is safe for the secq256r1 prime (31 bytes = 248 bits; the prime is 256 bits). A 31‑byte field element ≤ 2^248 − 1 ≪ p, so packing is injective. Confirmed safe.

4. **`subject_dn` binding.** Given finding [MEDIUM], if the team intends the cert's subject DN to be auditable post‑hoc, adding it as a public output (or binding it into `pk_commit`) is an inexpensive change.

5. **`pk_blind` randomness assumption.** The circuit imposes no range or non‑zero check on `pk_blind`. This is correct because hiding is a prover‑side property — but the input‑builder layer (`zkid-input-builder`) should sample uniformly from the secq256r1 scalar field. Worth a one‑line review there.

---

## Scope and Limitations

This audit covers business‑logic and mathematical vulnerabilities in the constraints of the three top‑level circuits and their direct dependencies inside this repo. The following are explicitly out of scope:

- Underconstrained‑signal classes that automated tools (Picus, Ecne, `circomspect`) target. **Strongly recommend running `circomspect` on `circuits/cert_chain.circom`, `circuits/device_sig.circom`, and `circuits/utils/utils.circom` as a follow‑up.**
- The `circomlib` and `@zk-email/circuits` library code, treated as trusted.
- The Spartan2 prover/verifier (`ecdsa-spartan2/`) and the Go verifier (`go-zkid-verifier`).
- The Rust input builder (`zkid-input-builder`); however, see "Areas for Further Investigation" §5.
- Trusted‑setup assumptions for Groth16 (the project may switch to Spartan2/Hyrax for the prover, in which case there is no toxic‑waste setup — verify with the team).

This audit is a manual analysis and does not constitute a formal verification.

---

```yaml
---
benchmark:
  circuit:
    name: zkID (CertChainRSA256 + DeviceSigRSA256)
    files: 14
    lines: ~900
    complexity: MEDIUM
    strategy_used: FOCUSED

  results:
    confirmed: 2
    unconfirmed: 0
    advisory: 3
    dropped: 4
    classes_triggered: [2, 3]   # SPEC_MISMATCH, COMPOSITION_FLAW; LOW (4) advisory only

  false_positives:
    near_misses: 4
    descriptions:
      - "Poseidon partial-round wiring (sigma[r][j].in <== 0 for partial rounds, j>0) initially looked like an unconstrained signal but the value is unused in the MDS step (which uses state[r][j] + C[r*t+j] directly). Dropped after re-reading lines 60-82."
      - "ChunkedPoseidonP256 chaining considered for length-extension; rejected because the two call sites have different fixed input counts (17 vs 18) so cannot collide via length confusion."
      - "secq256r1 vs P-256 base field name confusion in the constants file header (`P-256 base field`); resolved that circom's `secq256r1` mode uses the secq256r1 scalar field which equals the secp256r1 base field. Constants file is consistent."
      - "actual_len < MAX_SERIAL_LEN edge in VerifySerialNumber; the byte_weight reconstruction goes to zero for i >= actual_len so the recon sum is correct. Dropped."

  skill_gaps:
    rationalizations_caught:
      - "'This constraint looks correct' — initial read of VerifyTBSinCert seemed fine; only by tracing user_cert outside the bound region did the CRITICAL emerge."
      - "'No documentation, so I can't determine intent' — SPEC.md was rich but had to be cross-checked against the main wrapper (which exposed only `challenge` as public, not `app_id_bytes`); resolved by reading the public-output declarations directly."
    missing_from_taxonomy:
      - pattern: "Prover-supplied byte offsets used to extract structured data from a longer buffer, with no constraint that the offsets fall inside the authenticated portion of the buffer (CRITICAL above is the canonical instance)."
        detection_heuristic: "grep for `signal input *_offset` and check whether the corresponding offset enters any GreaterEqThan / LessEqThan / range-check binding the offset to a length signal that appears in an integrity check (signature, hash, MAC, Merkle root)."
        false_positive_risk: LOW
      - pattern: "Nullifier-from-signature-of-payload where the payload is wider than the public binding (here app_id is bound but tbs[31..] is free) — the nullifier is per-payload, not per-(key, public-binding)."
        detection_heuristic: "Whenever nullifier = H(signature) or H(deterministic_function(secret, public_data)), check that every byte of the input to the deterministic function is bound to either a constant, the public-input set, or the secret key — no free bytes."
        false_positive_risk: LOW
      - pattern: "Dual length signals for the same byte buffer with no equality constraint between them (issuer_tbs_length vs actual_issuer_tbs_length)."
        detection_heuristic: "grep for two distinct `signal input *_length` (or *_len) entries naming the same buffer. Flag if no `=== ` between them."
        false_positive_risk: MEDIUM (may be intentional in two-pass / variable-length structures).
    phases_that_struggled:
      - phase: 2
        issue: "Mapping which inputs are public vs private required cross-referencing the main wrapper (`circuits/main/*.circom`) — the inner template uses `signal input` uniformly. Adding a quick public-input table at the top of each main wrapper / SPEC would help."

  new_patterns:
    - bug_class: 3   # COMPOSITION_FLAW
      pattern: "X.509 / DER parsing where structural-element offsets are prover-supplied without binding to the cryptographically authenticated payload range."
      detection_heuristic: "For every `*_offset` private input feeding a Multiplexer / SelectSubArray, find the integrity check (signature, hash) that authenticates the buffer slice the offset is supposed to land in. If no GreaterEqThan/LessEqThan binds the offset (and offset+length) into that slice, the extraction is in the unauthenticated region."
      false_positive_risk: LOW
    - bug_class: 2   # SPEC_MISMATCH
      pattern: "`signal input` declared in template but never referenced in any constraint (true dead input). In Circom this is not flagged by the compiler (unlike Noir's `nargo check` which may warn)."
      detection_heuristic: "grep -n 'signal input ' for every template; for each, count occurrences of the signal name elsewhere in the same file. Zero hits = dead input."
      false_positive_risk: LOW

  human_feedback:
    true_positives_confirmed:
    false_positives_reported:
    missed_bugs_human_found:
    notes: ""
---
```
