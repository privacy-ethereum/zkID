/**
 * Audit v2 regression suite — see `wallet-unit-poc/circom/audit_report_v2.md`.
 *
 * Each describe block isolates one finding from the audit and demonstrates
 * the gap at the template level by exercising the bypassable component
 * directly with circomkit's `WitnessTester`. The full-circuit positive
 * baselines (`should accept valid cert chain inputs`, etc.) stay in the
 * per-circuit test files; everything that proves an audit-finding-specific
 * constraint gap lives here.
 */
import { WitnessTester } from "circomkit";
import { circomkit } from "../common";
import { loadInput } from "../common/fixtures";
import assert from "node:assert";
import {
  constants as cryptoConstants,
  generateKeyPairSync,
  sign as cryptoSign,
  type KeyObject,
} from "node:crypto";
import { sha256Pad } from "@zk-email/helpers/dist/shaHash";
import {
  bigIntToChunkedBytes,
  bytesToBigInt,
} from "@zk-email/helpers/dist/binaryFormat";

const MAX_MESSAGE_LENGTH = 1536;
const MAX_SERIAL_LEN = 20;
const N_BITS = 121;
const K_LIMBS_USER = 17;
const USER_MODULUS_BITS = 2048;

/**
 * Scan a TBS buffer for every ASN.1 INTEGER tag whose length byte lies in
 * (0, MAX_SERIAL_LEN] — the same local checks `VerifySerialNumber` performs
 * on (cert[offset-2], cert[offset-1]). Returns the (offset, decoded value)
 * pairs the prover could supply to `tbsSerialNumberOffset`/`serialNumber`.
 */
function findAlternateSerialOffsets(
  tbs: readonly bigint[],
  tbsLen: number
): { offset: number; target: bigint }[] {
  const out: { offset: number; target: bigint }[] = [];
  for (let i = 0; i + 2 < tbsLen; i++) {
    if (Number(tbs[i]) !== 0x02) continue;
    const L = Number(tbs[i + 1]);
    if (L <= 0 || L > MAX_SERIAL_LEN) continue;
    if (i + 2 + L > tbsLen) continue;
    let v = 0n;
    for (let j = 0; j < L; j++) v = v * 256n + tbs[i + 2 + j];
    out.push({ offset: i + 2, target: v });
  }
  return out;
}

/**
 * Compute the canonical serial-INTEGER offset (first byte of the serial
 * value) inside a MOICA TBS by walking the outer SEQUENCE + optional
 * [0] EXPLICIT version block, mirroring the DER walk the audit's
 * recommended Fix (a) performs in-circuit.
 */
function canonicalSerialOffset(tbs: readonly bigint[]): number {
  const hasVersion = Number(tbs[4]) === 0xa0;
  return 4 + (hasVersion ? 5 : 0) + 2;
}

describe("Audit v2 regression suite", function () {
  /**
   * Finding 1 (CRITICAL) — `tbsSerialNumberOffset` is not pinned to the
   * canonical serial position. `VerifySerialNumber` only checks
   *
   *   cert[offset-2] == 0x02
   *   0 < cert[offset-1] <= MAX_SERIAL_LEN
   *
   * and a real X.509 TBS contains several ASN.1 INTEGERs that satisfy these
   * checks (version field, RSA exponent, …). A revoked card-holder can
   * re-aim `tbsSerialNumberOffset` at any of them, supply the decoded value
   * as `serialNumber`, and build a trivially-valid SMT non-membership proof
   * — bypassing revocation. This block proves the constraint is bypassable
   * at the template level. The SMT step is out of scope here: once
   * `VerifySerialNumber` accepts a forged value, the only remaining defense
   * is the non-membership proof, which is trivially satisfied for any
   * integer (like 2 or 65537) that is not on the revocation tree.
   */
  describe("[CRITICAL] tbsSerialNumberOffset is not pinned to the canonical serial position", function () {
    let serialCircuit: WitnessTester<["cert", "offset", "target"], []>;
    let input: Record<string, any>;
    let alternates: { offset: number; target: bigint }[];

    before(async function () {
      this.timeout(900_000);
      input = loadInput("cert_chain_rs2048");
      serialCircuit = await circomkit.WitnessTester(
        "VerifySerialNumberFixture",
        {
          file: "utils/utils",
          template: "VerifySerialNumber",
          params: [MAX_MESSAGE_LENGTH, MAX_SERIAL_LEN],
        }
      );
      const tbsLen = Number(input.actualIssuerTbsLength as bigint);
      alternates = findAlternateSerialOffsets(
        input.issuerTbs as bigint[],
        tbsLen
      );
    });

    it("fixture's TBS contains more than one ASN.1 INTEGER offset satisfying the local tag/length checks", function () {
      const realSerial = input.serialNumber as bigint;
      const realOffset = canonicalSerialOffset(input.issuerTbs as bigint[]);
      const realHit = alternates.find(
        (a) => a.offset === realOffset && a.target === realSerial
      );
      assert.ok(
        realHit !== undefined,
        `expected the real (offset=${realOffset}, serial=${realSerial}) to appear in the scan`
      );
      const forged = alternates.filter(
        (a) => !(a.offset === realOffset && a.target === realSerial)
      );
      assert.ok(
        forged.length > 0,
        `expected at least one alternate (offset, target) the prover could aim at; got ${alternates.length} total hits`
      );
      console.log(
        "  alternate serial witnesses derived from the real fixture:",
        alternates
          .map((a) => `offset=${a.offset} target=${a.target}`)
          .join("; ")
      );
    });

    it("baseline: VerifySerialNumber accepts the canonical (offset, serial) pair", async function () {
      this.timeout(900_000);
      await serialCircuit.expectPass({
        cert: input.issuerTbs,
        offset: BigInt(canonicalSerialOffset(input.issuerTbs as bigint[])),
        target: input.serialNumber,
      });
    });

    const attackerWitnesses: {
      description: string;
      forgedOffset: bigint;
      forgedTarget: bigint;
    }[] = [
      {
        description: "version INTEGER (value = 2)",
        forgedOffset: 8n,
        forgedTarget: 2n,
      },
      {
        description: "version/serial header overlap (value = 5214)",
        forgedOffset: 10n,
        forgedTarget: 5214n,
      },
      {
        description: "RSA exponent INTEGER (value = 65537)",
        forgedOffset: 512n,
        forgedTarget: 65537n,
      },
    ];

    for (const { description, forgedOffset, forgedTarget } of attackerWitnesses) {
      it(`BYPASS: VerifySerialNumber accepts forged offset=${forgedOffset} target=${forgedTarget} (${description})`, async function () {
        this.timeout(900_000);
        // Cross-check against the live scan so a fixture rotation can't make
        // the hardcoded values silently obsolete.
        const live = alternates.find(
          (a) => BigInt(a.offset) === forgedOffset && a.target === forgedTarget
        );
        assert.ok(
          live !== undefined,
          `attacker witness (offset=${forgedOffset}, target=${forgedTarget}) is no longer derivable from the fixture; update the test if the fixture rotated`
        );
        await serialCircuit.expectPass({
          cert: input.issuerTbs,
          offset: forgedOffset,
          target: forgedTarget,
        });
      });
    }
  });

  /**
   * Finding 2 (HIGH) — `nullifier` is malleable for fixed `(card, app_id)`.
   * The circuit's only constraints on `tbsLength` are `Num2Bits(7)` and
   * `tbsLength <= 64`. Bytes `tbs[31..tbsLength]` are only byte-range-checked
   * by SHA-256; `AssertZeroPadding` zero-fills `tbs[tbsLength..1536]` but
   * says nothing about `tbs[31..tbsLength]`. Since `appIdPacked` is
   * `PackBytes(31)(tbs[0..31])`, the prover can keep `(userPkLimbs, tbs[0..31])`
   * fixed and vary `tbs[31..]` + `tbsLength` to mint different signatures
   * and therefore different nullifiers. Per-`(card, app_id)` uniqueness is
   * broken.
   *
   * This test instantiates a fresh RSA-2048 signing oracle in Node, builds
   * two valid witnesses that share `(userPkLimbs, tbs[0..31])` but differ in
   * `tbs[31..]`, and asserts the circuit accepts both with `appIdPacked_A
   * == appIdPacked_B` and `nullifier_A != nullifier_B`.
   */
  describe("[HIGH] nullifier is malleable under fixed (card, app_id)", function () {
    let userSigCircuit: WitnessTester<
      [
        "tbs",
        "tbsLength",
        "userPkLimbs",
        "userRsaSignature",
        "pkBlind",
        "challenge"
      ],
      ["pkCommit", "nullifier", "appIdPacked"]
    >;
    let testRsaPrivKey: KeyObject;
    let testRsaPubLimbs: string[];

    function signAndLimb(rawMessage: Buffer): string[] {
      // Sha256Bytes(tbs, tbsLength) inside the circuit consumes a
      // SHA-256-padded buffer and emits the hash of the ORIGINAL (pre-padded)
      // message. So the signature must be over the raw message — node:crypto's
      // sign("sha256", raw, …) does exactly that: PKCS#1 v1.5 RSA over
      // SHA-256(raw).
      const sig = cryptoSign("sha256", rawMessage, {
        key: testRsaPrivKey,
        padding: cryptoConstants.RSA_PKCS1_PADDING,
      });
      return bigIntToChunkedBytes(bytesToBigInt(sig), N_BITS, K_LIMBS_USER);
    }

    function buildWitness(appIdBytes: Uint8Array, tail: Uint8Array) {
      assert.strictEqual(appIdBytes.length, 31, "appIdBytes must be 31 bytes");
      const message = Buffer.concat([appIdBytes, tail]);
      const [padded, paddedLen] = sha256Pad(
        new Uint8Array(message),
        MAX_MESSAGE_LENGTH
      );
      assert.ok(
        paddedLen <= 64,
        `padded length must fit the circuit's tbsLength <= 64 bound; got ${paddedLen}`
      );
      return {
        tbs: Array.from(padded).map(String),
        tbsLength: paddedLen.toString(),
        userPkLimbs: testRsaPubLimbs,
        userRsaSignature: signAndLimb(message),
        pkBlind: "1",
        challenge: "42",
      };
    }

    before(async function () {
      this.timeout(900_000);
      userSigCircuit = await circomkit.WitnessTester("userSigRS2048", {
        file: "userSig",
        template: "UserSigRSA256",
        params: [MAX_MESSAGE_LENGTH, N_BITS, K_LIMBS_USER],
      });
      const { publicKey, privateKey } = generateKeyPairSync("rsa", {
        modulusLength: USER_MODULUS_BITS,
        publicExponent: 65537,
      });
      testRsaPrivKey = privateKey;
      const jwk = publicKey.export({ format: "jwk" }) as { n: string };
      const modulus = bytesToBigInt(Buffer.from(jwk.n, "base64url"));
      testRsaPubLimbs = bigIntToChunkedBytes(modulus, N_BITS, K_LIMBS_USER);
    });

    it("witness A and witness B share appIdPacked but produce different nullifiers", async function () {
      this.timeout(900_000);
      const appId = Buffer.from("audit-v2-high-test-app-id-fixed", "utf-8");
      assert.strictEqual(appId.length, 31);

      // Witness A: raw message = appId (31 bytes), sha256Pad fills tbs[31..64]
      // with the canonical SHA-256 padding for a 31-byte input.
      const witnessA = buildWitness(appId, Buffer.alloc(0));

      // Witness B: raw message = appId ‖ 0x42 (32 bytes). The 0x42 lives at
      // tbs[31] — outside the appIdPacked window but inside the SHA-256
      // domain that determines the signature and therefore the nullifier.
      const witnessB = buildWitness(appId, Buffer.from([0x42]));

      for (let i = 0; i < 31; i++) {
        assert.strictEqual(
          witnessA.tbs[i],
          witnessB.tbs[i],
          `tbs[${i}] should match across witnesses`
        );
      }
      assert.notStrictEqual(
        witnessA.tbs[31],
        witnessB.tbs[31],
        "tbs[31] should differ to exercise the malleability axis"
      );

      const wA = await userSigCircuit.calculateWitness(witnessA);
      await userSigCircuit.expectConstraintPass(wA);
      const wB = await userSigCircuit.calculateWitness(witnessB);
      await userSigCircuit.expectConstraintPass(wB);

      // The witness vector layout for a circom main is
      //   witness[0] = 1, witness[1..numOutputs] = outputs in declaration order,
      // followed by public inputs and intermediate signals. We read outputs by
      // index directly because the .sym file for UserSigRSA256 exceeds
      // Node's V8 max-string length and would crash readWitnessSignals.
      // Output declaration order in userSig.circom: pkCommit, nullifier, appIdPacked.
      const PK_COMMIT = 1;
      const NULLIFIER = 2;
      const APP_ID_PACKED = 3;

      const appIdA = (wA as readonly bigint[])[APP_ID_PACKED];
      const appIdB = (wB as readonly bigint[])[APP_ID_PACKED];
      const nullA = (wA as readonly bigint[])[NULLIFIER];
      const nullB = (wB as readonly bigint[])[NULLIFIER];

      assert.strictEqual(
        appIdA,
        appIdB,
        `appIdPacked must match across witnesses sharing tbs[0..31]; got A=${appIdA} B=${appIdB}`
      );
      assert.notStrictEqual(
        nullA,
        nullB,
        `nullifier should differ — got identical ${nullA} for both witnesses (HIGH is mitigated?)`
      );

      // Sanity: pkCommit also matches (shared userPkLimbs + pkBlind), so the
      // protocol-level identity is genuinely the "same card".
      assert.strictEqual(
        (wA as readonly bigint[])[PK_COMMIT],
        (wB as readonly bigint[])[PK_COMMIT],
        "pkCommit must match across witnesses sharing (userPkLimbs, pkBlind)"
      );
    });
  });

  /**
   * Finding 3 (LOW, advisory) — `ExtractModulus` checks only
   * `in[modulusTagOffset] == 0x02` and `Multiplexer` in-range. The two
   * prover-supplied offsets `modulusOffset` and `modulusTagOffset` are not
   * tied together by a DER length-byte walk, so the prover can aim the tag
   * at any 0x02 byte in the TBS while pointing the modulus offset wherever
   * they like. The audit notes this is not exploitable in the current
   * composition (the surrounding RSA-verify forces `userPkLimbs` to be a
   * real key the prover holds the secret exponent for), but the soundness
   * gap is real at the template level. This block serves as a regression
   * guard against future refactors that would make the gap reachable.
   */
  describe("[LOW] ExtractModulus accepts decoupled (modulusOffset, modulusTagOffset)", function () {
    let modulusCircuit: WitnessTester<
      ["in", "modulusOffset", "modulusTagOffset"],
      ["out"]
    >;
    let input: Record<string, any>;

    before(async function () {
      this.timeout(900_000);
      input = loadInput("cert_chain_rs2048");
      modulusCircuit = await circomkit.WitnessTester(
        "ExtractModulusFixture",
        {
          file: "utils/utils",
          template: "ExtractModulus",
          params: [MAX_MESSAGE_LENGTH, N_BITS, K_LIMBS_USER, USER_MODULUS_BITS],
        }
      );
    });

    it("baseline: real (modulusOffset, modulusTagOffset) extracts the real modulus", async function () {
      this.timeout(900_000);
      await modulusCircuit.expectPass({
        in: input.issuerTbs,
        modulusOffset: input.tbsModulusOffset,
        modulusTagOffset: input.tbsModulusTagOffset,
      });
    });

    it("BYPASS: tag at the RSA exponent INTEGER + offset at the real modulus still passes", async function () {
      this.timeout(900_000);
      // The exponent INTEGER tag lives at tbs[510] = 0x02 (followed by len=3,
      // value=65537). Pointing modulusTagOffset there satisfies the tag check
      // while modulusOffset still indexes the real 256 modulus bytes —
      // proving the two offsets are not bound together at the template level.
      await modulusCircuit.expectPass({
        in: input.issuerTbs,
        modulusOffset: input.tbsModulusOffset,
        modulusTagOffset: 510n,
      });
    });

    it("BYPASS: real tag + arbitrary modulusOffset extracts non-modulus bytes", async function () {
      this.timeout(900_000);
      // Real tag passes (tbs[249] == 0x02) but modulusOffset = 0 makes the
      // template read tbs[0..256] as "the modulus". The template doesn't
      // notice the mismatch — only the surrounding RSA-verify would.
      await modulusCircuit.expectPass({
        in: input.issuerTbs,
        modulusOffset: 0n,
        modulusTagOffset: input.tbsModulusTagOffset,
      });
    });
  });
});
