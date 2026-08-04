import { strict as assert } from "assert";
import { createHash } from "crypto";
import { sha256Pad } from "@zk-email/helpers";
import type { WitnessTester } from "circomkit";
import { circomkit } from "../common/index.ts";
import { MDOC_PARAMS } from "../common/mdoc-fixture.ts";
import { createTestMdocCredential } from "../../src/mdoc-fixture.ts";
import { generateMdocCircuitParams, generateMdocInputs, parseMdocClaims } from "../../src/mdoc.ts";
import { uint8ArrayToBigIntArray } from "../../src/utils.ts";

// Mirror of the circuit's digest→field step: Sha256Bytes emits 256 MSB-first
// bits, and Bits2Num(248) reads bit i with weight 2^i.
function truncatedDigest248(msg: Uint8Array): bigint {
  const digest = createHash("sha256").update(msg).digest();
  let out = 0n;
  for (let i = 0; i < 248; i++) {
    const bit = (digest[i >> 3] >> (7 - (i & 7))) & 1;
    if (bit) out += 1n << BigInt(i);
  }
  return out;
}

describe("mdoc reveal_digest padding binding", () => {
  let mdocCircuit: WitnessTester<any, any>;

  before(async () => {
    mdocCircuit = await circomkit.WitnessTester("MDOC", {
      file: "mdoc",
      template: "MDOC",
      params: [...MDOC_PARAMS],
      recompile: true,
    });
  });

  // Regression: a collapsed value slice used to zero every binding constraint's
  // mask, letting the holder hash arbitrary bytes.
  it("rejects dataLen=0 with an attacker-chosen digest preimage", async () => {
    const cred = await createTestMdocCredential();
    const params = generateMdocCircuitParams([...MDOC_PARAMS]);
    const { claims, deviceKeyPrefixData } = parseMdocClaims(cred.tbsData, cred.items, cred.deviceKeyX, {
      family_name: { type: "reveal_digest" },
    });
    const honest = generateMdocInputs(
      params,
      cred.tbsData,
      cred.signature,
      cred.issuerPubRaw,
      claims,
      deviceKeyPrefixData,
    );

    const attack = structuredClone(honest);
    // Collapse the value slice so uintLenGt[i] == 0 for every i.
    attack.valueEnds[0] = attack.valueStarts[0];
    const attackerBytes = Uint8Array.from(Buffer.from("totally-unrelated-attacker-bytes", "utf8"));
    const [padded, paddedLen] = sha256Pad(attackerBytes, params.maxValueLen);
    attack.digestInputsPadded[0] = uint8ArrayToBigIntArray(padded);
    attack.digestInputsPaddedLen[0] = BigInt(paddedLen);

    // The canonical padding constraints pin 0x80 and the big-endian length
    // field from dataLen, so a collapsed slice no longer frees the SHA input.
    await mdocCircuit.expectFail(attack);

    // Control: the honest witness still proves, so the rejection is the padding
    // binding and not a broken fixture.
    const honestWitness = await mdocCircuit.calculateWitness(honest);
    await mdocCircuit.expectConstraintPass(honestWitness);
    assert.ok(
      !honestWitness.some((w) => w === truncatedDigest248(attackerBytes)),
      "honest witness must not contain the attacker-chosen digest",
    );
  });

  // Regression: dataLen was prover-chosen, so a shorter one produced valid
  // padding for a prefix of the signed value. It is now bound to the CBOR header.
  it("rejects a truncated dataLen that would prove a value prefix", async () => {
    const cred = await createTestMdocCredential();
    const params = generateMdocCircuitParams([...MDOC_PARAMS]);
    const { claims, deviceKeyPrefixData } = parseMdocClaims(cred.tbsData, cred.items, cred.deviceKeyX, {
      family_name: { type: "reveal_digest" },
    });
    const honest = generateMdocInputs(
      params,
      cred.tbsData,
      cred.signature,
      cred.issuerPubRaw,
      claims,
      deviceKeyPrefixData,
    );

    const claim = claims[0];
    const full = claim.preimage.slice(claim.valueStart, claim.valueEnd);
    assert.ok(full.length >= 3, "fixture value must be long enough to truncate");
    const prefix = full.slice(0, full.length - 1);

    const attack = structuredClone(honest);
    attack.valueEnds[0] = attack.valueStarts[0] + BigInt(prefix.length);
    const [padded, paddedLen] = sha256Pad(prefix, params.maxValueLen);
    attack.digestInputsPadded[0] = uint8ArrayToBigIntArray(padded);
    attack.digestInputsPaddedLen[0] = BigInt(paddedLen);

    await mdocCircuit.expectFail(attack);

    // Control: the honest witness still proves and commits to the full value.
    const witness = await mdocCircuit.calculateWitness(honest);
    await mdocCircuit.expectConstraintPass(witness);
    assert.ok(
      witness.some((w) => w === truncatedDigest248(full)),
      "honest witness should commit to the full signed value",
    );
    assert.ok(
      !witness.some((w) => w === truncatedDigest248(prefix)),
      "honest witness must not contain the prefix digest",
    );
  });
});
