import { strict as assert } from "assert";
import type { WitnessTester } from "circomkit";
import { circomkit } from "../common/index.ts";
import { buildMdocWitness, MDOC_PARAMS } from "../common/mdoc-fixture.ts";
import { createTestMdocCredential } from "../../src/mdoc-fixture.ts";
import { generateMdocCircuitParams, generateMdocInputs, parseMdocClaims } from "../../src/mdoc.ts";

describe("MDOC Circuit", () => {
  let circuit: WitnessTester<any, any>;

  before(async () => {
    circuit = await circomkit.WitnessTester("mdoc", {
      file: "mdoc",
      template: "MDOC",
      params: [...MDOC_PARAMS],
      recompile: true,
    });
    console.log("#constraints:", await circuit.getConstraintCount());
  });

  it("verifies a credential with all 4 claim types", async () => {
    const { inputs } = await buildMdocWitness({
      birth_date: { type: "date" },
      resident_state: { type: "string" },
      family_name: { type: "reveal_digest" },
      given_name: { type: "reveal_digest" },
    });
    const witness = await circuit.calculateWitness(inputs);
    await circuit.expectConstraintPass(witness);
  });

  it("verifies a credential with a subset of claims", async () => {
    const { inputs } = await buildMdocWitness({
      birth_date: { type: "date" },
      resident_state: { type: "string" },
    });
    const witness = await circuit.calculateWitness(inputs);
    await circuit.expectConstraintPass(witness);
  });

  it("rejects a tampered signature", async () => {
    const cred = await createTestMdocCredential();
    const params = generateMdocCircuitParams([...MDOC_PARAMS]);
    const { claims, deviceKeyPos } = parseMdocClaims(cred.tbsData, cred.items, cred.deviceKeyX, {
      birth_date: { type: "date" },
    });

    const tampered = new Uint8Array(cred.signature);
    tampered[0] ^= 0xff;

    assert.throws(
      () => generateMdocInputs(params, cred.tbsData, tampered, cred.issuerPubRaw, claims, deviceKeyPos),
      /Internal ECDSA signature verification failed/,
    );
  });

  describe("consistency checks", () => {
    it("rejects a non-boolean claimFlag", async () => {
      const { inputs } = await buildMdocWitness({ birth_date: { type: "date" } });
      const tampered = { ...inputs, claimFlags: [...inputs.claimFlags] };
      tampered.claimFlags[0] = 2n;
      await circuit.expectFail(tampered);
    });

    it("rejects a valueType >= 4", async () => {
      const { inputs } = await buildMdocWitness({ birth_date: { type: "date" } });
      const tampered = { ...inputs, valueTypes: [...inputs.valueTypes] };
      tampered.valueTypes[0] = 4n;
      await circuit.expectFail(tampered);
    });

    it("rejects valueEnd < valueStart (dataLen underflow)", async () => {
      const { inputs } = await buildMdocWitness({ birth_date: { type: "date" } });
      const tampered = {
        ...inputs,
        valueEnds: [...inputs.valueEnds],
        valueStarts: [...inputs.valueStarts],
      };
      tampered.valueEnds[0] = tampered.valueStarts[0] - 1n;
      await circuit.expectFail(tampered);
    });

    it("rejects a dataLen larger than maxValueLen", async () => {
      const { inputs } = await buildMdocWitness({ birth_date: { type: "date" } });
      const params = generateMdocCircuitParams([...MDOC_PARAMS]);
      const tampered = { ...inputs, valueEnds: [...inputs.valueEnds] };
      tampered.valueEnds[0] = tampered.valueStarts[0] + BigInt(params.maxValueLen + 1);
      await circuit.expectFail(tampered);
    });
  });
});
