import { strict as assert } from "assert";
import type { WitnessTester } from "circomkit";
import { circomkit } from "../common/index.ts";
import { buildMdocWitness, MDOC_PARAMS } from "../common/mdoc-fixture.ts";

const BASE_CLAIMS = {
  family_name: "Smith",
  given_name: "Alice",
  birth_date: "1990-07-15",
};

describe("MDOC integer claim range", () => {
  let circuit: WitnessTester<any, any>;

  before(async () => {
    circuit = await circomkit.WitnessTester("mdoc", {
      file: "mdoc",
      template: "MDOC",
      params: [...MDOC_PARAMS],
      recompile: true,
    });
  });

  it("normalizes an integer claim to its decimal value", async () => {
    // Before the padding fix this normalized to 12345 * 10^(64 - 5), so the
    // integer branch could never match an unscaled policy literal.
    const { inputs } = await buildMdocWitness(
      { document_number: { type: "integer" } },
      { ...BASE_CLAIMS, document_number: "12345" },
    );
    const witness = await circuit.calculateWitness(inputs);
    await circuit.expectConstraintPass(witness);
    // Output order: validUntilDate, normalizedClaimValues, deviceKeyX, deviceKeyY.
    assert.equal(witness.slice(2, 2 + MDOC_PARAMS[2])[0], 12345n);
  });

  it("rejects an integer claim too long to compare soundly", async () => {
    const { inputs } = await buildMdocWitness(
      { document_number: { type: "integer" } },
      { ...BASE_CLAIMS, document_number: "1".repeat(20) },
    );
    await circuit.expectFail(inputs);
  });
});
