import { strict as assert } from "assert";
import type { WitnessTester } from "circomkit";
import { circomkit } from "../common/index.ts";
import { buildMdocWitness, MDOC_PARAMS } from "../common/mdoc-fixture.ts";

// Audit item 4 (finding 10 + NB-09). MdocValueExtractor read the CBOR length
// header from preimage[valueStart-1] -- a byte the prover's own valueStart
// selected, which then *defined* dataLen. Circular, so the value window could be
// slid onto anything that happened to parse as a text header.
//
// The header is now read at a fixed distance from elementValueLabelPos (pinned
// to the 13-byte "elementValue" constant), and the header form determines
// valueStart rather than the reverse.
describe("MDOC value header anchoring", () => {
  let circuit: WitnessTester<any, any>;

  const claims = { birth_date: { type: "date" as const }, resident_state: { type: "string" as const } };

  before(async () => {
    circuit = await circomkit.WitnessTester("mdoc", {
      file: "mdoc",
      template: "MDOC",
      params: [...MDOC_PARAMS],
      recompile: true,
    });
  });

  it("accepts the honest windows for both header forms", async () => {
    const { inputs } = await buildMdocWitness(claims);
    const witness = await circuit.calculateWitness(inputs);
    await circuit.expectConstraintPass(witness);
  });

  it("the fixture really exercises both tag(1004) and bare text", async () => {
    const { inputs } = await buildMdocWitness(claims);
    const off = (i: number) => Number(inputs.valueStarts[i]) - Number(inputs.elementValueLabelPositions[i]);
    // date -> d9 03 ec + text(10), value at label+17; string -> text(2), at label+14
    assert.equal(off(0), 17, "date should use the tag(1004) form");
    assert.equal(off(1), 14, "string should use the bare short-text form");
  });

  // THE ATTACK: offset 13 puts valueStart-1 on the final 'e' of the circuit's own
  // "elementValue" constant. 'e' = 0x65 = CBOR text(5), so the old check passed
  // with dataLen = 5 on every claim of every credential, and the extractor read
  // the value's header bytes as if they were its content.
  it("rejects the label-'e' alias (offset 13, dataLen 5)", async () => {
    const { inputs } = await buildMdocWitness(claims);
    const labelPos = inputs.elementValueLabelPositions[0];
    await circuit.expectFail({
      ...inputs,
      valueStarts: [labelPos + 13n, ...inputs.valueStarts.slice(1)],
      valueEnds: [labelPos + 18n, ...inputs.valueEnds.slice(1)],
    });
  });

  // Offsets 15-18 used to land on real value bytes, where any 0x60..0x77 byte
  // (ASCII 'a'..'w') served as a forged header for a suffix of the value.
  for (const off of [15, 16, 18]) {
    it(`rejects a value window at offset ${off}`, async () => {
      const { inputs } = await buildMdocWitness(claims);
      const labelPos = inputs.elementValueLabelPositions[0];
      const start = labelPos + BigInt(off);
      await circuit.expectFail({
        ...inputs,
        valueStarts: [start, ...inputs.valueStarts.slice(1)],
        valueEnds: [start + 4n, ...inputs.valueEnds.slice(1)],
      });
    });
  }

  // dataLen is now the header's length field, not a free witness value.
  it("rejects a truncated value window at the honest start", async () => {
    const { inputs } = await buildMdocWitness(claims);
    await circuit.expectFail({
      ...inputs,
      valueEnds: [inputs.valueEnds[0] - 1n, ...inputs.valueEnds.slice(1)],
    });
  });

  it("rejects an extended value window at the honest start", async () => {
    const { inputs } = await buildMdocWitness(claims);
    await circuit.expectFail({
      ...inputs,
      valueEnds: [inputs.valueEnds[0] + 1n, ...inputs.valueEnds.slice(1)],
    });
  });

  // The label anchors the header, so moving the label moves the whole derivation
  // rather than opening a gap between them.
  it("rejects a label position that is not the elementValue label", async () => {
    const { inputs } = await buildMdocWitness(claims);
    await circuit.expectFail({
      ...inputs,
      elementValueLabelPositions: [
        inputs.elementValueLabelPositions[0] + 1n,
        ...inputs.elementValueLabelPositions.slice(1),
      ],
    });
  });
});
