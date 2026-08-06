import { strict as assert } from "assert";
import type { WitnessTester } from "circomkit";
import { circomkit } from "../common/index.ts";
import { buildMdocWitness, MDOC_PARAMS } from "../common/mdoc-fixture.ts";

// Audit item 6: MdocDeviceKeyExtractor used to take the "prefix" as a prover
// input and derive yStart from an unconstrained yPrefixLen, so a prover could
// aim each coordinate at any 32-byte window of the signed message -- including
// the SHA-padding zero run, which yields deviceKeyX = deviceKeyY = 0.
//
// The coordinates are now pinned by the COSE constants 0x21 0x58 0x20 (label -2)
// and 0x22 0x58 0x20 (label -3) at fixed offsets, so deviceKeyPos is the only
// prover freedom left and every shift of it breaks a marker.
describe("MDOC device key anchoring", () => {
  let circuit: WitnessTester<any, any>;

  before(async () => {
    circuit = await circomkit.WitnessTester("mdoc", {
      file: "mdoc",
      template: "MDOC",
      params: [...MDOC_PARAMS],
      recompile: true,
    });
  });

  it("accepts the honest position", async () => {
    const { inputs } = await buildMdocWitness({ birth_date: { type: "date" } });
    const witness = await circuit.calculateWitness(inputs);
    await circuit.expectConstraintPass(witness);
  });

  it("the honest position really is the COSE -2 marker", async () => {
    const { inputs } = await buildMdocWitness({ birth_date: { type: "date" } });
    const pos = Number(inputs.deviceKeyPos);
    const msg = inputs.message.map(Number);
    assert.deepEqual(msg.slice(pos, pos + 3), [0x21, 0x58, 0x20], "x marker");
    assert.deepEqual(msg.slice(pos + 35, pos + 38), [0x22, 0x58, 0x20], "y marker");
  });

  // Shifting the window is the whole attack: any offset that still lands inside
  // the message now fails a marker equality.
  for (const delta of [-3, -1, 1, 3, 32, 35]) {
    it(`rejects a device key window shifted by ${delta}`, async () => {
      const { inputs } = await buildMdocWitness({ birth_date: { type: "date" } });
      await circuit.expectFail({ ...inputs, deviceKeyPos: inputs.deviceKeyPos + BigInt(delta) });
    });
  }

  it("rejects aiming at the SHA-padding zero run (deviceKey = 0)", async () => {
    const { inputs } = await buildMdocWitness({ birth_date: { type: "date" } });
    const msg = inputs.message.map(Number);

    // First index of a 70-byte all-zero run — the degenerate-key target.
    let zeroStart = -1;
    for (let i = 0; i + 70 <= msg.length; i++) {
      if (msg.slice(i, i + 70).every((b) => b === 0)) {
        zeroStart = i;
        break;
      }
    }
    assert.ok(zeroStart >= 0, "fixture should contain a zero run to aim at");

    await circuit.expectFail({ ...inputs, deviceKeyPos: BigInt(zeroStart) });
  });

  it("rejects a window running past messageLength", async () => {
    const { inputs } = await buildMdocWitness({ birth_date: { type: "date" } });
    await circuit.expectFail({ ...inputs, deviceKeyPos: inputs.messageLength - 69n });
  });
});
