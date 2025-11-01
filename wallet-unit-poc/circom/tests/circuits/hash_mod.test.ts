import { WitnessTester } from "circomkit";
import { circomkit } from "../common";
import assert from "assert";

describe("HashModScalarField", () => {
  let circuit!: WitnessTester<["hash"], ["out"]>;

  const qHex = "0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551";
  const q = BigInt(qHex);
  const toBits256 = (hex: string): number[] => BigInt(hex).toString(2).padStart(256, "0").split("").map(Number);

  before(async () => {
    circuit = await circomkit.WitnessTester("HashModScalarField", {
      file: "utils/utils",
      template: "HashModScalarField",
      params: [],
      recompile: true,
    });

    console.log("#constraints:", await circuit.getConstraintCount());
  });

  it("reduces any 256‑bit hash into the secp256r1 scalar field", async () => {
    const cases = {
      qMinus1: "0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632550", // q‑1
      qExact: "0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", // q
      qPlus1: "0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632552", // q+1
    };

    const w1 = await circuit.calculateWitness({ hash: toBits256(cases.qMinus1) });
    const signals = await circuit.readWitnessSignals(w1, ["out"]);
    assert(signals.out === q - 1n, `Expected out to be q-1`);

    const w2 = await circuit.calculateWitness({ hash: toBits256(cases.qExact) });
    const signals2 = await circuit.readWitnessSignals(w2, ["out"]);
    assert(signals2.out === 0n, `Expected out to be 0`);

    const w3 = await circuit.calculateWitness({ hash: toBits256(cases.qPlus1) });
    const signals3 = await circuit.readWitnessSignals(w3, ["out"]);
    assert(signals3.out === 1n, `Expected out to be 1`);
  });
});
