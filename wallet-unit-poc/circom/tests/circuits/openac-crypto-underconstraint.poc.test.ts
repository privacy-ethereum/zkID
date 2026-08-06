import { strict as assert } from "assert";
import type { WitnessTester } from "circomkit";
import { circomkit } from "../common/index.ts";

const P256_Q = BigInt("0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551");

type SignalMap = Map<string, number>;
type SymbolInfo = { varIdx: number };

function bits256(value: bigint): number[] {
  return value.toString(2).padStart(256, "0").split("").map(Number);
}

async function readSignalMap(circuit: WitnessTester<any, any>): Promise<SignalMap> {
  const tester = circuit as unknown as {
    loadSymbols: () => Promise<void>;
    symbols?: Record<string, SymbolInfo>;
  };
  await tester.loadSymbols();

  const map = new Map<string, number>();
  for (const [signalName, info] of Object.entries(tester.symbols ?? {})) {
    if (Number.isInteger(info.varIdx) && info.varIdx >= 0) {
      map.set(signalName, info.varIdx);
    }
  }
  return map;
}

function spliceBySignalName(
  target: bigint[],
  source: bigint[],
  signalMap: SignalMap,
  shouldCopy: (name: string) => boolean,
): bigint[] {
  const out = target.slice();
  for (const [name, idx] of signalMap) {
    if (idx <= 0) continue;
    if (idx >= out.length || idx >= source.length) continue;
    if (shouldCopy(name)) out[idx] = source[idx]!;
  }
  return out;
}

describe("OpenAC crypto underconstraint PoC", () => {
  it("rejects K_add witness where internal limbs come from a different scalar", async () => {
    const circuit: WitnessTester<["s"], ["out"]> = await circomkit.WitnessTester("KAddBindingPoC", {
      file: "ecdsa/p256/mul",
      template: "K_add",
      params: [],
      recompile: true,
    });

    const oneWitness = await circuit.calculateWitness({ s: 1n });
    const twoWitness = await circuit.calculateWitness({ s: 2n });
    await circuit.expectConstraintPass(oneWitness);
    await circuit.expectConstraintPass(twoWitness);

    const signalMap = await readSignalMap(circuit);
    const tampered = spliceBySignalName(oneWitness, twoWitness, signalMap, (name) => {
      if (name === "main.s") return false;
      return (
        name === "main.slo" ||
        name === "main.shi" ||
        name.startsWith("main.inBits.") ||
        name.startsWith("main.alpha.") ||
        name.startsWith("main.beta.") ||
        name.startsWith("main.gamma.") ||
        name.startsWith("main.betaANDgamma.") ||
        name.startsWith("main.isQuotientOne.") ||
        name.startsWith("main.theta.") ||
        name.startsWith("main.borrow.") ||
        name === "main.carry" ||
        name === "main.ahi" ||
        name === "main.alo" ||
        name === "main.klo" ||
        name === "main.khi" ||
        name.startsWith("main.kloBits.") ||
        name.startsWith("main.khiBits.") ||
        name.startsWith("main.out[")
      );
    });

    // The scalar input is 1, but the decomposed limbs and output bits were
    // copied from scalar 2. The current circuit accepts because slo/shi are not
    // bound back to s.
    await circuit.expectConstraintFail(tampered);
  });

  it("rejects HashModScalarField witness where internal limbs come from a different hash", async () => {
    const circuit: WitnessTester<["hash"], ["out"]> = await circomkit.WitnessTester("HashModBindingPoC", {
      file: "utils/utils",
      template: "HashModScalarField",
      params: [],
      recompile: true,
    });

    const qMinusOneWitness = await circuit.calculateWitness({ hash: bits256(P256_Q - 1n) });
    const oneWitness = await circuit.calculateWitness({ hash: bits256(1n) });
    await circuit.expectConstraintPass(qMinusOneWitness);
    await circuit.expectConstraintPass(oneWitness);

    const qMinusOneSignals = await circuit.readWitnessSignals(qMinusOneWitness, ["out"]);
    const oneSignals = await circuit.readWitnessSignals(oneWitness, ["out"]);
    assert.equal(qMinusOneSignals.out, P256_Q - 1n);
    assert.equal(oneSignals.out, 1n);

    const signalMap = await readSignalMap(circuit);
    const tampered = spliceBySignalName(qMinusOneWitness, oneWitness, signalMap, (name) => {
      if (name.startsWith("main.hash[")) return false;
      if (name.startsWith("main.hashNum.")) return false;
      return (
        name === "main.hashLo" ||
        name === "main.hashHi" ||
        name.startsWith("main.verifyLo.") ||
        name.startsWith("main.verifyHi.") ||
        name.startsWith("main.alpha.") ||
        name.startsWith("main.beta.") ||
        name.startsWith("main.gamma.") ||
        name.startsWith("main.betaANDgamma.") ||
        name.startsWith("main.isHashGteQ.") ||
        name === "main.resultLo" ||
        name === "main.resultHi" ||
        name === "main.out"
      );
    });

    // The hash input bits encode q-1, but the reduction limbs and output were
    // copied from hash=1. The current circuit accepts because hashLo/hashHi are
    // not bound back to hashNum.out.
    await circuit.expectConstraintFail(tampered);
  });
});
