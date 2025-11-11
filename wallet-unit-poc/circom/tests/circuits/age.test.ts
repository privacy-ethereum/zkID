import { WitnessTester } from "circomkit";
import { circomkit } from "../common";
import { assert } from "console";

describe("AgeVerifier", () => {
  let circuit: WitnessTester<["claim", "currentYear", "currentMonth", "currentDay"], ["ageAbove18"]>;

  const maxClaimLength = 128;
  const byteLength = Math.floor((maxClaimLength * 3) / 4);

  before(async () => {
    circuit = await circomkit.WitnessTester("AgeVerifier", {
      file: "components/age-verifier",
      template: "AgeVerifier",
      params: [byteLength],
      recompile: true,
    });
    console.log("AgeVerifier constraints:", await circuit.getConstraintCount());
  });

  it("should decode raw claims with padding correctly and pass constraints", async () => {
    const input = "WyJGc2w4ZWpObEFNT2Vqc1lTdjc2Z1NnIiwicm9jX2JpcnRoZGF5IiwiMTA0MDYwNSJd";

    let decodedClaims = Array.from(Buffer.from(atob(input)));
    while (decodedClaims.length < byteLength) {
      decodedClaims.push(0);
    }

    const now = new Date();
    const currentYear = BigInt(now.getUTCFullYear());
    const currentMonth = BigInt(now.getUTCMonth() + 1);
    const currentDay = BigInt(now.getUTCDate());

    const witness = await circuit.calculateWitness({
      claim: decodedClaims,
      currentYear,
      currentMonth,
      currentDay,
    });

    await circuit.expectConstraintPass(witness);
  });
});

describe("AgeExtractor", () => {
  let circuit: WitnessTester<["YYMMDD", "currentYear", "currentMonth", "currentDay"], ["age"]>;

  before(async () => {
    circuit = await circomkit.WitnessTester("AgeExtractor", {
      file: "components/age-verifier",
      template: "AgeExtractor",
      params: [],
      recompile: true,
    });
    console.log("AgeExtractor constraints:", await circuit.getConstraintCount());
  });

  function toDigits(rocYear: number, month: number, day: number): number[] {
    const roc = rocYear.toString().padStart(3, "0");
    const m = month.toString().padStart(2, "0");
    const d = day.toString().padStart(2, "0");
    return [...roc, ...m, ...d].map((c) => parseInt(c, 10));
  }

  //  March 15, 2025
  const currentYear = BigInt(2025);
  const currentMonth = BigInt(3);
  const currentDay = BigInt(15);

  it("calculates age when birthday has passed this year (March)", async () => {
    //  March 14, 2000 => ROC year = 2000 - 1911 = 89
    const YYMMDD = toDigits(89, 3, 14);
    const witness = await circuit.calculateWitness({
      YYMMDD,
      currentYear,
      currentMonth,
      currentDay,
    });
    const signals = await circuit.readWitnessSignals(witness, ["age"]);
    assert(signals.age === 25n, `Expected age 25, got ${signals.age}`);
  });

  it("calculates age when birthday is today (March)", async () => {
    //  March 15, 2000 => ROC year = 89
    const YYMMDD = toDigits(89, 3, 15);
    const witness = await circuit.calculateWitness({
      YYMMDD,
      currentYear,
      currentMonth,
      currentDay,
    });
    const signals = await circuit.readWitnessSignals(witness, ["age"]);
    assert(signals.age === 25n, `Expected age 25, got ${signals.age}`);
  });

  it("calculates age when birthday has not passed yet (March)", async () => {
    //  March 16, 2000 => ROC year = 89
    const YYMMDD = toDigits(89, 3, 16);
    const witness = await circuit.calculateWitness({
      YYMMDD,
      currentYear,
      currentMonth,
      currentDay,
    });
    const signals = await circuit.readWitnessSignals(witness, ["age"]);
    assert(signals.age === 24n, `Expected age 24, got ${signals.age}`);
  });
});
