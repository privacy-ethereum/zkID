import { strict as assert } from "assert";
import type { WitnessTester } from "circomkit";
import { circomkit } from "../common/index.ts";

const VALUE_LEN = 96;
const FORMAT_UINT = 1n;

function uintInput(decimal: string) {
  const value = new Array<bigint>(VALUE_LEN).fill(0n);
  for (let i = 0; i < decimal.length; i++) value[i] = BigInt(decimal.charCodeAt(i));
  return { value, valueLength: BigInt(decimal.length), format: FORMAT_UINT };
}

// The circuits compile over secq256r1 (circomkit.json), whose modulus is the
// P-256 base field. A decimal at or past 78 digits wraps the uint accumulator.
const q = 115792089210356248762697446949407573530086143415290314195533631308867097853951n;

describe("ClaimValueNormalizer uint range", () => {
  let circuit: WitnessTester<["value", "valueLength", "format"], ["normalizedValue"]>;

  before(async () => {
    circuit = await circomkit.WitnessTester("claim_value_normalizer", {
      file: "components/claim-value-normalizer",
      template: "ClaimValueNormalizer",
      params: [VALUE_LEN],
      recompile: true,
    });
  });

  it("normalizes an ordinary uint", async () => {
    await circuit.expectPass(uintInput("18"), { normalizedValue: 18n });
  });

  it("normalizes the largest accepted uint", async () => {
    const d = "9".repeat(19);
    await circuit.expectPass(uintInput(d), { normalizedValue: BigInt(d) });
  });

  it("rejects a decimal that overflows the predicate domain", async () => {
    // 10^19 > 2^64, so this can no longer reach LessEqThan(64).
    await circuit.expectFail(uintInput("1".repeat(20)));
  });

  it("rejects a field-wrapping decimal that would alias onto a small residue", async () => {
    // A 78-digit value congruent to 17 mod q. Verified: before the length
    // bound this normalized to exactly 17, satisfying a `claim <= 18`
    // predicate that is false for the actual signed decimal.
    const aliased = q + 17n;
    assert.ok(aliased % q === 17n);
    assert.ok(aliased.toString().length <= VALUE_LEN);
    await circuit.expectFail(uintInput(aliased.toString()));
  });

  it("rejects a non-digit byte under uint format", async () => {
    await circuit.expectFail(uintInput("1a3"));
  });

  it("rejects a byte just outside the digit range", async () => {
    await circuit.expectFail(uintInput("1:3")); // ':' is '9' + 1
  });
});
