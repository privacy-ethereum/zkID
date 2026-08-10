import assert from "assert";
import type { WitnessTester } from "circomkit";
import { circomkit } from "../common/index.ts";

/**
 * Regression tests for the JSON-escape desync in the claim extractors.
 *
 * Both extractors locate their field by counting raw 0x22 bytes, so a
 * disclosure that keeps the total at 6 while moving where those quotes fall
 * makes them read the wrong bytes. The audit PoC does that by adding two
 * escaped quotes inside the salt and dropping the two around the value
 * (leaving a bare JSON number), which keeps the count balanced at 6.
 *
 * The fix forbids backslash bytes outright, so no escape can reach the
 * counter in the first place.
 */

const DECODED_LEN = 64;

/** Pack an ASCII disclosure into the fixed-width byte array the templates take. */
function claimBytes(s: string): number[] {
  const bytes = Array.from(s, (c) => c.charCodeAt(0));
  assert.ok(bytes.length <= DECODED_LEN, `payload too long: ${bytes.length}`);
  return [...bytes, ...Array(DECODED_LEN - bytes.length).fill(0)];
}

function readString(signal: unknown, len: unknown): string {
  const bytes = signal as (number | bigint)[];
  return bytes
    .slice(0, Number(len))
    .map((b) => String.fromCharCode(Number(b)))
    .join("");
}

// The audit PoC. Honest JSON reads salt=`x""age`, name=`18`, value=`999`;
// the quote-counting extractors instead read name=`age` and value=`18`.
const POC = '["x\\"\\"age","18",999]';
const LEGIT = '["realsaltvalue","age","25"]';

describe("Claim extractors reject JSON escapes", () => {
  let nameCircuit: WitnessTester<["claim", "isActive"], ["name", "nameLength"]>;
  let valueCircuit: WitnessTester<["claim", "isActive"], ["value", "valueLength"]>;

  before(async () => {
    nameCircuit = await circomkit.WitnessTester("ClaimNameExtractor", {
      file: "components/claim-name-extractor",
      template: "ClaimNameExtractor",
      params: [DECODED_LEN],
      recompile: true,
    });
    valueCircuit = await circomkit.WitnessTester("ClaimValueExtractor", {
      file: "components/claim-value-extractor",
      template: "ClaimValueExtractor",
      params: [DECODED_LEN],
      recompile: true,
    });
  });

  it("sanity: the PoC keeps the raw quote count at 6, so the count check alone misses it", () => {
    assert.strictEqual((POC.match(/"/g) ?? []).length, 6);
    assert.strictEqual((LEGIT.match(/"/g) ?? []).length, 6);
  });

  it("rejects the escaped-quote PoC in the name extractor", async () => {
    await nameCircuit.expectFail({ claim: claimBytes(POC), isActive: 1 });
  });

  it("rejects the escaped-quote PoC in the value extractor", async () => {
    await valueCircuit.expectFail({ claim: claimBytes(POC), isActive: 1 });
  });

  it("rejects any backslash, even one that is not part of a quote escape", async () => {
    // `\\` (an escaped backslash) leaves the quote count at 6, so only the
    // backslash ban catches it.
    const payload = '["a\\\\b","age","25"]';
    assert.strictEqual((payload.match(/"/g) ?? []).length, 6);
    await nameCircuit.expectFail({ claim: claimBytes(payload), isActive: 1 });
    await valueCircuit.expectFail({ claim: claimBytes(payload), isActive: 1 });
  });

  it("still extracts the correct name and value from an escape-free claim", async () => {
    const input = { claim: claimBytes(LEGIT), isActive: 1 };

    const nameWitness = await nameCircuit.calculateWitness(input);
    await nameCircuit.expectConstraintPass(nameWitness);
    const nameOut = await nameCircuit.readWitnessSignals(nameWitness, ["name", "nameLength"]);
    assert.strictEqual(readString(nameOut.name, nameOut.nameLength), "age");

    const valueWitness = await valueCircuit.calculateWitness(input);
    await valueCircuit.expectConstraintPass(valueWitness);
    const valueOut = await valueCircuit.readWitnessSignals(valueWitness, ["value", "valueLength"]);
    assert.strictEqual(readString(valueOut.value, valueOut.valueLength), "25");
  });

  it("accepts raw multi-byte UTF-8, which the backslash ban must not break", async () => {
    // UTF-8 continuation bytes are 0x80-0xBF, never 0x22 or 0x5C. Issuers that
    // emit raw UTF-8 (JS JSON.stringify) stay provable; only \uXXXX-escaping
    // serializers (Python json.dumps default) are now rejected.
    const utf8 = Array.from(new TextEncoder().encode('["salt","name","José"]'));
    const padded = [...utf8, ...Array(DECODED_LEN - utf8.length).fill(0)];

    const witness = await valueCircuit.calculateWitness({ claim: padded, isActive: 1 });
    await valueCircuit.expectConstraintPass(witness);
    const out = await valueCircuit.readWitnessSignals(witness, ["value", "valueLength"]);
    const bytes = (out.value as (number | bigint)[])
      .slice(0, Number(out.valueLength))
      .map((b) => Number(b));
    assert.strictEqual(new TextDecoder().decode(Uint8Array.from(bytes)), "José");
  });

  it("leaves inactive slots unconstrained", async () => {
    // isActive=0 must not enforce the quote count or the backslash ban,
    // otherwise unused claim slots would make the whole circuit unsatisfiable.
    const input = { claim: claimBytes(POC), isActive: 0 };
    await nameCircuit.expectConstraintPass(await nameCircuit.calculateWitness(input));
    await valueCircuit.expectConstraintPass(await valueCircuit.calculateWitness(input));
  });
});
