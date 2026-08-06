import { createReadStream } from "node:fs";
import { join } from "node:path";
import { createInterface } from "node:readline";
import type { WitnessTester } from "circomkit";

/**
 * Witness indices of the given full symbol names (e.g. `main.deviceKeyX`,
 * `main.normalizedClaimValues[0]`), read from the `.sym` of the circuit that
 * `tester` actually compiled.
 *
 * Read it from the tester rather than `build/<circuit>/`: `Circomkit.WitnessTester`
 * compiles its own main under `circuits/test/` (no `public[...]` list) into a
 * temp dir at optimization level 1, while `scripts/compile.sh` builds
 * `circuits/main/` at O2 with the public inputs declared. The two layouts do not
 * match -- a private signal sits at a different index in each -- so an offset
 * taken from one is wrong in the other. (That mismatch is exactly how
 * MDOC_CLAIM_VALUES_WITNESS_START in ecdsa-spartan2 ended up pointing at 3321,
 * a tester-build index, when the production build puts it at 3036.)
 *
 * circomkit's own `readWitness()` can't be used here: it `readFile`s the whole
 * `.sym` into a string, and these circuits produce files well past Node's
 * ~512 MB max string length (mdoc's is ~1.1 GB). Streaming line-by-line and
 * stopping once every requested symbol is found reads only the `main.*` prefix.
 */
export async function witnessIndices(
  tester: WitnessTester<any, any>,
  symbols: string[],
): Promise<number[]> {
  // `circomTester` is circomkit-internal; it is the only handle on the temp
  // build dir the tester compiled into.
  const circomTester = (tester as any).circomTester;
  const symPath = join(circomTester.dir, `${circomTester.baseName}.sym`);

  const pending = new Map(symbols.map((s, i) => [s, i]));
  const indices = new Array<number>(symbols.length).fill(-1);

  const lines = createInterface({ input: createReadStream(symPath), crlfDelay: Infinity });
  try {
    for await (const line of lines) {
      // `labelIdx,witnessIdx,componentIdx,symbolName`; witnessIdx -1 = optimized away.
      const [, witnessIdx, , name] = line.split(",");
      const slot = pending.get(name);
      if (slot === undefined) continue;
      if (Number(witnessIdx) < 0) throw new Error(`${name} was optimized out`);
      indices[slot] = Number(witnessIdx);
      pending.delete(name);
      if (pending.size === 0) break;
    }
  } finally {
    lines.close();
  }

  if (pending.size > 0) {
    throw new Error(`not found in ${symPath}: ${[...pending.keys()].join(", ")}`);
  }
  return indices;
}
