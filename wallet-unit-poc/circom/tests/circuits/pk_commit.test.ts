import { WitnessTester } from "circomkit";
import { circomkit } from "../common";
import assert from "assert";

/**
 * Tests for ChunkedPoseidonP256 — the sponge-style hash used to produce
 * `pkCommit` in both CertChainRSA256 (Circuit A) and UserSigRSA256
 * (Circuit B). These tests exercise the primitive directly; end-to-end
 * linking between Circuit A and Circuit B is covered in Phase 2b once the
 * Rust prover supports the split circuits and RSA fixtures are available.
 */
describe("ChunkedPoseidonP256", function () {
  describe("nInputs = 2 (smoke)", function () {
    let circuit: WitnessTester<["inputs"], ["out"]>;

    before(async function () {
      this.timeout(60000);
      circuit = await circomkit.WitnessTester("ChunkedPoseidonP256_2", {
        file: "components/pkCommit",
        template: "ChunkedPoseidonP256",
        params: [2],
        recompile: true,
      });
      console.log("  #constraints (N=2):", await circuit.getConstraintCount());
    });

    it("is deterministic", async () => {
      const inputs = { inputs: [1n, 2n] };
      const w1 = await circuit.calculateWitness(inputs);
      const w2 = await circuit.calculateWitness(inputs);
      const out1 = (await circuit.readWitnessSignals(w1, ["out"])).out;
      const out2 = (await circuit.readWitnessSignals(w2, ["out"])).out;
      assert.strictEqual(out1, out2);
    });

    it("differs when inputs change", async () => {
      const w1 = await circuit.calculateWitness({ inputs: [1n, 2n] });
      const w2 = await circuit.calculateWitness({ inputs: [1n, 3n] });
      const out1 = (await circuit.readWitnessSignals(w1, ["out"])).out;
      const out2 = (await circuit.readWitnessSignals(w2, ["out"])).out;
      assert.notStrictEqual(out1, out2);
    });

    it("is order-sensitive", async () => {
      const w1 = await circuit.calculateWitness({ inputs: [1n, 2n] });
      const w2 = await circuit.calculateWitness({ inputs: [2n, 1n] });
      const out1 = (await circuit.readWitnessSignals(w1, ["out"])).out;
      const out2 = (await circuit.readWitnessSignals(w2, ["out"])).out;
      assert.notStrictEqual(out1, out2);
    });
  });

  describe("nInputs = 18 (pkCommit case for RSA-2048 user key + blind)", function () {
    let circuit: WitnessTester<["inputs"], ["out"]>;

    before(async function () {
      this.timeout(120000);
      circuit = await circomkit.WitnessTester("ChunkedPoseidonP256_18", {
        file: "components/pkCommit",
        template: "ChunkedPoseidonP256",
        params: [18],
        recompile: true,
      });
      console.log("  #constraints (N=18):", await circuit.getConstraintCount());
    });

    it("produces identical commit for identical (userPkLimbs, pkBlind)", async () => {
      // Simulates the linking check: Circuit A and Circuit B should produce
      // the same pkCommit when they use the same pk and blind.
      const userPkLimbs = Array.from({ length: 17 }, (_, i) => BigInt(i + 1));
      const pkBlind = 0xdeadbeefn;
      const inputs = { inputs: [...userPkLimbs, pkBlind] };

      const w1 = await circuit.calculateWitness(inputs);
      const w2 = await circuit.calculateWitness(inputs);
      const out1 = (await circuit.readWitnessSignals(w1, ["out"])).out;
      const out2 = (await circuit.readWitnessSignals(w2, ["out"])).out;
      assert.strictEqual(out1, out2, "pkCommit must be deterministic across instances");
    });

    it("distinguishes different pkBlind (defeats session-replay mixing)", async () => {
      const userPkLimbs = Array.from({ length: 17 }, (_, i) => BigInt(i + 1));
      const blind_A = 0xdeadbeefn;
      const blind_B = 0xcafebaben;

      const wA = await circuit.calculateWitness({ inputs: [...userPkLimbs, blind_A] });
      const wB = await circuit.calculateWitness({ inputs: [...userPkLimbs, blind_B] });
      const outA = (await circuit.readWitnessSignals(wA, ["out"])).out;
      const outB = (await circuit.readWitnessSignals(wB, ["out"])).out;
      assert.notStrictEqual(outA, outB, "different blinds must yield different pkCommit");
    });

    it("distinguishes different user_pk (defeats cert-swap attacks)", async () => {
      // Same blind but different pk → commits must differ, so an adversary
      // can't pair a legit CertChainRSA256 proof with an illegit
      // UserSigRSA256 proof from a different keypair.
      const pk_A = Array.from({ length: 17 }, (_, i) => BigInt(i + 1));
      const pk_B = [99n, ...pk_A.slice(1)];
      const pkBlind = 0xdeadbeefn;

      const wA = await circuit.calculateWitness({ inputs: [...pk_A, pkBlind] });
      const wB = await circuit.calculateWitness({ inputs: [...pk_B, pkBlind] });
      const outA = (await circuit.readWitnessSignals(wA, ["out"])).out;
      const outB = (await circuit.readWitnessSignals(wB, ["out"])).out;
      assert.notStrictEqual(outA, outB, "different pks must yield different pkCommit");
    });
  });
});
