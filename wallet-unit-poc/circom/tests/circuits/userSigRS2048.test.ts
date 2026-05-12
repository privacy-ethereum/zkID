import { WitnessTester } from "circomkit";
import { circomkit } from "../common";
import { loadInput } from "../common/fixtures";

describe("UserSigRSA256 (rs2048)", function () {
  let circuit: WitnessTester<
    ["tbs", "tbsLength", "userPkLimbs", "userRsaSignature", "pkBlind", "challenge"],
    ["pkCommit", "nullifier", "appIdPacked"]
  >;
  let input: Record<string, any>;

  before(async function () {
    this.timeout(900_000);
    input = loadInput("user_sig_rs2048");
    circuit = await circomkit.WitnessTester("userSigRS2048", {
      file: "userSig",
      template: "UserSigRSA256",
      params: [1536, 121, 17],
    });
  });

  it("should accept valid device signature inputs", async function () {
    this.timeout(900_000);
    const witness = await circuit.calculateWitness(input);
    await circuit.expectConstraintPass(witness);
  });

  it("should accept any value for the per-session challenge", async function () {
    this.timeout(900_000);
    // Different challenge → witness must still satisfy. The value is a
    // public input, so verifier-side mismatch is what catches a tampered
    // or stale challenge.
    const altered = { ...input, challenge: "12345" };
    const witness = await circuit.calculateWitness(altered);
    await circuit.expectConstraintPass(witness);
  });
});
