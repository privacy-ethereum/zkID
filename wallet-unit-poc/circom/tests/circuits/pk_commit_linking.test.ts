import { WitnessTester } from "circomkit";
import { circomkit } from "../common";
import { loadInput } from "../common/fixtures";
import assert from "assert";

/**
 * Cross-circuit invariant: CertChainRSA256 (Circuit A) and UserSigRSA256
 * (Circuit B) must produce identical pkCommit when given the same user RSA
 * public key and pkBlind. This is the linking check that prevents proof-mixing.
 *
 * We read pkCommit directly from the witness array by index rather than via
 * readWitnessSignals, because the .sym files for these large circuits exceed
 * Node's string length limit.
 *
 * Witness layout (circom convention: index 0 = constant 1, then outputs):
 *   cert_chain:  witness[1] = pkCommit
 *   user_sig:  witness[1] = pkCommit, witness[2] = nullifier
 */
describe("pkCommit linking (CertChain <-> UserSig)", function () {
  let certChainCircuit: WitnessTester<any, ["pkCommit"]>;
  let userSigCircuit: WitnessTester<any, ["pkCommit", "nullifier"]>;
  let certChainInput: Record<string, any>;
  let userSigInput: Record<string, any>;

  before(async function () {
    this.timeout(900_000);
    certChainInput = loadInput("cert_chain_rs2048");
    userSigInput = loadInput("user_sig_rs2048");

    certChainCircuit = await circomkit.WitnessTester("certChainRS2048", {
      file: "certChain",
      template: "CertChainRSA256",
      params: [1536, 121, 17, 2048, 17, 2048, 128, 20],
    });
    userSigCircuit = await circomkit.WitnessTester("userSigRS2048", {
      file: "userSig",
      template: "UserSigRSA256",
      params: [1536, 121, 17],
    });
  });

  it("produces identical pkCommit for same user key and pkBlind", async function () {
    this.timeout(900_000);
    const ccWitness = await certChainCircuit.calculateWitness(certChainInput);
    const dsWitness = await userSigCircuit.calculateWitness(userSigInput);

    const ccPkCommit = ccWitness[1];
    const dsPkCommit = dsWitness[1];

    assert.strictEqual(
      ccPkCommit,
      dsPkCommit,
      "pkCommit must match between CertChain and UserSig for same key+blind"
    );
  });
});
