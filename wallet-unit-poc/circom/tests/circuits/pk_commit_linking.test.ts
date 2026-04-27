import { WitnessTester } from "circomkit";
import { circomkit } from "../common";
import { loadInput } from "../common/fixtures";
import assert from "assert";

/**
 * Cross-circuit invariant: CertChainRSA256 (Circuit A) and DeviceSigRSA256
 * (Circuit B) must produce identical pk_commit when given the same user RSA
 * public key and pk_blind. This is the linking check that prevents proof-mixing.
 *
 * We read pk_commit directly from the witness array by index rather than via
 * readWitnessSignals, because the .sym files for these large circuits exceed
 * Node's string length limit.
 *
 * Witness layout (circom convention: index 0 = constant 1, then outputs):
 *   cert_chain:  witness[1] = nullifier, witness[2] = pk_commit
 *   device_sig:  witness[1] = pk_commit, witness[2] = packed_tbs
 */
describe("pk_commit linking (CertChain <-> DeviceSig)", function () {
  let certChainCircuit: WitnessTester<any, ["nullifier", "pk_commit"]>;
  let deviceSigCircuit: WitnessTester<any, ["pk_commit", "packed_tbs"]>;
  let certChainInput: Record<string, any>;
  let deviceSigInput: Record<string, any>;

  before(async function () {
    this.timeout(900_000);
    certChainInput = loadInput("cert_chain_rs2048");
    deviceSigInput = loadInput("device_sig_rs2048");

    certChainCircuit = await circomkit.WitnessTester("cert_chain_rs2048", {
      file: "cert_chain",
      template: "CertChainRSA256",
      params: [1536, 121, 17, 2048, 17, 2048, 128, 128, 20],
    });
    deviceSigCircuit = await circomkit.WitnessTester("device_sig_rs2048", {
      file: "device_sig",
      template: "DeviceSigRSA256",
      params: [1536, 121, 17],
    });
  });

  it("produces identical pk_commit for same user key and pk_blind", async function () {
    this.timeout(900_000);
    const ccWitness = await certChainCircuit.calculateWitness(certChainInput);
    const dsWitness = await deviceSigCircuit.calculateWitness(deviceSigInput);

    // cert_chain outputs: [nullifier, pk_commit] → pk_commit at index 2
    const ccPkCommit = ccWitness[2];
    // device_sig outputs: [pk_commit, packed_tbs] → pk_commit at index 1
    const dsPkCommit = dsWitness[1];

    assert.strictEqual(
      ccPkCommit,
      dsPkCommit,
      "pk_commit must match between CertChain and DeviceSig for same key+blind"
    );
  });
});
