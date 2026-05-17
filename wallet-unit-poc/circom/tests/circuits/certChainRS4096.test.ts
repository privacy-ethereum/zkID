import { WitnessTester } from "circomkit";
import { circomkit } from "../common";
import { loadInput } from "../common/fixtures";

describe("CertChainRSA256 (rs4096)", function () {
  let circuit: WitnessTester<
    [
      "tbsModulusTagOffset",
      "issuerTbs",
      "issuerTbsLength",
      "actualIssuerTbsLength",
      "issuerRsaModulus",
      "issuerRsaSignature",
      "smtRoot",
      "serialNumber",
      "smtSiblings",
      "smtOldKey",
      "smtOldValue",
      "smtIsOld0",
      "pkBlind",
    ],
    ["pkCommit"]
  >;
  let input: Record<string, any>;

  before(async function () {
    this.timeout(900_000);
    input = loadInput("cert_chain_rs4096");
    circuit = await circomkit.WitnessTester("certChainRS4096", {
      file: "certChain",
      template: "CertChainRSA256",
      params: [1536, 121, 34, 4096, 17, 2048, 128, 20],
    });
  });

  it("should accept valid cert chain inputs", async function () {
    this.timeout(900_000);
    const witness = await circuit.calculateWitness(input as any);
    await circuit.expectConstraintPass(witness);
  });
});
