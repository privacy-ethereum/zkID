import { WitnessTester } from "circomkit";
import { circomkit } from "../common";
import { generateMockData } from "../../src/mock-vc-generator";
import { generateShowCircuitParams, generateShowInputs, signDeviceNonce } from "../../src/show";
import { base64ToBigInt, base64urlToBase64 } from "../../src/utils";
import assert from "assert";
import { p256 } from "@noble/curves/nist.js";
import fs from "fs";

describe("Show Circuit - Device Binding Verification", () => {
  let circuit: WitnessTester<["deviceKeyX", "deviceKeyY", "sig_r", "sig_s_inverse", "messageHash"], []>;

  before(async () => {
    const RECOMPILE = true;
    circuit = await circomkit.WitnessTester(`Show`, {
      file: "show",
      template: "Show",
      params: [256],
      recompile: RECOMPILE,
    });
    console.log("#constraints:", await circuit.getConstraintCount());
  });

  describe("Device Binding Key Verification", () => {
    it("should verify device signature on nonce matches device binding key", async () => {
      // Step 1: Generate mock credential with device binding key
      const mockData = await generateMockData({
        circuitParams: [2048, 2000, 6, 50, 128],
      });

      // Step 2: Get device binding key from credential
      const devicePrivateKey = mockData.devicePrivateKey;

      // Step 3: Verifier sends nonce/challenge
      const verifierNonce = "challenge-nonce-12345";

      // Step 4: Device signs the nonce with its private key (stored in secure element)
      const deviceSignature = signDeviceNonce(verifierNonce, devicePrivateKey);

      // Step 5: Generate Show circuit inputs
      const params = generateShowCircuitParams([256]);
      const inputs = generateShowInputs(params, verifierNonce, deviceSignature, mockData.deviceKey);

      fs.writeFileSync("show-inputs.json", JSON.stringify(inputs, null, 2));

      // Step 6: Calculate witness and verify constraints pass
      const witness = await circuit.calculateWitness(inputs);
      await circuit.expectConstraintPass(witness);
    });

    it("should fail when device signature doesn't match device binding key", async () => {
      const mockData = await generateMockData({
        circuitParams: [2048, 2000, 6, 50, 128],
      });

      const wrongPrivateKey = p256.utils.randomSecretKey();
      const verifierNonce = "challenge-nonce-12345";
      const deviceSignature = signDeviceNonce(verifierNonce, wrongPrivateKey);

      const params = generateShowCircuitParams([256]);

      assert.throws(() => {
        generateShowInputs(params, verifierNonce, deviceSignature, mockData.deviceKey);
      }, /Device signature verification failed/);
    });

    it("should verify with nonce of varying lengths", async () => {
      const mockData = await generateMockData({
        circuitParams: [2048, 2000, 6, 50, 128],
      });

      const devicePrivateKey = mockData.devicePrivateKey;

      const nonces = [
        "short",
        "medium-length-nonce",
        "a-very-long-nonce-that-should-still-work-with-the-circuit-parameters",
      ];

      for (const nonce of nonces) {
        if (nonce.length <= 256) {
          const deviceSignature = signDeviceNonce(nonce, devicePrivateKey);
          const params = generateShowCircuitParams([256]);
          const inputs = generateShowInputs(params, nonce, deviceSignature, mockData.deviceKey);

          const witness = await circuit.calculateWitness(inputs);
          await circuit.expectConstraintPass(witness);
        }
      }
    });
  });

  describe("Integration with JWT Circuit", () => {
    it("should use device binding key from JWT circuit output", async () => {
      const mockData = await generateMockData({
        circuitParams: [2048, 2000, 6, 50, 128],
      });

      const deviceKeyX = base64ToBigInt(base64urlToBase64(mockData.deviceKey.x));
      const deviceKeyY = base64ToBigInt(base64urlToBase64(mockData.deviceKey.y));

      assert.ok(deviceKeyX > 0n, "Device key X should be valid");
      assert.ok(deviceKeyY > 0n, "Device key Y should be valid");

      const verifierNonce = "verifier-challenge-2024";
      const deviceSignature = signDeviceNonce(verifierNonce, mockData.devicePrivateKey);

      const params = generateShowCircuitParams([256]);
      const inputs = generateShowInputs(params, verifierNonce, deviceSignature, mockData.deviceKey);

      const witness = await circuit.calculateWitness(inputs);
      await circuit.expectConstraintPass(witness);

      assert.strictEqual(inputs.deviceKeyX, deviceKeyX, "Device key X should match");
      assert.strictEqual(inputs.deviceKeyY, deviceKeyY, "Device key Y should match");
    });
  });
});
