import { WitnessTester } from "circomkit";
import { circomkit } from "../common";
import { generateMockData } from "../../src/mock-vc-generator";
import { generateShowCircuitParams, generateShowInputs, signDeviceNonce } from "../../src/show";
import { base64ToBigInt, base64urlToBase64 } from "../../src/utils";
import assert from "assert";
import { p256 } from "@noble/curves/nist.js";
import fs from "fs";

describe("Show Circuit - Device Binding Verification", () => {
  let circuit: WitnessTester<
    [
      "deviceKeyX",
      "deviceKeyY",
      "sig_r",
      "sig_s_inverse",
      "messageHash",
      "claim",
      "currentYear",
      "currentMonth",
      "currentDay"
    ],
    ["ageAbove18"]
  >;
  const claim = "WyJGc2w4ZWpObEFNT2Vqc1lTdjc2Z1NnIiwicm9jX2JpcnRoZGF5IiwiMTA0MDYwNSJd";
  const currentDate = { year: 2025, month: 1, day: 1 };

  before(async () => {
    const RECOMPILE = true;
    circuit = await circomkit.WitnessTester(`Show`, {
      file: "show",
      template: "Show",
      params: [128],
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
      const params = generateShowCircuitParams(mockData.circuitParams);
      const inputs = generateShowInputs(params, verifierNonce, deviceSignature, mockData.deviceKey, claim, {
        year: currentDate.year,
        month: currentDate.month,
        day: currentDate.day,
      });

      const witness = await circuit.calculateWitness(inputs);
      await circuit.expectConstraintPass(witness);
      const signals = await circuit.readWitnessSignals(witness, ["ageAbove18"]);
      assert.strictEqual(signals.ageAbove18, 0n, "Expect ageAbove18 to be 0 for underage claim");
    });

    it("should fail when device signature doesn't match device binding key", async () => {
      const mockData = await generateMockData({
        circuitParams: [2048, 2000, 6, 50, 128],
      });

      const wrongPrivateKey = p256.utils.randomSecretKey();
      const verifierNonce = "challenge-nonce-12345";
      const deviceSignature = signDeviceNonce(verifierNonce, wrongPrivateKey);

      const params = generateShowCircuitParams(mockData.circuitParams);

      assert.throws(() => {
        generateShowInputs(params, verifierNonce, deviceSignature, mockData.deviceKey, claim, {
          year: currentDate.year,
          month: currentDate.month,
          day: currentDate.day,
        });
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
          const params = generateShowCircuitParams(mockData.circuitParams);
          const inputs = generateShowInputs(params, nonce, deviceSignature, mockData.deviceKey, claim, {
            year: currentDate.year,
            month: currentDate.month,
            day: currentDate.day,
          });

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

      const params = generateShowCircuitParams(mockData.circuitParams);
      const inputs = generateShowInputs(params, verifierNonce, deviceSignature, mockData.deviceKey, claim, {
        year: currentDate.year,
        month: currentDate.month,
        day: currentDate.day,
      });

      const witness = await circuit.calculateWitness(inputs);
      await circuit.expectConstraintPass(witness);

      assert.strictEqual(inputs.deviceKeyX, deviceKeyX, "Device key X should match");
      assert.strictEqual(inputs.deviceKeyY, deviceKeyY, "Device key Y should match");
    });
  });
});
