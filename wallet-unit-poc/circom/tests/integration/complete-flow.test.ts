import { WitnessTester } from "circomkit";
import { circomkit } from "../common";
import { generateMockData } from "../../src/mock-vc-generator";
import { generateShowCircuitParams, generateShowInputs, signDeviceNonce } from "../../src/show";
import { base64ToBigInt, base64urlToBase64 } from "../../src/utils";
import assert from "assert";
import fs from "fs";

describe("Complete Flow: Register (JWT) → Show Circuit", () => {
  let jwtCircuit: WitnessTester<
    [
      "message",
      "messageLength",
      "periodIndex",
      "sig_r",
      "sig_s_inverse",
      "pubKeyX",
      "pubKeyY",
      "matchesCount",
      "matchSubstring",
      "matchLength",
      "matchIndex",
      "claims",
      "claimLengths",
      "decodeFlags"
    ],
    ["KeyBindingX", "KeyBindingY", "messages"]
  >;

  let showCircuit: WitnessTester<["deviceKeyX", "deviceKeyY", "sig_r", "sig_s_inverse", "messageHash"], []>;

  before(async () => {
    const RECOMPILE = true;
    jwtCircuit = await circomkit.WitnessTester(`JWT`, {
      file: "jwt",
      template: "JWT",
      params: [2048, 2000, 4, 50, 128],
      recompile: RECOMPILE,
    });
    console.log("JWT Circuit #constraints:", await jwtCircuit.getConstraintCount());

    showCircuit = await circomkit.WitnessTester(`Show`, {
      file: "show",
      template: "Show",
      params: [256],
      recompile: RECOMPILE,
    });
    console.log("Show Circuit #constraints:", await showCircuit.getConstraintCount());
  });

  describe("Complete End-to-End Flow", () => {
    it("should complete full flow: JWT circuit extracts device key → Show circuit verifies device signature", async () => {
      const mockData = await generateMockData({
        circuitParams: [2048, 2000, 4, 50, 128],
      });

      fs.writeFileSync("jwtInputs.json", JSON.stringify(mockData.circuitInputs, null, 2));
      const jwtWitness = await jwtCircuit.calculateWitness(mockData.circuitInputs);
      await jwtCircuit.expectConstraintPass(jwtWitness);

      // const jwtOutputs = await jwtCircuit.readWitnessSignals(jwtWitness, ["KeyBindingX", "KeyBindingY"]);
      // Get circuit outputs
      // const outputs = await circuit.readWitnessSignals(witness, ["KeyBindingX", "KeyBindingY"]);
      // TODO: readWitnessSignals is not returning outputs from Circom (bug in circomkit)
      // Verified locally using Circomkit logging
      // Need to find a more efficient way to retrieve outputs from Circom
      // Large witness values are causing overflow issues
      // readWitnessSignal works fine for smaller witnesses

      // const extractedKeyBindingX = jwtOutputs.KeyBindingX as bigint;
      // const extractedKeyBindingY = jwtOutputs.KeyBindingY as bigint;

      const expectedKeyX = base64ToBigInt(base64urlToBase64(mockData.deviceKey.x));
      const expectedKeyY = base64ToBigInt(base64urlToBase64(mockData.deviceKey.y));

      // assert.strictEqual(extractedKeyBindingX, expectedKeyX);
      // assert.strictEqual(extractedKeyBindingY, expectedKeyY);

      const verifierNonce = "verifier-challenge-" + Date.now().toString();
      const deviceSignature = signDeviceNonce(verifierNonce, mockData.devicePrivateKey);

      const showParams = generateShowCircuitParams([256]);
      const showInputs = generateShowInputs(showParams, verifierNonce, deviceSignature, mockData.deviceKey);
      fs.writeFileSync("showInputs.json", JSON.stringify(showInputs, null, 2));

      assert.strictEqual(showInputs.deviceKeyX, expectedKeyX);
      assert.strictEqual(showInputs.deviceKeyY, expectedKeyY);

      const showWitness = await showCircuit.calculateWitness(showInputs);
      await showCircuit.expectConstraintPass(showWitness);
    });

    it("should fail Show circuit when device signature doesn't match extracted key", async () => {
      // Phase 1: Prepare - Extract device binding key
      const mockData = await generateMockData({
        circuitParams: [2048, 2000, 4, 50, 128],
      });

      const jwtWitness = await jwtCircuit.calculateWitness(mockData.circuitInputs);
      await jwtCircuit.expectConstraintPass(jwtWitness);

      // Phase 2: Show - Try to use wrong device signature
      const verifierNonce = "verifier-challenge-12345";

      // Create a different device key (wrong key)
      const { p256 } = await import("@noble/curves/p256");
      const wrongPrivateKey = p256.utils.randomPrivateKey();
      const wrongSignature = signDeviceNonce(verifierNonce, wrongPrivateKey);

      // Try to verify with wrong signature (should fail)
      const showParams = generateShowCircuitParams([256]);

      // This should throw an error because signature doesn't match
      assert.throws(
        () => {
          generateShowInputs(showParams, verifierNonce, wrongSignature, mockData.deviceKey);
        },
        /Device signature verification failed/,
        "Should fail when device signature doesn't match device binding key"
      );
    });

    it("should complete flow with multiple verifier nonces", async () => {
      // Phase 1: Prepare - Extract device binding key once
      const mockData = await generateMockData({
        circuitParams: [2048, 2000, 4, 50, 128],
      });

      const jwtWitness = await jwtCircuit.calculateWitness(mockData.circuitInputs);
      await jwtCircuit.expectConstraintPass(jwtWitness);

      // const jwtOutputs = await jwtCircuit.readWitnessSignals(jwtWitness, ["KeyBindingX", "KeyBindingY"]);
      // const extractedKeyBindingX = jwtOutputs.KeyBindingX as bigint;
      // const extractedKeyBindingY = jwtOutputs.KeyBindingY as bigint;

      // Phase 2: Show - Multiple presentations with different nonces
      const nonces = ["nonce-1", "nonce-2", "nonce-3", "a-longer-nonce-for-testing-purposes"];

      for (let i = 0; i < nonces.length; i++) {
        const nonce = nonces[i];
        const deviceSignature = signDeviceNonce(nonce, mockData.devicePrivateKey);

        const showParams = generateShowCircuitParams([256]);
        const showInputs = generateShowInputs(showParams, nonce, deviceSignature, mockData.deviceKey);

        // // Verify key matches extracted key from JWT circuit
        // assert.strictEqual(showInputs.deviceKeyX, extractedKeyBindingX, `Nonce ${i + 1}: deviceKeyX should match`);
        // assert.strictEqual(showInputs.deviceKeyY, extractedKeyBindingY, `Nonce ${i + 1}: deviceKeyY should match`);

        // Verify Show circuit
        const showWitness = await showCircuit.calculateWitness(showInputs);
        await showCircuit.expectConstraintPass(showWitness);
      }

      console.log(`✓ Successfully completed ${nonces.length} presentations with different nonces`);
    });
  });
});
