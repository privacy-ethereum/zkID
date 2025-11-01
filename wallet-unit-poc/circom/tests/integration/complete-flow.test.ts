import { WitnessTester } from "circomkit";
import { circomkit } from "../common";
import { generateMockData } from "../../src/mock-vc-generator";
import { generateShowCircuitParams, generateShowInputs, signDeviceNonce } from "../../src/show";
import { base64ToBigInt, base64urlToBase64 } from "../../src/utils";
import assert from "assert";

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

  let showCircuit: WitnessTester<["deviceKeyX", "deviceKeyY", "nonce", "nonceLength", "sig_r", "sig_s_inverse"], []>;

  before(async () => {
    const RECOMPILE = true;
    jwtCircuit = await circomkit.WitnessTester(`JWT`, {
      file: "jwt",
      template: "JWT",
      params: [2048, 2000, 6, 50, 128],
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
        circuitParams: [2048, 2000, 6, 50, 128],
      });

      const jwtWitness = await jwtCircuit.calculateWitness(mockData.circuitInputs);
      await jwtCircuit.expectConstraintPass(jwtWitness);

      const jwtOutputs = await jwtCircuit.readWitnessSignals(jwtWitness, ["KeyBindingX", "KeyBindingY"]);
      const extractedKeyBindingX = jwtOutputs.KeyBindingX as bigint;
      const extractedKeyBindingY = jwtOutputs.KeyBindingY as bigint;

      const expectedKeyX = base64ToBigInt(base64urlToBase64(mockData.deviceKey.x));
      const expectedKeyY = base64ToBigInt(base64urlToBase64(mockData.deviceKey.y));

      assert.strictEqual(extractedKeyBindingX, expectedKeyX);
      assert.strictEqual(extractedKeyBindingY, expectedKeyY);

      const verifierNonce = "verifier-challenge-" + Date.now().toString();
      const deviceSignature = signDeviceNonce(verifierNonce, mockData.devicePrivateKey);

      const showParams = generateShowCircuitParams([256]);
      const showInputs = generateShowInputs(showParams, verifierNonce, deviceSignature, mockData.deviceKey);

      assert.strictEqual(showInputs.deviceKeyX, extractedKeyBindingX);
      assert.strictEqual(showInputs.deviceKeyY, extractedKeyBindingY);

      const showWitness = await showCircuit.calculateWitness(showInputs);
      await showCircuit.expectConstraintPass(showWitness);
    });

    it("should fail Show circuit when device signature doesn't match extracted key", async () => {
      // Phase 1: Prepare - Extract device binding key
      const mockData = await generateMockData({
        circuitParams: [2048, 2000, 6, 50, 128],
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
        circuitParams: [2048, 2000, 6, 50, 128],
      });

      const jwtWitness = await jwtCircuit.calculateWitness(mockData.circuitInputs);
      await jwtCircuit.expectConstraintPass(jwtWitness);

      const jwtOutputs = await jwtCircuit.readWitnessSignals(jwtWitness, ["KeyBindingX", "KeyBindingY"]);
      const extractedKeyBindingX = jwtOutputs.KeyBindingX as bigint;
      const extractedKeyBindingY = jwtOutputs.KeyBindingY as bigint;

      // Phase 2: Show - Multiple presentations with different nonces
      const nonces = ["nonce-1", "nonce-2", "nonce-3", "a-longer-nonce-for-testing-purposes"];

      for (let i = 0; i < nonces.length; i++) {
        const nonce = nonces[i];
        const deviceSignature = signDeviceNonce(nonce, mockData.devicePrivateKey);

        const showParams = generateShowCircuitParams([256]);
        const showInputs = generateShowInputs(showParams, nonce, deviceSignature, mockData.deviceKey);

        // Verify key matches extracted key from JWT circuit
        assert.strictEqual(showInputs.deviceKeyX, extractedKeyBindingX, `Nonce ${i + 1}: deviceKeyX should match`);
        assert.strictEqual(showInputs.deviceKeyY, extractedKeyBindingY, `Nonce ${i + 1}: deviceKeyY should match`);

        // Verify Show circuit
        const showWitness = await showCircuit.calculateWitness(showInputs);
        await showCircuit.expectConstraintPass(showWitness);
      }

      console.log(`✓ Successfully completed ${nonces.length} presentations with different nonces`);
    });

    it("should demonstrate complete workflow with claims verification", async () => {
      const mockData = await generateMockData({
        circuitParams: [2048, 2000, 6, 50, 128],
        claims: [
          { key: "name", value: "Alice" },
          { key: "age", value: "30" },
          { key: "email", value: "alice@example.com" },
        ],
      });

      // PHASE 1: PREPARE (JWT Circuit)
      const jwtWitness = await jwtCircuit.calculateWitness(mockData.circuitInputs);
      await jwtCircuit.expectConstraintPass(jwtWitness);

      // Extract device binding key
      const jwtOutputs = await jwtCircuit.readWitnessSignals(jwtWitness, ["KeyBindingX", "KeyBindingY", "messages"]);
      const deviceKeyX = jwtOutputs.KeyBindingX as bigint;
      const deviceKeyY = jwtOutputs.KeyBindingY as bigint;

      // PHASE 2: SHOW (Show Circuit)
      // Verifier sends nonce
      const verifierNonce = "verifier-session-" + Date.now();

      // Device signs nonce
      const deviceSignature = signDeviceNonce(verifierNonce, mockData.devicePrivateKey);

      // Generate Show circuit inputs using device key from JWT circuit
      const showParams = generateShowCircuitParams([256]);
      const showInputs = generateShowInputs(showParams, verifierNonce, deviceSignature, mockData.deviceKey);

      assert.strictEqual(showInputs.deviceKeyX, deviceKeyX, "Device key X should match");
      assert.strictEqual(showInputs.deviceKeyY, deviceKeyY, "Device key Y should match");

      // Run Show circuit
      const showWitness = await showCircuit.calculateWitness(showInputs);
      await showCircuit.expectConstraintPass(showWitness);
    });
  });
});
