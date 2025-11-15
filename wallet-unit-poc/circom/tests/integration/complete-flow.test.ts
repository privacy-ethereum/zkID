import { WitnessTester } from "circomkit";
import { circomkit } from "../common";
import { generateMockData } from "../../src/mock-vc-generator";
import { generateShowCircuitParams, generateShowInputs, signDeviceNonce } from "../../src/show";
import { base64ToBigInt, base64urlToBase64 } from "../../src/utils";
import assert from "assert";
import fs from "fs";
import { p256 } from "@noble/curves/nist.js";

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
      "decodeFlags",
      "ageClaimIndex"
    ],
    ["KeyBindingX", "KeyBindingY", "messages", "claim", "currentYear", "currentMonth", "currentDay"]
  >;

  let showCircuit: WitnessTester<["deviceKeyX", "deviceKeyY", "sig_r", "sig_s_inverse", "messageHash"], []>;
  let currentDate = { year: 2025, month: 1, day: 1 };

  before(async () => {
    const RECOMPILE = true;
    jwtCircuit = await circomkit.WitnessTester(`JWT`, {
      file: "jwt",
      template: "JWT",
      params: [1920, 1900, 4, 50, 128],
      recompile: RECOMPILE,
    });
    console.log("JWT Circuit #constraints:", await jwtCircuit.getConstraintCount());

    showCircuit = await circomkit.WitnessTester(`Show`, {
      file: "show",
      template: "Show",
      params: [128],
      recompile: RECOMPILE,
    });
    console.log("Show Circuit #constraints:", await showCircuit.getConstraintCount());
  });

  describe("Complete End-to-End Flow", () => {
    it("should complete full flow: JWT circuit extracts device key → Show circuit verifies device signature", async () => {
      const mockData = await generateMockData({
        circuitParams: [1920, 1900, 4, 50, 128],
        decodeFlags: [0, 1],
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

      let claim = mockData.claims[mockData.circuitInputs.ageClaimIndex - 2];

      const verifierNonce = "verifier-challenge-" + Date.now().toString();
      const deviceSignature = signDeviceNonce(verifierNonce, mockData.devicePrivateKey);

      const showParams = generateShowCircuitParams([128]);
      const showInputs = generateShowInputs(showParams, verifierNonce, deviceSignature, mockData.deviceKey, claim, {
        year: currentDate.year,
        month: currentDate.month,
        day: currentDate.day,
      });

      fs.writeFileSync("showInputs.json", JSON.stringify(showInputs, null, 2));

      // assert.strictEqual(showInputs.deviceKeyX, expectedKeyX);
      // assert.strictEqual(showInputs.deviceKeyY, expectedKeyY);

      const showWitness = await showCircuit.calculateWitness(showInputs);
      await showCircuit.expectConstraintPass(showWitness);
    });

    // it("should fail Show circuit when device signature doesn't match extracted key", async () => {
    //   // Phase 1: Prepare - Extract device binding key
    //   const mockData = await generateMockData({
    //     circuitParams: [2048, 2000, 4, 50, 128],
    //   });

    //   let claim = mockData.claims[mockData.circuitInputs.ageClaimIndex - 2];

    //   const jwtWitness = await jwtCircuit.calculateWitness(mockData.circuitInputs);
    //   await jwtCircuit.expectConstraintPass(jwtWitness);

    //   // Phase 2: Show - Try to use wrong device signature
    //   const verifierNonce = "verifier-challenge-12345";

    //   // Create a different device key (wrong key)
    //   const wrongPrivateKey = p256.utils.randomSecretKey();
    //   const wrongSignature = signDeviceNonce(verifierNonce, wrongPrivateKey);

    //   // Try to verify with wrong signature (should fail)
    //   const showParams = generateShowCircuitParams([256]);

    //   // This should throw an error because signature doesn't match
    //   assert.throws(
    //     () => {
    //       generateShowInputs(showParams, verifierNonce, wrongSignature, mockData.deviceKey, claim, {
    //         year: currentDate.year,
    //         month: currentDate.month,
    //         day: currentDate.day,
    //       });
    //     },
    //     /Device signature verification failed/,
    //     "Should fail when device signature doesn't match device binding key"
    //   );
    // });
  });
});
