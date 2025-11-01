import { WitnessTester } from "circomkit";
import { generateMockData, verifyJWTSignature } from "../../src/mock-vc-generator";
import { circomkit } from "../common";
import assert from "assert";
import { base64ToBigInt, base64urlToBase64 } from "../../src/utils";

describe("VC Mock Data Generator - Circuit Tests", () => {
  let circuit: WitnessTester<
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

  before(async () => {
    const RECOMPILE = true;
    circuit = await circomkit.WitnessTester(`JWT`, {
      file: "jwt",
      template: "JWT",
      params: [2048, 2000, 6, 50, 128],
      recompile: RECOMPILE,
    });
    console.log("#constraints:", await circuit.getConstraintCount());
  });

  describe("Claims in _sd Array", () => {
    it("should verify hashed claims match _sd array in JWT payload", async () => {
      const mockData = await generateMockData();

      // Decode JWT payload
      const [header, payload, signature] = mockData.token.split(".");
      const decodedPayload = JSON.parse(Buffer.from(payload, "base64url").toString("utf8"));

      // Verify _sd array exists
      assert.ok(decodedPayload.vc, "VC should exist in payload");
      assert.ok(decodedPayload.vc.credentialSubject, "Credential subject should exist");
      assert.ok(decodedPayload.vc.credentialSubject._sd, "_sd array should exist");
      assert.ok(Array.isArray(decodedPayload.vc.credentialSubject._sd), "_sd should be an array");

      // Verify hashed claims match _sd array
      assert.strictEqual(
        mockData.hashedClaims.length,
        decodedPayload.vc.credentialSubject._sd.length,
        "Hashed claims length should match _sd array length"
      );

      for (let i = 0; i < mockData.hashedClaims.length; i++) {
        assert.strictEqual(
          mockData.hashedClaims[i],
          decodedPayload.vc.credentialSubject._sd[i],
          `Hashed claim ${i} should match _sd array entry`
        );
      }
    });
  });

  describe("Signature Verification", () => {
    it("should verify JWT signature is valid using issuer key", async () => {
      const mockData = await generateMockData();

      // Verify JWT signature using our custom verification function
      const isValid = verifyJWTSignature(mockData.token, mockData.issuerKey);
      assert.ok(isValid, "JWT signature should be valid");

      // Decode and verify payload structure
      const [header, payload, signature] = mockData.token.split(".");
      const decoded = JSON.parse(Buffer.from(payload, "base64url").toString("utf8"));

      // Verify payload structure
      assert.ok(decoded.vc, "VC should exist in verified payload");
      assert.ok(decoded.cnf, "CNF should exist in verified payload");
      assert.ok((decoded.cnf as any).jwk, "JWK should exist in CNF");
    });
  });

  describe("Device Binding Key Extraction", () => {
    it("should verify circuit outputs (KeyBindingX, KeyBindingY) match device binding key", async () => {
      const mockData = await generateMockData({
        circuitParams: [2048, 2000, 6, 50, 128],
      });

      // Calculate witness with circuit inputs
      const witness = await circuit.calculateWitness(mockData.circuitInputs);

      // Get circuit outputs
      const outputs = await circuit.readWitnessSignals(witness, ["KeyBindingX", "KeyBindingY"]);
      const KeyBindingX = outputs.KeyBindingX as bigint;
      const KeyBindingY = outputs.KeyBindingY as bigint;

      // Convert device binding key coordinates to bigint
      // JWK coordinates are in base64url format, need to convert to base64 first
      const deviceKeyX = base64ToBigInt(base64urlToBase64(mockData.deviceKey.x));
      const deviceKeyY = base64ToBigInt(base64urlToBase64(mockData.deviceKey.y));

      // Verify circuit outputs match device binding key
      assert.strictEqual(KeyBindingX, deviceKeyX, "Circuit KeyBindingX should match device binding key X");
      assert.strictEqual(KeyBindingY, deviceKeyY, "Circuit KeyBindingY should match device binding key Y");
    });
  });

  describe("Circuit Compatibility", () => {
    it("should generate circuit inputs that pass circuit constraints", async () => {
      const mockData = await generateMockData({
        circuitParams: [2048, 2000, 6, 50, 128],
      });

      const witness = await circuit.calculateWitness(mockData.circuitInputs);
      await circuit.expectConstraintPass(witness);
    });
  });

  describe("Issuer Key Consistency", () => {
    it("should use the same issuer key across multiple calls", async () => {
      const mockData1 = await generateMockData();
      const mockData2 = await generateMockData();

      assert.strictEqual(mockData1.issuerKey.x, mockData2.issuerKey.x, "Issuer key X should be constant");
      assert.strictEqual(mockData1.issuerKey.y, mockData2.issuerKey.y, "Issuer key Y should be constant");
    });
  });

  describe("Device Binding Key Randomness", () => {
    it("should generate different device binding keys across multiple calls", async () => {
      const mockData1 = await generateMockData();
      const mockData2 = await generateMockData();

      // Device keys should be different (very unlikely to be the same)
      const keysAreDifferent =
        mockData1.deviceKey.x !== mockData2.deviceKey.x || mockData1.deviceKey.y !== mockData2.deviceKey.y;

      assert.ok(keysAreDifferent, "Device binding keys should be different across calls");
    });
  });

  describe("Custom Options", () => {
    it("should accept custom claims", async () => {
      const customClaims = [
        { key: "custom_field", value: "custom_value" },
        { key: "another_field", value: "another_value" },
      ];

      const mockData = await generateMockData({ claims: customClaims });

      assert.strictEqual(mockData.claims.length, customClaims.length, "Claims length should match");
    });

    it("should accept custom circuit parameters", async () => {
      const customParams = [2048, 2000, 6, 50, 128];

      const mockData = await generateMockData({ circuitParams: customParams });

      assert.strictEqual(
        mockData.circuitParams.maxMatches,
        customParams[2],
        "Circuit max matches should match custom params"
      );
    });
  });

  describe("Circuit Output Messages", () => {
    it("should verify circuit outputs include decoded claims", async () => {
      const mockData = await generateMockData({
        circuitParams: [2048, 2000, 6, 50, 128],
      });

      console.log(mockData.deviceKey);
      console.log(mockData.token);
      const witness = await circuit.calculateWitness(mockData.circuitInputs);

      const outputs = await circuit.readWitnessSignals(witness, ["messages"]);

      assert.ok(outputs.messages !== undefined, "Messages output should exist");
      assert.ok(Array.isArray(outputs.messages), "Messages should be an array");
    });
  });
});
