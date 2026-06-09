import { WasmBridge } from "./wasm-bridge.js";
import { deserializeProofBundle } from "./prover.js";
import type {
  VerificationResult,
  VerifyingKeys,
  SerializedProof,
} from "./types.js";

function parseScalarToBool(value: string): boolean {
  if (!value) return false;
  const cleaned = value.replace(/^0x/, "").replace(/[^0-9a-fA-F]/g, "");
  if (!cleaned) return false;
  if (/^0+$/.test(cleaned)) return false;
  return true;
}

export class Verifier {
  private bridge: WasmBridge;

  constructor(bridge: WasmBridge) {
    this.bridge = bridge;
  }

  async verifyProof(
    proof: SerializedProof,
    keys: VerifyingKeys,
  ): Promise<VerificationResult> {
    const startTime = performance.now();

    let bundle;
    try {
      bundle = deserializeProofBundle(proof);
    } catch {
      return {
        valid: false,
        expressionResult: null,
        deviceKey: null,
        verifyMs: performance.now() - startTime,
        error: "Invalid proof format",
      };
    }

    const result = await this.bridge.verify(
      bundle.prepareProof,
      keys.prepareVerifyingKey,
      bundle.prepareInstance,
      bundle.showProof,
      keys.showVerifyingKey,
      bundle.showInstance,
    );

    if (!result.valid) {
      return {
        valid: false,
        expressionResult: null,
        deviceKey: null,
        verifyMs: performance.now() - startTime,
        error: result.error ?? "Proof verification failed",
      };
    }

    const expressionResult = parseScalarToBool(result.showPublicValues[0] ?? "");

    return {
      valid: true,
      expressionResult,
      deviceKey: null,
      verifyMs: performance.now() - startTime,
    };
  }

  async verifyComponents(
    prepareProof: Uint8Array,
    showProof: Uint8Array,
    keys: VerifyingKeys,
    prepareInstance: Uint8Array,
    showInstance: Uint8Array,
  ): Promise<VerificationResult> {
    const startTime = performance.now();

    const result = await this.bridge.verify(
      prepareProof,
      keys.prepareVerifyingKey,
      prepareInstance,
      showProof,
      keys.showVerifyingKey,
      showInstance,
    );

    if (!result.valid) {
      return {
        valid: false,
        expressionResult: null,
        deviceKey: null,
        verifyMs: performance.now() - startTime,
        error: result.error ?? "Proof verification failed",
      };
    }

    const expressionResult = parseScalarToBool(result.showPublicValues[0] ?? "");

    return {
      valid: true,
      expressionResult,
      deviceKey: null,
      verifyMs: performance.now() - startTime,
    };
  }
}
