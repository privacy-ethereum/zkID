// Orchestrates the full Prepare -> Show proving pipeline.

import { WasmBridge } from "./wasm-bridge.js";
import { WitnessCalculator } from "./witness-calculator.js";
import { Credential } from "./credential.js";
import { buildJwtCircuitInputs } from "./inputs/jwt-input-builder.js";
import {
  buildShowCircuitInputs,
  signDeviceNonce,
} from "./inputs/show-input-builder.js";
import { circuitInputsToJson, base64Encode } from "./utils.js";
import { InputError, ProofError } from "./errors.js";
import type {
  ProofRequest,
  ProofResult,
  ProofPublicValues,
  ProofTiming,
  SerializedProofJSON,
  JwtCircuitParams,
  ShowCircuitParams,
} from "./types.js";

const SDK_VERSION = "0.1.0";

export class Prover {
  private bridge: WasmBridge;
  private witnessCalculator: WitnessCalculator | null = null;

  constructor(bridge: WasmBridge, witnessCalculator?: WitnessCalculator) {
    this.bridge = bridge;
    this.witnessCalculator = witnessCalculator ?? null;
  }

  async initWitnessCalculator(assetsDir?: string): Promise<void> {
    this.witnessCalculator = new WitnessCalculator(assetsDir);
    await this.witnessCalculator.init();
  }

  get hasWitnessCalculator(): boolean {
    return this.witnessCalculator !== null;
  }

  async createProof(request: ProofRequest): Promise<ProofResult> {
    const startTime = performance.now();
    const timing: Partial<ProofTiming> = {};

    const credential = Credential.parse(request.jwt, request.disclosures);

    // determine birthday claim index
    let birthdayClaimIndex: number;
    if (request.birthdayClaimIndex !== undefined) {
      birthdayClaimIndex = request.birthdayClaimIndex;
    } else {
      const autoDetected = credential.findBirthdayClaim();
      if (autoDetected === null) {
        throw new InputError(
          "BIRTHDAY_NOT_FOUND",
          "Could not auto-detect birthday claim. Provide birthdayClaimIndex explicitly.",
        );
      }
      birthdayClaimIndex = autoDetected;
    }

    const decodeFlags =
      request.decodeFlags ??
      credential.claims.map((_, i) => (i === birthdayClaimIndex ? 1 : 0));

    const additionalMatches =
      request.additionalMatches ?? credential.disclosureHashes;

    const jwtParams: JwtCircuitParams = request.jwtParams ?? {
      maxMessageLength: 1920,
      maxB64PayloadLength: 1900,
      maxMatches: 4,
      maxSubstringLength: 50,
      maxClaimLength: 128,
    };

    const showParams: ShowCircuitParams = request.showParams ?? {
      maxClaimsLength: 128,
    };

    const jwtInputs = buildJwtCircuitInputs(
      credential,
      request.issuerPublicKey,
      jwtParams,
      additionalMatches,
      decodeFlags,
      birthdayClaimIndex,
    );

    const jwtInputsJson = circuitInputsToJson(jwtInputs);

    const keys = request.keys;
    if (!keys) {
      throw new ProofError(
        "PROOF_GENERATION_FAILED",
        "Keys are required. Call setup() first or provide keys in ProofRequest.",
      );
    }

    let t1 = performance.now();
    // const prepareWitness = await this.generatePrepareWitness(jwtInputsJson);
    const prepareResult = await this.bridge.precompute(keys.prepareProvingKey);
    timing.prepareProveMs = performance.now() - t1;

    // build Show circuit inputs
    const currentDate = request.currentDate ?? new Date();
    const userSignature = signDeviceNonce(
      request.verifierNonce,
      request.devicePrivateKey,
    );

    const birthdayClaim = credential.claims[birthdayClaimIndex];
    if (!birthdayClaim) {
      throw new InputError(
        "BIRTHDAY_NOT_FOUND",
        `No claim at index ${birthdayClaimIndex}`,
      );
    }

    const deviceKey = credential.deviceBindingKey;
    if (!deviceKey) {
      throw new InputError(
        "INVALID_JWT",
        "JWT payload does not contain device binding key (cnf.jwk)",
      );
    }

    const showInputs = buildShowCircuitInputs(
      showParams,
      request.verifierNonce,
      userSignature,
      deviceKey,
      birthdayClaim.raw,
      {
        year: currentDate.getUTCFullYear(),
        month: currentDate.getUTCMonth() + 1,
        day: currentDate.getUTCDate(),
      },
    );

    const showInputsJson = circuitInputsToJson(showInputs);

    t1 = performance.now();
    const showWitnessBytes = await this.generateShowWitness(showInputsJson);
    const showResult = await this.bridge.precompute(keys.showProvingKey);
    timing.showProveMs = performance.now() - t1;

    t1 = performance.now();
    const presentResult = await this.bridge.present(
      keys.prepareProvingKey,
      prepareResult.instance,
      prepareResult.witness,
      keys.showProvingKey,
      showResult.instance,
      showResult.witness,
    );
    timing.prepareReblindMs = performance.now() - t1;
    timing.showReblindMs = 0; // Included in the present() call above

    timing.totalMs = performance.now() - startTime;

    // Extract ageAbove18 and ageClaim from witness outputs
    // JWT circuit: w[1..96] = ageClaim (96 decoded bytes), w[97] = KeyBindingX, w[98] = KeyBindingY
    // Show circuit: w[1] = ageAbove18 (0 or 1), w[2] = deviceKeyX, w[3] = deviceKeyY
    let ageAbove18 = false;
    let ageClaim: bigint[] = [];

    if (this.witnessCalculator) {
      const jwtWitness = await this.calculateJwtWitness(jwtInputsJson);
      ageClaim = jwtWitness.slice(1, 97);

      const showWitness = await this.calculateShowWitness(showInputsJson);
      ageAbove18 = showWitness[1] === 1n;
    }

    const publicValues: ProofPublicValues = {
      ageAbove18,
      deviceKeyX: showInputs.deviceKeyX.toString(),
      deviceKeyY: showInputs.deviceKeyY.toString(),
      ageClaim,
    };

    const result: ProofResult = {
      prepareProof: presentResult.prepareProof,
      showProof: presentResult.showProof,
      prepareInstance: presentResult.prepareInstance,
      showInstance: presentResult.showInstance,
      publicValues,
      timing: timing as ProofTiming,

      serialize(): Uint8Array {
        return serializeProofBundle(result);
      },

      toBase64(): string {
        return base64Encode(serializeProofBundle(result));
      },

      toJSON(): SerializedProofJSON {
        return {
          version: SDK_VERSION,
          prepareProof: base64Encode(result.prepareProof),
          showProof: base64Encode(result.showProof),
          prepareInstance: base64Encode(result.prepareInstance),
          showInstance: base64Encode(result.showInstance),
          publicValues: {
            ageAbove18: result.publicValues.ageAbove18,
            deviceKeyX: result.publicValues.deviceKeyX,
            deviceKeyY: result.publicValues.deviceKeyY,
          },
        };
      },
    };

    return result;
  }

  private async generatePrepareWitness(
    inputsJson: string,
  ): Promise<Uint8Array> {
    if (!this.witnessCalculator) {
      throw new ProofError(
        "WITNESS_GENERATION_FAILED",
        "WitnessCalculator not initialized. Call initWitnessCalculator() first or provide it in constructor.",
      );
    }
    const inputs = this.parseJsonToBigInt(inputsJson);
    return await this.witnessCalculator.calculateJwtWitnessWtns(inputs);
  }

  private async generateShowWitness(inputsJson: string): Promise<Uint8Array> {
    if (!this.witnessCalculator) {
      throw new ProofError(
        "WITNESS_GENERATION_FAILED",
        "WitnessCalculator not initialized. Call initWitnessCalculator() first or provide it in constructor.",
      );
    }
    const inputs = this.parseJsonToBigInt(inputsJson);
    return await this.witnessCalculator.calculateShowWitnessWtns(inputs);
  }

  private async calculateJwtWitness(inputsJson: string): Promise<bigint[]> {
    if (!this.witnessCalculator) {
      throw new ProofError(
        "WITNESS_GENERATION_FAILED",
        "WitnessCalculator not initialized.",
      );
    }
    const inputs = this.parseJsonToBigInt(inputsJson);
    return await this.witnessCalculator.calculateJwtWitness(inputs);
  }

  private async calculateShowWitness(inputsJson: string): Promise<bigint[]> {
    if (!this.witnessCalculator) {
      throw new ProofError(
        "WITNESS_GENERATION_FAILED",
        "WitnessCalculator not initialized.",
      );
    }
    const inputs = this.parseJsonToBigInt(inputsJson);
    return await this.witnessCalculator.calculateShowWitness(inputs);
  }

  private parseJsonToBigInt(json: string): Record<string, unknown> {
    return JSON.parse(json, (_key, value) => {
      if (typeof value === "string" && /^-?\d+$/.test(value)) {
        return BigInt(value);
      }
      return value;
    });
  }
}

// Serialize a proof bundle into a single binary blob.
// Format: [4 bytes: length][bytes] for each of: version, prepareProof, showProof, prepareInstance, showInstance
function serializeProofBundle(result: ProofResult): Uint8Array {
  const version = new TextEncoder().encode(SDK_VERSION);
  const parts = [
    version,
    result.prepareProof,
    result.showProof,
    result.prepareInstance,
    result.showInstance,
  ];

  let totalSize = 0;
  for (const part of parts) {
    totalSize += 4 + part.length;
  }

  const buffer = new Uint8Array(totalSize);
  const view = new DataView(buffer.buffer);
  let offset = 0;

  for (const part of parts) {
    view.setUint32(offset, part.length, true);
    offset += 4;
    buffer.set(part, offset);
    offset += part.length;
  }

  return buffer;
}

export function deserializeProofBundle(data: Uint8Array): {
  version: string;
  prepareProof: Uint8Array;
  showProof: Uint8Array;
  prepareInstance: Uint8Array;
  showInstance: Uint8Array;
} {
  const view = new DataView(data.buffer, data.byteOffset, data.byteLength);
  let offset = 0;

  function readPart(): Uint8Array {
    const len = view.getUint32(offset, true);
    offset += 4;
    const part = data.slice(offset, offset + len);
    offset += len;
    return part;
  }

  const versionBytes = readPart();
  const version = new TextDecoder().decode(versionBytes);
  const prepareProof = readPart();
  const showProof = readPart();
  const prepareInstance = readPart();
  const showInstance = readPart();

  return { version, prepareProof, showProof, prepareInstance, showInstance };
}
