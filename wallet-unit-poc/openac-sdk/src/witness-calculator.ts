import { readFile } from "fs/promises";
import { join, dirname } from "path";
import { fileURLToPath } from "url";
import { ProofError } from "./errors.js";
import type { JwtCircuitInputs, ShowCircuitInputs } from "./types.js";
import type { VcSize } from "./sizing.js";

// Circom witness calculators accept any object with string keys
type CircuitInput = Record<string, unknown>;

interface WitnessCalculatorInstance {
  calculateWitness(input: CircuitInput, sanityCheck?: boolean): Promise<bigint[]>;
  calculateBinWitness(input: CircuitInput, sanityCheck?: boolean): Promise<Uint8Array>;
  calculateWTNSBin(input: CircuitInput, sanityCheck?: boolean): Promise<Uint8Array>;
}

type WitnessCalculatorBuilder = (
  code: ArrayBuffer | Uint8Array,
  options?: { sanityCheck?: boolean }
) => Promise<WitnessCalculatorInstance>;

export class WitnessCalculator {
  /** Per-circuit-name cache of loaded calculators. */
  private calculators = new Map<string, WitnessCalculatorInstance>();
  private builder: WitnessCalculatorBuilder | null = null;

  private assetsDir: string;

  constructor(assetsDir?: string) {
    const defaultAssetsDir = join(dirname(fileURLToPath(import.meta.url)), "..", "assets");
    this.assetsDir = assetsDir ?? defaultAssetsDir;
  }

  private wasmPath(name: string): string {
    return join(this.assetsDir, `${name}.wasm`);
  }

  /** Map a VcSize to the circom circuit name (jwt_1k, jwt_2k, ...). */
  static jwtCircuitName(size?: VcSize): string {
    if (!size) return "jwt";
    return `jwt_${size}`;
  }

  async init(): Promise<void> {
    const builderPath = join(dirname(fileURLToPath(import.meta.url)), "..", "assets", "witness_calculator.js");
    const module = await import(/* webpackIgnore: true */ builderPath);
    this.builder = module.default ?? module;
  }

  private async getCalculator(name: string): Promise<WitnessCalculatorInstance> {
    let calc = this.calculators.get(name);
    if (calc) return calc;

    if (!this.builder) {
      throw new ProofError(
        "WITNESS_GENERATION_FAILED",
        "Witness calculator not initialized. Call init() first.",
      );
    }
    const wasmBuffer = await readFile(this.wasmPath(name));
    calc = await this.builder(wasmBuffer, { sanityCheck: true });
    this.calculators.set(name, calc);
    return calc;
  }

  async calculateJwtWitness(
    inputs: JwtCircuitInputs | CircuitInput,
    size?: VcSize,
  ): Promise<bigint[]> {
    const calc = await this.getCalculator(WitnessCalculator.jwtCircuitName(size));
    return await calc.calculateWitness(inputs as CircuitInput, true);
  }

  async calculateShowWitness(inputs: ShowCircuitInputs | CircuitInput): Promise<bigint[]> {
    const calc = await this.getCalculator("show");
    return await calc.calculateWitness(inputs as CircuitInput, true);
  }

  async calculateJwtWitnessWtns(
    inputs: JwtCircuitInputs | CircuitInput,
    size?: VcSize,
  ): Promise<Uint8Array> {
    const calc = await this.getCalculator(WitnessCalculator.jwtCircuitName(size));
    return await calc.calculateWTNSBin(inputs as CircuitInput, true);
  }

  async calculateShowWitnessWtns(
    inputs: ShowCircuitInputs | CircuitInput,
  ): Promise<Uint8Array> {
    const calc = await this.getCalculator("show");
    return await calc.calculateWTNSBin(inputs as CircuitInput, true);
  }

  async calculateMdocWitness(inputs: CircuitInput): Promise<bigint[]> {
    const calc = await this.getCalculator("mdoc");
    return await calc.calculateWitness(inputs, true);
  }

  async calculateMdocWitnessWtns(inputs: CircuitInput): Promise<Uint8Array> {
    const calc = await this.getCalculator("mdoc");
    return await calc.calculateWTNSBin(inputs, true);
  }
}
