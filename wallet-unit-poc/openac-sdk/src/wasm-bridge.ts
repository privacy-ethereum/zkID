// Async loader and typed wrapper over the Spartan2 WASM module.
// Provides high-level API methods aligned with the zkID paper protocol:
// 1. loadKeys(baseUrl, vcSize)    — Fetch pre-generated keys (one-time, by VC size)
// 2. precomputeFromWitness()      — Prove Prepare circuit (once per credential)
// 3. precomputeShowFromWitness()  — Prove Show circuit (once per credential)
// 4. present()                    — Reblind both proofs with shared randomness (per presentation)
// 5. verify()                     — Verify both proofs + commitment check (per presentation)
//
// NOTE: Keys are generated offline via native CLI, not in browser.

import { WasmError } from "./errors.js";

export type VcSize = "1k" | "2k" | "4k" | "8k";

interface WasmPrecomputeResult {
  proof: Uint8Array;
  instance: Uint8Array;
  witness: Uint8Array;
}

interface WasmPresentResult {
  prepare_proof: Uint8Array;
  prepare_instance: Uint8Array;
  show_proof: Uint8Array;
  show_instance: Uint8Array;
}

interface WasmVerifyResult {
  valid: boolean;
  prepare_public_values: string[];
  show_public_values: string[];
  error: string | null;
}

interface WasmSingleVerifyResult {
  valid: boolean;
  public_values: string[];
}

interface OpenACWasmModule {
  init(): void;
  precompute_from_witness(
    pk: Uint8Array,
    witnessWtns: Uint8Array,
  ): WasmPrecomputeResult;
  precompute_show_from_witness(
    pk: Uint8Array,
    witnessWtns: Uint8Array,
  ): WasmPrecomputeResult;
  present(
    preparePk: Uint8Array,
    prepareInstance: Uint8Array,
    prepareWitness: Uint8Array,
    showPk: Uint8Array,
    showInstance: Uint8Array,
    showWitness: Uint8Array,
  ): WasmPresentResult;
  verify(
    prepareProof: Uint8Array,
    prepareVk: Uint8Array,
    prepareInstance: Uint8Array,
    showProof: Uint8Array,
    showVk: Uint8Array,
    showInstance: Uint8Array,
  ): WasmVerifyResult;
  verify_single(proof: Uint8Array, vk: Uint8Array): WasmSingleVerifyResult;
  compare_comm_w_shared(instance1: Uint8Array, instance2: Uint8Array): boolean;
}

export interface SetupKeys {
  preparePk: Uint8Array;
  prepareVk: Uint8Array;
  showPk: Uint8Array;
  showVk: Uint8Array;
}

export interface PrecomputeState {
  proof: Uint8Array;
  instance: Uint8Array;
  witness: Uint8Array;
}

export interface PresentationProof {
  prepareProof: Uint8Array;
  prepareInstance: Uint8Array;
  showProof: Uint8Array;
  showInstance: Uint8Array;
}

export interface VerificationResult {
  valid: boolean;
  preparePublicValues: string[];
  showPublicValues: string[];
  error?: string;
}

export class WasmBridge {
  private wasm: OpenACWasmModule | null = null;
  private initialized = false;

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  initWithModule(module: any): void {
    if (this.initialized) return;
    this.wasm = module as OpenACWasmModule;
    if (this.wasm?.init) {
      this.wasm.init();
    }
    this.initialized = true;
  }

  async init(wasmPath?: string): Promise<void> {
    if (this.initialized) return;

    if (wasmPath) {
      const module = await import(/* @vite-ignore */ wasmPath);
      this.wasm = module as OpenACWasmModule;
    } else {
      try {
        const module = await import("../wasm/pkg/openac_wasm.js");
        this.wasm = module as OpenACWasmModule;
      } catch {
        throw new WasmError(
          "WASM_LOAD_FAILED",
          "Could not load bundled WASM module. Build it first (npm run build:wasm) or provide wasmPath.",
        );
      }
    }

    if (this.wasm?.init) {
      this.wasm.init();
    }

    this.initialized = true;
  }

  get isInitialized(): boolean {
    return this.initialized;
  }

  private getWasm(): OpenACWasmModule {
    if (!this.wasm || !this.initialized) {
      throw new WasmError(
        "WASM_NOT_INITIALIZED",
        "WASM module not initialized. Call init() first.",
      );
    }
    return this.wasm;
  }

  async loadKeys(baseUrl: string, vcSize: VcSize): Promise<SetupKeys> {
    const prefix = `${vcSize}_`;
    const keyFiles = [
      `${prefix}prepare_proving.key`,
      `${prefix}prepare_verifying.key`,
      `${prefix}show_proving.key`,
      `${prefix}show_verifying.key`,
    ];

    const fetchKey = async (filename: string): Promise<Uint8Array> => {
      const url = `${baseUrl}/${filename}`;
      const response = await fetch(url);
      if (!response.ok) {
        throw new WasmError(
          "KEY_LOAD_FAILED",
          `Failed to load key from ${url}: ${response.status} ${response.statusText}`,
        );
      }
      const contentType = response.headers.get("content-type") ?? "";
      if (contentType.includes("text/html")) {
        throw new WasmError(
          "KEY_LOAD_FAILED",
          `Key file at ${url} returned HTML instead of binary data. ` +
            `The keys directory likely does not exist — run the ecdsa-spartan2 setup binary to generate keys.`,
        );
      }
      const buffer = await response.arrayBuffer();
      return new Uint8Array(buffer);
    };

    const keys = await Promise.all(keyFiles.map(fetchKey));
    const [preparePk, prepareVk, showPk, showVk] = keys as [
      Uint8Array,
      Uint8Array,
      Uint8Array,
      Uint8Array,
    ];

    return { preparePk, prepareVk, showPk, showVk };
  }

  async precomputeFromWitness(
    preparePk: Uint8Array,
    witnessWtns: Uint8Array,
  ): Promise<PrecomputeState> {
    const wasm = this.getWasm();
    const result = wasm.precompute_from_witness(preparePk, witnessWtns);
    return {
      proof: new Uint8Array(result.proof),
      instance: new Uint8Array(result.instance),
      witness: new Uint8Array(result.witness),
    };
  }

  async precomputeShowFromWitness(
    showPk: Uint8Array,
    witnessWtns: Uint8Array,
  ): Promise<PrecomputeState> {
    const wasm = this.getWasm();
    const result = wasm.precompute_show_from_witness(showPk, witnessWtns);
    return {
      proof: new Uint8Array(result.proof),
      instance: new Uint8Array(result.instance),
      witness: new Uint8Array(result.witness),
    };
  }

  async present(
    preparePk: Uint8Array,
    prepareInstance: Uint8Array,
    prepareWitness: Uint8Array,
    showPk: Uint8Array,
    showInstance: Uint8Array,
    showWitness: Uint8Array,
  ): Promise<PresentationProof> {
    const wasm = this.getWasm();
    const result = wasm.present(
      preparePk,
      prepareInstance,
      prepareWitness,
      showPk,
      showInstance,
      showWitness,
    );
    return {
      prepareProof: new Uint8Array(result.prepare_proof),
      prepareInstance: new Uint8Array(result.prepare_instance),
      showProof: new Uint8Array(result.show_proof),
      showInstance: new Uint8Array(result.show_instance),
    };
  }

  async verify(
    prepareProof: Uint8Array,
    prepareVk: Uint8Array,
    prepareInstance: Uint8Array,
    showProof: Uint8Array,
    showVk: Uint8Array,
    showInstance: Uint8Array,
  ): Promise<VerificationResult> {
    const wasm = this.getWasm();
    try {
      const result = wasm.verify(
        prepareProof,
        prepareVk,
        prepareInstance,
        showProof,
        showVk,
        showInstance,
      );
      return {
        valid: result.valid,
        preparePublicValues: result.prepare_public_values,
        showPublicValues: result.show_public_values,
        error: result.error ?? undefined,
      };
    } catch (error) {
      // Handle deserialization and verification errors from WASM
      const errorMessage = error instanceof Error ? error.message : String(error);
      return {
        valid: false,
        preparePublicValues: [],
        showPublicValues: [],
        error: errorMessage,
      };
    }
  }

  /** @deprecated Use verify() instead */
  async verifySingle(
    proof: Uint8Array,
    vk: Uint8Array,
  ): Promise<{ valid: boolean; publicValues: string[] }> {
    const wasm = this.getWasm();
    const result = wasm.verify_single(proof, vk);
    return { valid: result.valid, publicValues: result.public_values };
  }

  /** @deprecated Use verify() instead — commitment check is now internal */
  compareCommWShared(
    prepareInstance: Uint8Array,
    showInstance: Uint8Array,
  ): boolean {
    const wasm = this.getWasm();
    return wasm.compare_comm_w_shared(prepareInstance, showInstance);
  }
}
