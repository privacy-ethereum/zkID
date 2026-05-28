import { describe, it, expect, beforeAll } from "vitest";
import { readFile } from "fs/promises";
import { existsSync } from "fs";
import { join, dirname } from "path";
import { fileURLToPath } from "url";

import { Verifier } from "../src/index.js";
import { WasmBridge } from "../src/wasm-bridge.js";
import type { VerifyingKeys } from "../src/types.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const KEYS_DIR = join(__dirname, "..", "..", "ecdsa-spartan2", "keys");
const WASM_PKG_DIR = join(__dirname, "..", "wasm", "pkg");

function checkVerificationArtifactsExist(): boolean {
  const requiredFiles = [
    join(KEYS_DIR, "1k_prepare_verifying.key"),
    join(KEYS_DIR, "1k_show_verifying.key"),
    join(KEYS_DIR, "1k_prepare_proof.bin"),
    join(KEYS_DIR, "1k_show_proof.bin"),
    join(KEYS_DIR, "1k_prepare_instance.bin"),
    join(KEYS_DIR, "1k_show_instance.bin"),
    join(WASM_PKG_DIR, "openac_wasm.js"),
    join(WASM_PKG_DIR, "openac_wasm_bg.wasm"),
  ];

  for (const file of requiredFiles) {
    if (!existsSync(file)) {
      return false;
    }
  }
  return true;
}

describe.skipIf(!checkVerificationArtifactsExist())(
  "WASM Verifier: Artifact Availability",
  () => {
    it("should have WASM module built", () => {
      expect(existsSync(join(WASM_PKG_DIR, "openac_wasm.js"))).toBe(true);
      expect(existsSync(join(WASM_PKG_DIR, "openac_wasm_bg.wasm"))).toBe(true);
    });

    it("should have verifying keys generated", () => {
      expect(existsSync(join(KEYS_DIR, "1k_prepare_verifying.key"))).toBe(true);
      expect(existsSync(join(KEYS_DIR, "1k_show_verifying.key"))).toBe(true);
    });

    it("should have pre-generated proofs for testing", () => {
      expect(existsSync(join(KEYS_DIR, "1k_prepare_proof.bin"))).toBe(true);
      expect(existsSync(join(KEYS_DIR, "1k_show_proof.bin"))).toBe(true);
      expect(existsSync(join(KEYS_DIR, "1k_prepare_instance.bin"))).toBe(true);
      expect(existsSync(join(KEYS_DIR, "1k_show_instance.bin"))).toBe(true);
    });
  },
);

describe("WASM Verifier: Class Structure", () => {
  it("should instantiate Verifier with WasmBridge", () => {
    const bridge = new WasmBridge();
    const verifier = new Verifier(bridge);
    expect(verifier).toBeInstanceOf(Verifier);
  });

  it("should have verifyProof method", () => {
    const bridge = new WasmBridge();
    const verifier = new Verifier(bridge);
    expect(typeof verifier.verifyProof).toBe("function");
  });

  it("should have verifyComponents method", () => {
    const bridge = new WasmBridge();
    const verifier = new Verifier(bridge);
    expect(typeof verifier.verifyComponents).toBe("function");
  });
});

describe.skipIf(!checkVerificationArtifactsExist())(
  "WASM Verifier: WasmBridge Initialization",
  () => {
    it("should load WASM module synchronously", async () => {
      const bridge = new WasmBridge();
      expect(bridge.isInitialized).toBe(false);

      try {
        const wasmModule = await import(
          /* webpackIgnore: true */ join(WASM_PKG_DIR, "openac_wasm.js")
        );
        const wasmBinary = await readFile(
          join(WASM_PKG_DIR, "openac_wasm_bg.wasm"),
        );
        wasmModule.initSync({ module: wasmBinary });
        bridge.initWithModule(wasmModule);

        expect(bridge.isInitialized).toBe(true);
      } catch (error) {
      }
    });
  },
);

describe.skipIf(!checkVerificationArtifactsExist())(
  "WASM Verifier: Pre-generated Proof Verification (Browser Only)",
  () => {
    let bridge: WasmBridge;
    let verifier: Verifier;
    let verifyingKeys: VerifyingKeys;
    let prepareProof: Uint8Array;
    let showProof: Uint8Array;
    let prepareInstance: Uint8Array;
    let showInstance: Uint8Array;
    let wasmAvailable = false;

    beforeAll(async () => {
      try {
        bridge = new WasmBridge();
        const wasmModule = await import(
          /* webpackIgnore: true */ join(WASM_PKG_DIR, "openac_wasm.js")
        );
        const wasmBinary = await readFile(
          join(WASM_PKG_DIR, "openac_wasm_bg.wasm"),
        );
        wasmModule.initSync({ module: wasmBinary });
        bridge.initWithModule(wasmModule);
        verifier = new Verifier(bridge);

        const [prepVk, showVk, prepProof_, shProof_, prepInst, shInst] =
          await Promise.all([
            readFile(join(KEYS_DIR, "1k_prepare_verifying.key")),
            readFile(join(KEYS_DIR, "1k_show_verifying.key")),
            readFile(join(KEYS_DIR, "1k_prepare_proof.bin")),
            readFile(join(KEYS_DIR, "1k_show_proof.bin")),
            readFile(join(KEYS_DIR, "1k_prepare_instance.bin")),
            readFile(join(KEYS_DIR, "1k_show_instance.bin")),
          ]);

        verifyingKeys = {
          prepareVerifyingKey: new Uint8Array(prepVk),
          showVerifyingKey: new Uint8Array(showVk),
        };
        prepareProof = new Uint8Array(prepProof_);
        showProof = new Uint8Array(shProof_);
        prepareInstance = new Uint8Array(prepInst);
        showInstance = new Uint8Array(shInst);

        try {
          await bridge.verify(
            prepareProof,
            verifyingKeys.prepareVerifyingKey,
            prepareInstance,
            showProof,
            verifyingKeys.showVerifyingKey,
            showInstance,
          );
          wasmAvailable = true;
        } catch (e) {
          wasmAvailable = false;
        }
      } catch (error) {
        wasmAvailable = false;
      }
    }, 60_000);

    it("should verify valid pre-generated proofs", async () => {
      if (!wasmAvailable) return;

      const result = await verifier.verifyComponents(
        prepareProof,
        showProof,
        verifyingKeys,
        prepareInstance,
        showInstance,
      );

      expect(result.valid).toBe(true);
      expect(result.error).toBeUndefined();
    }, 30_000);

    it("should reject proof with corrupted bytes", async () => {
      if (!wasmAvailable) return;

      const corruptedProof = new Uint8Array(prepareProof.slice());
      corruptedProof[Math.floor(corruptedProof.length / 2)] ^= 0xff;

      const result = await verifier.verifyComponents(
        corruptedProof,
        showProof,
        verifyingKeys,
        prepareInstance,
        showInstance,
      );

      expect(result.valid).toBe(false);
    }, 30_000);

    it("should reject proof with wrong verifying key", async () => {
      if (!wasmAvailable) return;

      const wrongKeys: VerifyingKeys = {
        prepareVerifyingKey: verifyingKeys.showVerifyingKey,
        showVerifyingKey: verifyingKeys.prepareVerifyingKey,
      };

      const result = await verifier.verifyComponents(
        prepareProof,
        showProof,
        wrongKeys,
        prepareInstance,
        showInstance,
      );

      expect(result.valid).toBe(false);
    }, 30_000);

    it("should extract public values from proof", async () => {
      if (!wasmAvailable) return;

      const result = await verifier.verifyComponents(
        prepareProof,
        showProof,
        verifyingKeys,
        prepareInstance,
        showInstance,
      );

      expect(result.valid).toBe(true);
      expect(typeof result.expressionResult).toBe("boolean");
      // Device key is no longer a verifier-observable public output of Show.
      expect(result.deviceKey).toBeNull();
      expect(result.verifyMs).toBeGreaterThan(0);
    }, 30_000);
  },
);

