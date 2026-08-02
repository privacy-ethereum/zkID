// Keys fetched from the CDN must match pinned SHA-256 digests; tampered or
// unknown key material is rejected before it reaches the WASM verifier.
import { describe, it, expect, vi, afterEach } from "vitest";
import { WasmBridge } from "../src/wasm-bridge.js";
import { WasmError } from "../src/errors.js";

afterEach(() => vi.unstubAllGlobals());

describe("loadKeys key integrity", () => {
  it("rejects fetched key bytes that do not match the pinned digest", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => new Response(new Uint8Array([1, 2, 3]))),
    );
    const bridge = new WasmBridge();
    await expect(bridge.loadKeys("https://evil.example", "1k")).rejects.toSatisfy(
      (e: unknown) =>
        e instanceof WasmError && e.code === "KEY_INTEGRITY_FAILED",
    );
  });
});
