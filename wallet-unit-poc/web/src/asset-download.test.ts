// Tests for asset-download.ts. fake-indexeddb/auto installs a global
// `indexedDB` shim so asset-store.ts's IDB fallback is exercised — OPFS is
// unavailable in Node, so hasOPFS() returns false and we hit the IDB path.

import "fake-indexeddb/auto";
import { gzipSync } from "node:zlib";
import { createHash } from "node:crypto";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { ensureAsset } from "./asset-download";
import { assetStore, clearAllAssets } from "./asset-store";

function sha256HexOf(bytes: Uint8Array): string {
  return createHash("sha256").update(bytes).digest("hex");
}

function gzipped(bytes: Uint8Array): { gz: Uint8Array; sha: string } {
  const gz = gzipSync(bytes);
  return { gz, sha: sha256HexOf(gz) };
}

function gzippedResponse(gz: Uint8Array): Response {
  const ab = gz.buffer.slice(gz.byteOffset, gz.byteOffset + gz.byteLength);
  return new Response(ab as ArrayBuffer, {
    status: 200,
    headers: { "Content-Length": String(gz.byteLength) },
  });
}

describe("ensureAsset", () => {
  const originalFetch = globalThis.fetch;
  const testUrl = "/keys/test-asset.bin.gz";

  beforeEach(async () => {
    await clearAllAssets().catch(() => {});
  });

  afterEach(() => {
    globalThis.fetch = originalFetch;
    vi.restoreAllMocks();
  });

  it("downloads, decompresses, and verifies the compressed-byte hash", async () => {
    const raw = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);
    const { gz, sha } = gzipped(raw);
    globalThis.fetch = vi.fn(async () => gzippedResponse(gz)) as typeof fetch;

    const progressUpdates: Array<{ bytesDone: number; bytesTotal: number }> = [];
    const out = await ensureAsset(testUrl, "cache-key-happy", sha, (p) =>
      progressUpdates.push({ ...p }),
    );

    expect(Array.from(out)).toEqual(Array.from(raw));
    expect(progressUpdates.length).toBeGreaterThan(0);

    const cached = await assetStore.get("cache-key-happy");
    expect(cached).not.toBeNull();
    expect(Array.from(cached!)).toEqual(Array.from(raw));
  });

  it("throws and clears cache on hash mismatch", async () => {
    const raw = new Uint8Array([9, 8, 7, 6]);
    const { gz } = gzipped(raw);
    const wrongHash = "0".repeat(64);
    globalThis.fetch = vi.fn(async () => gzippedResponse(gz)) as typeof fetch;

    await expect(
      ensureAsset(testUrl, "cache-key-mismatch", wrongHash, () => {}),
    ).rejects.toThrow(/hash mismatch/);

    const cached = await assetStore.get("cache-key-mismatch");
    expect(cached).toBeNull();
    expect(await assetStore.get("cache-key-mismatch.partial")).toBeNull();
  });

  it("returns cached bytes without fetching when the cache key is hit", async () => {
    const raw = new Uint8Array([42, 42, 42, 42, 42]);
    const { sha } = gzipped(raw);
    await assetStore.put("cache-key-cached", raw);

    const fetchSpy = vi.fn(async () => gzippedResponse(gzipped(raw).gz)) as typeof fetch;
    globalThis.fetch = fetchSpy;

    const out = await ensureAsset(testUrl, "cache-key-cached", sha, () => {});
    expect(Array.from(out)).toEqual(Array.from(raw));
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it("throws synchronously when called with an empty expected hash", async () => {
    const fetchSpy = vi.fn(async () =>
      gzippedResponse(gzipped(new Uint8Array([1])).gz),
    ) as typeof fetch;
    globalThis.fetch = fetchSpy;

    await expect(
      ensureAsset(testUrl, "cache-key-empty", "", () => {}),
    ).rejects.toThrow(/without expected hash/);
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it("handles identity encoding for un-gzipped assets", async () => {
    const raw = new Uint8Array([7, 7, 7, 7, 7]);
    const sha = sha256HexOf(raw);
    globalThis.fetch = vi.fn(
      async () =>
        new Response(raw.slice().buffer as ArrayBuffer, {
          status: 200,
          headers: { "Content-Length": String(raw.byteLength) },
        }),
    ) as typeof fetch;

    const out = await ensureAsset(
      "/smt-snapshot/smt.wasm",
      "cache-key-identity",
      sha,
      () => {},
      { encoding: "identity" },
    );
    expect(Array.from(out)).toEqual(Array.from(raw));

    const cached = await assetStore.get("cache-key-identity");
    expect(Array.from(cached!)).toEqual(Array.from(raw));
  });

  it("throws and leaves no cache entry on non-2xx response", async () => {
    globalThis.fetch = vi.fn(
      async () =>
        new Response("oops", { status: 500, statusText: "Internal Server Error" }),
    ) as typeof fetch;

    await expect(
      ensureAsset(testUrl, "cache-key-500", "0".repeat(64), () => {}),
    ).rejects.toThrow(/500/);

    const cached = await assetStore.get("cache-key-500");
    expect(cached).toBeNull();
  });

  it("throws and clears cache on malformed gzip payload", async () => {
    const junk = new Uint8Array([0x00, 0x01, 0x02, 0x03, 0x04, 0x05]);
    globalThis.fetch = vi.fn(
      async () =>
        new Response(junk.buffer as ArrayBuffer, {
          status: 200,
          headers: { "Content-Length": String(junk.byteLength) },
        }),
    ) as typeof fetch;

    await expect(
      ensureAsset(testUrl, "cache-key-badgz", sha256HexOf(junk), () => {}),
    ).rejects.toThrow();

    const cached = await assetStore.get("cache-key-badgz");
    expect(cached).toBeNull();
    expect(await assetStore.get("cache-key-badgz.partial")).toBeNull();
  });

  it("aborted writer leaves no committed key", async () => {
    const w = await assetStore.writer("writer-abort-key");
    const writer = w.stream.getWriter();
    await writer.write(new Uint8Array([1, 2, 3]));
    await writer.close();
    await w.abort();
    expect(await assetStore.get("writer-abort-key")).toBeNull();
  });

  it("committed writer makes bytes visible only after commit()", async () => {
    const w = await assetStore.writer("writer-commit-key");
    const writer = w.stream.getWriter();
    await writer.write(new Uint8Array([4, 5, 6]));
    await writer.close();
    expect(await assetStore.get("writer-commit-key")).toBeNull();
    await w.commit();
    expect(Array.from((await assetStore.get("writer-commit-key"))!)).toEqual([
      4, 5, 6,
    ]);
  });

  it("reaps stale siblings under the same prefix on successful verify", async () => {
    const oldSha = "a".repeat(64);
    const otherOldSha = "b".repeat(64);
    await assetStore.put(`pkg_pk_${oldSha}`, new Uint8Array([1]));
    await assetStore.put(`pkg_pk_${otherOldSha}`, new Uint8Array([2]));
    await assetStore.put(`pkg_pk_${otherOldSha}.partial`, new Uint8Array([5]));
    // Same prefix family but different role → must NOT be swept.
    await assetStore.put(`pkg_wgen_${oldSha}`, new Uint8Array([3]));
    // No SHA suffix → must NOT be swept.
    await assetStore.put("pkg_pk_legacy", new Uint8Array([4]));

    const raw = new Uint8Array([7, 7, 7]);
    const { gz, sha } = gzipped(raw);
    globalThis.fetch = vi.fn(async () => gzippedResponse(gz)) as typeof fetch;

    const out = await ensureAsset(testUrl, `pkg_pk_${sha}`, sha, () => {});
    expect(Array.from(out)).toEqual(Array.from(raw));

    expect(await assetStore.get(`pkg_pk_${oldSha}`)).toBeNull();
    expect(await assetStore.get(`pkg_pk_${otherOldSha}`)).toBeNull();
    expect(await assetStore.get(`pkg_pk_${otherOldSha}.partial`)).toBeNull();
    expect(await assetStore.get(`pkg_wgen_${oldSha}`)).not.toBeNull();
    expect(await assetStore.get("pkg_pk_legacy")).not.toBeNull();
    expect(await assetStore.get(`pkg_pk_${sha}`)).not.toBeNull();
  });
});

describe("clearAllAssets", () => {
  it("empties every cache entry across repeated calls", async () => {
    await assetStore.put("clear-a", new Uint8Array([1, 2, 3]));
    await assetStore.put("clear-b", new Uint8Array([4, 5, 6]));

    await clearAllAssets();

    expect(await assetStore.get("clear-a")).toBeNull();
    expect(await assetStore.get("clear-b")).toBeNull();

    // A second clear on an empty store must not throw.
    await clearAllAssets();
  });
});
