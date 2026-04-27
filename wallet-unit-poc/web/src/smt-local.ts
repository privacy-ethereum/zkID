// Local SMT engine wrapper. Runs the Go-compiled `smt.wasm` from the
// moica-revocation-smt `snapshot-latest` release, streams the per-issuer
// binary snapshot into it, and exposes a `createProof(serialHex)` that
// yields the same `SmtProofResponse` shape the remote REST server used to
// return. The circuit-side converter (`convertSmtProofToCircuitInputs`) is
// therefore byte-for-byte compatible with the new source.
//
// This module is imported by the proving Worker; it is NOT safe to call
// from the main thread (the Go runtime hooks `globalThis` and keeps a
// blocking select{} alive). The Worker also isolates the wasm instance
// from the main-thread event loop so a slow ingest can't freeze the UI.

import { ensureAsset } from "./asset-download";
import type { DownloadProgress } from "./asset-download";
import {
  basename,
  requireDigest,
  SMT_SNAPSHOTS,
  SMT_WASM,
  SMT_WASM_EXEC,
  type DigestMap,
} from "./manifest";
import type { SmtIssuer, SmtProofResponse } from "./smt-client";
import {
  iterateNodeChunks,
  parseSnapshotHeader,
  type SnapshotHeader,
} from "./smt-snapshot";

/** Size of each node batch handed to `smtAddNodeChunk`. Matches the
 *  benchmark pattern the upstream PR #22 used — keeps memory pressure
 *  bounded and lets the Worker event loop run between batches. */
const NODE_CHUNK = 10_000;

/** Yield to the event loop roughly every N nodes during ingest. `setTimeout`
 *  has a ~4 ms browser floor, so yielding on every 10k-node chunk would add
 *  ~160 ms of wall-clock jank to a G2 tree for no UI benefit — one progress
 *  event per chunk already paints. Yield every ~5 chunks instead. */
const YIELD_EVERY_NODES = 50_000;

export type SmtLoadPhase = "wasm" | "snapshot" | "ingest";

export interface SmtLoadProgress {
  phase: SmtLoadPhase;
  /** Byte counters for the download phases. `ingest` reports node progress
   *  in `bytesDone` (nodes done) / `bytesTotal` (node count). */
  bytesDone: number;
  bytesTotal: number;
}

export interface SmtEngine {
  issuer: SmtIssuer;
  rootHex: string;
  crlNumber: bigint;
  depth: number;
  /** Hex key (with or without `0x` prefix). Returns the same JSON shape the
   *  REST server emitted so the existing converter keeps working. */
  createProof(serialHex: string): SmtProofResponse;
}

let wasmExecLoaded = false;
let wasmStarted = false;

export async function loadSmtEngine(
  issuer: SmtIssuer,
  digests: DigestMap,
  onProgress: (p: SmtLoadProgress) => void,
  signal?: AbortSignal,
): Promise<SmtEngine> {
  checkAborted(signal);

  if (!wasmStarted) {
    await ensureWasmExecLoaded(digests, onProgress, signal);
    await startSmtWasm(digests, onProgress, signal);
    wasmStarted = true;
  }

  const snapshot = SMT_SNAPSHOTS[issuer];
  const snapshotSha = requireDigest(digests, basename(snapshot.snapshotUrl));
  const bytes = await ensureAsset(
    snapshot.snapshotUrl,
    `smt_snapshot_${issuer}_${snapshotSha}`,
    snapshotSha,
    (p: DownloadProgress) =>
      onProgress({
        phase: "snapshot",
        bytesDone: p.bytesDone,
        bytesTotal: p.bytesTotal,
      }),
  );
  checkAborted(signal);

  const header = parseSnapshotHeader(bytes);
  if (header.depth !== 128) {
    throw new Error(
      `snapshot depth=${header.depth} but the circuit expects 128`,
    );
  }

  const api = wasmApi();
  throwOnError(api.smtInitTree(header.nodeCount, header.depth));

  let nodesDone = 0;
  let leafCount = 0;
  for (const chunk of iterateNodeChunks(bytes, header, NODE_CHUNK)) {
    checkAborted(signal);
    const parsed = api.smtAddNodeChunk(chunk.slice);
    if (typeof parsed !== "number" || parsed !== chunk.nodes) {
      throwOnError(parsed);
      throw new Error(
        `smtAddNodeChunk returned ${String(parsed)}; expected ${chunk.nodes}`,
      );
    }
    const priorNodes = nodesDone;
    nodesDone += chunk.nodes;
    leafCount += chunk.leaves;
    onProgress({
      phase: "ingest",
      bytesDone: nodesDone,
      bytesTotal: header.nodeCount,
    });
    // Yield so cancel/abort messages get a chance to land between batches.
    // Yielding every chunk costs ~4 ms per call (setTimeout floor), so gate
    // it on a per-node threshold — avoids ~5× the wall-clock hit for no UX gain.
    if (
      Math.floor(priorNodes / YIELD_EVERY_NODES) !==
      Math.floor(nodesDone / YIELD_EVERY_NODES)
    ) {
      await new Promise<void>((r) => setTimeout(r, 0));
    }
  }

  throwOnError(api.smtFinalize(header.rootHex, leafCount));

  return buildEngine(issuer, header, api);
}

function buildEngine(
  issuer: SmtIssuer,
  header: SnapshotHeader,
  api: WasmApi,
): SmtEngine {
  return {
    issuer,
    rootHex: header.rootHex,
    crlNumber: header.crlNumber,
    depth: header.depth,
    createProof(serialHex) {
      const keyHex = stripHexPrefix(serialHex);
      const result = api.smtCreateProof(keyHex);
      throwOnError(result);
      if (typeof result !== "string") {
        throw new Error(
          `smtCreateProof returned non-string: ${typeof result}`,
        );
      }
      const parsed = JSON.parse(result) as unknown;
      return normalizeProofResponse(parsed);
    },
  };
}

function stripHexPrefix(s: string): string {
  if (s.startsWith("0x") || s.startsWith("0X")) return s.slice(2);
  return s;
}

function normalizeProofResponse(raw: unknown): SmtProofResponse {
  if (!raw || typeof raw !== "object") {
    throw new Error("smtCreateProof JSON is not an object");
  }
  const obj = raw as Record<string, unknown>;
  const root = obj.root;
  const entry = obj.entry;
  const siblings = obj.siblings;
  const matchingEntry = obj.matchingEntry;
  if (typeof root !== "string") throw new Error("proof root missing");
  if (!Array.isArray(entry) || !entry.every((x) => typeof x === "string")) {
    throw new Error("proof entry missing or malformed");
  }
  if (
    !Array.isArray(siblings) ||
    !siblings.every((x) => typeof x === "string")
  ) {
    throw new Error("proof siblings missing or malformed");
  }
  if (
    matchingEntry != null &&
    (!Array.isArray(matchingEntry) ||
      !matchingEntry.every((x) => typeof x === "string"))
  ) {
    throw new Error("proof matchingEntry malformed");
  }
  const out: SmtProofResponse = {
    root,
    entry: entry as string[],
    siblings: siblings as string[],
  };
  if (Array.isArray(matchingEntry)) {
    out.matchingEntry = matchingEntry as string[];
  }
  return out;
}

// ---------------------------------------------------------------------------
// Go wasm runtime plumbing
// ---------------------------------------------------------------------------

interface WasmApi {
  smtInitTree: (nodeCount: number, depth: number) => unknown;
  smtAddNodeChunk: (chunk: Uint8Array) => unknown;
  smtFinalize: (rootHex: string, count: number) => unknown;
  smtCreateProof: (keyHex: string) => unknown;
}

/** wasm_exec.js is classic UMD that assigns `globalThis.Go` on load —
 *  `import()` doesn't work, so we fetch the text and eval it into Worker scope. */
async function ensureWasmExecLoaded(
  digests: DigestMap,
  onProgress: (p: SmtLoadProgress) => void,
  signal: AbortSignal | undefined,
): Promise<void> {
  if (wasmExecLoaded) return;
  checkAborted(signal);

  const sha = requireDigest(digests, basename(SMT_WASM_EXEC.url));
  const bytes = await ensureAsset(
    SMT_WASM_EXEC.url,
    `smt_wasm_exec_${sha}`,
    sha,
    (p: DownloadProgress) =>
      onProgress({ phase: "wasm", bytesDone: p.bytesDone, bytesTotal: p.bytesTotal }),
    { encoding: "identity" },
  );
  const src = new TextDecoder().decode(bytes);
  new Function(src)();
  if (typeof (globalThis as { Go?: unknown }).Go !== "function") {
    throw new Error("wasm_exec.js did not define globalThis.Go");
  }
  wasmExecLoaded = true;
}

async function startSmtWasm(
  digests: DigestMap,
  onProgress: (p: SmtLoadProgress) => void,
  signal: AbortSignal | undefined,
): Promise<void> {
  checkAborted(signal);

  const sha = requireDigest(digests, basename(SMT_WASM.url));
  const wasmBytes = await ensureAsset(
    SMT_WASM.url,
    `smt_wasm_${sha}`,
    sha,
    (p: DownloadProgress) =>
      onProgress({ phase: "wasm", bytesDone: p.bytesDone, bytesTotal: p.bytesTotal }),
    { encoding: "identity" },
  );
  const total = wasmBytes.byteLength;
  // GitHub Release serves smt.wasm as application/octet-stream, which
  // instantiateStreaming rejects with a MIME-type error. Buffer + instantiate.
  const GoCtor = (globalThis as unknown as { Go: new () => GoRuntime }).Go;
  const go = new GoCtor();
  const result = await WebAssembly.instantiate(
    wasmBytes.slice().buffer,
    go.importObject,
  );
  onProgress({ phase: "wasm", bytesDone: total, bytesTotal: total });

  // Go's `main()` blocks on `select{}`. Kick it off without awaiting — the
  // JS exports (smtInitTree, etc.) are registered synchronously before the
  // blocking select runs, so the caller can invoke them as soon as `run()`
  // yields control back to the event loop.
  const runPromise = go.run(result.instance);
  runPromise.catch((err) => {
    console.error("smt.wasm exited unexpectedly", err);
  });

  // Wait for `globalThis.smtReady` to flip true (set at the end of main()).
  const deadline = Date.now() + 10_000;
  while (!(globalThis as { smtReady?: boolean }).smtReady) {
    if (Date.now() > deadline) {
      throw new Error("smt.wasm failed to initialize within 10s");
    }
    await new Promise<void>((r) => setTimeout(r, 10));
    checkAborted(signal);
  }
}

function wasmApi(): WasmApi {
  const g = globalThis as Record<string, unknown>;
  const api = {
    smtInitTree: g.smtInitTree,
    smtAddNodeChunk: g.smtAddNodeChunk,
    smtFinalize: g.smtFinalize,
    smtCreateProof: g.smtCreateProof,
  };
  for (const [name, fn] of Object.entries(api)) {
    if (typeof fn !== "function") {
      throw new Error(`smt.wasm did not export ${name}`);
    }
  }
  return api as WasmApi;
}

/** Go's js.Error values show up on the JS side as `Error` instances. The
 *  non-error path returns `null`/`undefined` for void functions or a number
 *  / string for the ones that return values. Any `Error` means the Go side
 *  refused the call and we need to surface it. */
function throwOnError(v: unknown): void {
  if (v instanceof Error) throw v;
}

function checkAborted(signal: AbortSignal | undefined): void {
  if (signal?.aborted) throw new DOMException("aborted", "AbortError");
}

/** Minimal shape of the `Go` runtime class defined by `wasm_exec.js`. We only
 *  touch `importObject` (for instantiateStreaming) and `run(instance)` (which
 *  returns a never-resolving Promise because the Go side blocks on select{}). */
interface GoRuntime {
  importObject: WebAssembly.Imports;
  run(instance: WebAssembly.Instance): Promise<void>;
}
