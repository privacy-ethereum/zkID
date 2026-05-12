// Dedicated Worker for warmup and proving phases.

import init, {
  CircuitKind,
  initThreadPool,
  load_pk,
  prove,
} from "./wasm/spartan2_wasm.js";

import { ensureAsset } from "./asset-download";
import { assetStore } from "./asset-store";
import {
  basename,
  CIRCUITS,
  fetchReleaseDigests,
  ManifestError,
  requireDigest,
  type CircuitKind as Kind,
  type DigestMap,
} from "./manifest";
import {
  convertSmtProofToCircuitInputs,
  type SmtCircuitInputs,
  type SmtIssuer,
} from "./smt-client";
import { loadSmtEngine, type SmtEngine, type SmtLoadPhase } from "./smt-local";
import { calculateWitness } from "./witness";

// Worker message contract.

export interface ProveInput {
  certJson: string;
  deviceJson: string;
  certKind: Kind;
  /** Verifier-issued per-session field element (decimal string). Forwarded
   *  back via `proving_complete` for review-screen display. */
  challenge: string;
}

export type WorkerInMsg =
  | { type: "warmup" }
  | { type: "load_smt"; issuer: SmtIssuer }
  | { type: "smt_proof"; requestId: string; serialHex: string; issuer: SmtIssuer }
  | { type: "prove"; input: ProveInput }
  | { type: "cancel" };

export type Progress =
  // Setup-screen warmup events.
  | {
      step: "warmup";
      status: "in_progress" | "done";
      phase?: "init" | "threads" | "manifest" | "download" | "load";
      asset?: string;
      bytesDone?: number;
      bytesTotal?: number;
      kind?: Kind;
    }
  | { step: "warmup_done" }
  // Setup-screen revocation events.
  | {
      step: "smt_load";
      phase: SmtLoadPhase;
      issuer: SmtIssuer;
      bytesDone: number;
      bytesTotal: number;
    }
  | {
      step: "smt_ready";
      issuer: SmtIssuer;
      rootHex: string;
      crlNumber: string;
    }
  // SMT proof request/response.
  | { step: "smt_proof_done"; requestId: string; inputs: SmtCircuitInputs }
  | { step: "smt_proof_error"; requestId: string; message: string }
  // Proving-screen step events.
  | { step: "witness"; status: "in_progress" | "done"; kind?: Kind }
  | {
      step: "prove";
      status: "in_progress" | "done";
      kind?: Kind;
      phase?: "prep" | "prove";
    }
  | {
      step: "proving_complete";
      certProofBytes: Uint8Array;
      deviceProofBytes: Uint8Array;
      certKind: Kind;
      challenge: string;
      provingMs: number;
      /** Per-circuit timing breakdown for measurement logs. */
      certWitnessMs: number;
      certProveMs: number;
      deviceWitnessMs: number;
      deviceProveMs: number;
      threads: number;
    }
  | {
      step: "error";
      where: string;
      message: string;
      retryable: boolean;
      /** Set when `where === "manifest"` so the UI can paint a network-style copy. */
      kind?: "manifest";
      /** Discriminates manifest failures: 403/429 vs network vs malformed body. */
      manifestCode?: "rate_limited" | "unreachable" | "malformed" | "missing_asset";
    };

const KIND_ENUM: Record<Kind, CircuitKind> = {
  certChainRS2048: CircuitKind.CertChainRs2048,
  certChainRS4096: CircuitKind.CertChainRs4096,
  userSigRS2048: CircuitKind.UserSigRs2048,
};

const KIND_LABEL: Record<Kind, string> = {
  certChainRS2048: "certChainRS2048",
  certChainRS4096: "certChainRS4096",
  userSigRS2048: "userSigRS2048",
};

let cancelled = false;
let warming = false;
let proving = false;
let warmed = false;
let smtLoading = false;

// SMT load happens after warmup (issuer is known only post-card-read), so the
// digest map captured at warmup needs to survive across messages.
let smtDigests: DigestMap | null = null;

// Keep witness-wasm in memory after warmup.
const witnessCache: Partial<Record<Kind, Uint8Array>> = {};
// Engines are keyed per-issuer; once an issuer is loaded it is reused, and
// requests for other issuers are loaded on demand. In practice only one issuer
// is loaded per session (users don't swap MOICA-G2 for G3 mid-flow).
const smtEngines: Partial<Record<SmtIssuer, SmtEngine>> = {};

// tsconfig excludes WebWorker libs; use a minimal typed worker surface.
interface WorkerGlobal {
  onmessage: ((this: WorkerGlobal, ev: MessageEvent<WorkerInMsg>) => unknown) | null;
  postMessage(msg: Progress): void;
  navigator: { hardwareConcurrency?: number };
  location: { search?: string };
  crossOriginIsolated?: boolean;
}

const workerSelf: WorkerGlobal = self as unknown as WorkerGlobal;

workerSelf.onmessage = (ev: MessageEvent<WorkerInMsg>) => {
  const data = ev.data;
  if (!data || typeof data !== "object") return;
  if (data.type === "cancel") {
    cancelled = true;
    return;
  }
  if (data.type === "warmup") {
    if (warming || proving) return;
    warming = true;
    cancelled = false;
    runWarmup().finally(() => {
      warming = false;
    });
    return;
  }
  if (data.type === "load_smt") {
    if (smtLoading) return;
    if (smtEngines[data.issuer]) {
      // Re-emit ready for late subscribers (for example, remounted setup UI).
      const engine = smtEngines[data.issuer]!;
      post({
        step: "smt_ready",
        issuer: engine.issuer,
        rootHex: engine.rootHex,
        crlNumber: engine.crlNumber.toString(),
      });
      return;
    }
    smtLoading = true;
    runLoadSmt(data.issuer).finally(() => {
      smtLoading = false;
    });
    return;
  }
  if (data.type === "smt_proof") {
    runSmtProof(data.requestId, data.serialHex, data.issuer);
    return;
  }
  if (data.type === "prove") {
    if (warming || proving) return;
    if (!warmed) {
      postError("prove", new Error("Worker not warmed; run warmup first"));
      return;
    }
    proving = true;
    cancelled = false;
    runProve(data.input).finally(() => {
      proving = false;
    });
  }
};

function post(p: Progress): void {
  workerSelf.postMessage(p);
}

function clampThreads(): number {
  // If not cross-origin isolated, fall back to one thread.
  if (workerSelf.crossOriginIsolated !== true) return 1;
  const override = parseThreadOverride();
  if (override != null) return override;
  const hc = (workerSelf.navigator as Navigator | undefined)?.hardwareConcurrency;
  const raw = typeof hc === "number" && hc > 0 ? hc : 2;
  return Math.max(2, Math.min(16, raw));
}

function parseThreadOverride(): number | null {
  try {
    const loc = workerSelf.location;
    if (!loc || !loc.search) return null;
    const params = new URLSearchParams(loc.search);
    const t = params.get("threads");
    if (!t) return null;
    const n = Number.parseInt(t, 10);
    if (!Number.isFinite(n) || n < 1) return null;
    return Math.max(1, Math.min(32, n));
  } catch {
    return null;
  }
}

function errorMessage(err: unknown): string {
  if (err instanceof Error) return err.message;
  try {
    return String(err);
  } catch {
    return "unknown error";
  }
}

async function mapWithConcurrency<T>(
  items: T[],
  limit: number,
  fn: (item: T) => Promise<void>,
): Promise<void> {
  let next = 0;
  const workers = Array.from(
    { length: Math.min(limit, items.length) },
    async () => {
      while (true) {
        const i = next++;
        if (i >= items.length) return;
        await fn(items[i]);
      }
    },
  );
  await Promise.all(workers);
}

function postError(where: string, err: unknown): void {
  const msg: Extract<Progress, { step: "error" }> = {
    step: "error",
    where,
    message: errorMessage(err),
    retryable: true,
  };
  if (where === "manifest" || err instanceof ManifestError) {
    msg.kind = "manifest";
    if (err instanceof ManifestError) msg.manifestCode = err.code;
  }
  post(msg);
}

let activeThreads = 1;

async function runWarmup(): Promise<void> {
  try {
    post({ step: "warmup", status: "in_progress", phase: "init" });
    await init();
    await assetStore.purgePartials().catch((err) =>
      console.warn("purgePartials failed:", err),
    );
    if (cancelled) return;

    const threads = clampThreads();
    activeThreads = threads;
    post({ step: "warmup", status: "in_progress", phase: "threads" });
    if (threads > 1) await initThreadPool(threads);
    if (cancelled) return;

    post({ step: "warmup", status: "in_progress", phase: "manifest" });
    let digests;
    try {
      digests = await fetchReleaseDigests();
    } catch (err) {
      postError("manifest", err);
      return;
    }
    smtDigests = digests.smt;
    if (cancelled) return;

    const kinds: Kind[] = [
      "certChainRS2048",
      "certChainRS4096",
      "userSigRS2048",
    ];

    type Role = "pk" | "wgen";
    interface Job {
      kind: Kind;
      role: Role;
      url: string;
      key: string;
      sha: string;
    }
    const jobs: Job[] = kinds.flatMap((kind) => {
      const m = CIRCUITS[kind];
      const pkSha = requireDigest(digests.keys, basename(m.pkUrl));
      const wgenSha = requireDigest(digests.keys, basename(m.witnessWasmUrl));
      return [
        { kind, role: "pk" as const, url: m.pkUrl, key: `${kind}_pk_${pkSha}`, sha: pkSha },
        {
          kind,
          role: "wgen" as const,
          url: m.witnessWasmUrl,
          key: `${kind}_wgen_${wgenSha}`,
          sha: wgenSha,
        },
      ];
    });

    const pkBytes: Partial<Record<Kind, Uint8Array>> = {};
    const ROLE_LABEL: Record<Role, string> = { pk: "pk", wgen: "witness-wasm" };
    // 2 caps IDB-fallback heap (each writer buffers full decompressed bytes;
    // RS4096 PK ≈ 500 MB).
    const WARMUP_CONCURRENCY = 2;
    await mapWithConcurrency(jobs, WARMUP_CONCURRENCY, async (job) => {
      if (cancelled) return;
      const bytes = await ensureAsset(job.url, job.key, job.sha, (p) =>
        post({
          step: "warmup",
          status: "in_progress",
          phase: "download",
          asset: `${KIND_LABEL[job.kind]} ${ROLE_LABEL[job.role]}`,
          bytesDone: p.bytesDone,
          bytesTotal: p.bytesTotal,
          kind: job.kind,
        }),
      );
      if (job.role === "pk") pkBytes[job.kind] = bytes;
      else witnessCache[job.kind] = bytes;
    });
    if (cancelled) return;

    for (const kind of kinds) {
      post({ step: "warmup", status: "in_progress", phase: "load", kind });
      const pk = pkBytes[kind];
      if (!pk) throw new Error(`missing PK for ${kind}`);
      load_pk(KIND_ENUM[kind], pk);
      if (cancelled) return;
    }

    warmed = true;
    post({ step: "warmup", status: "done" });
    post({ step: "warmup_done" });
  } catch (err) {
    postError("warmup", err);
  }
}

async function runLoadSmt(issuer: SmtIssuer): Promise<void> {
  try {
    if (!smtDigests) {
      throw new Error(
        "SMT load requested before manifest hydration; warmup must complete first",
      );
    }
    const engine = await loadSmtEngine(
      issuer,
      smtDigests,
      (p) => {
        post({
          step: "smt_load",
          phase: p.phase,
          issuer,
          bytesDone: p.bytesDone,
          bytesTotal: p.bytesTotal,
        });
      },
    );
    smtEngines[issuer] = engine;
    post({
      step: "smt_ready",
      issuer: engine.issuer,
      rootHex: engine.rootHex,
      crlNumber: engine.crlNumber.toString(),
    });
  } catch (err) {
    postError("smt_load", err);
  }
}

function runSmtProof(requestId: string, serialHex: string, issuer: SmtIssuer): void {
  try {
    const engine = smtEngines[issuer];
    if (!engine) {
      throw new Error(`SMT engine for issuer ${issuer} not loaded; call load_smt first`);
    }
    const resp = engine.createProof(serialHex);
    const inputs = convertSmtProofToCircuitInputs(resp);
    post({ step: "smt_proof_done", requestId, inputs });
  } catch (err) {
    post({
      step: "smt_proof_error",
      requestId,
      message: errorMessage(err),
    });
  }
}

async function runProve(inputs: ProveInput): Promise<void> {
  const t0 = performance.now();
  try {
    const { certKind } = inputs;

    const certWgen = witnessCache[certKind];
    if (!certWgen) throw new Error(`warmup did not cache witness-wasm for ${certKind}`);
    const deviceWgen = witnessCache["userSigRS2048"];
    if (!deviceWgen)
      throw new Error("warmup did not cache witness-wasm for userSigRS2048");

    post({ step: "witness", status: "in_progress", kind: certKind });
    const certWitnessStart = performance.now();
    const certWtns = await calculateWitness(certKind, inputs.certJson, certWgen);
    const certWitnessMs = performance.now() - certWitnessStart;
    if (cancelled) return;
    post({ step: "witness", status: "done", kind: certKind });

    post({ step: "prove", status: "in_progress", kind: certKind, phase: "prep" });
    const certProveStart = performance.now();
    const certProofOut = prove(KIND_ENUM[certKind], certWtns) as {
      proof: ArrayLike<number>;
    };
    const certProveMs = performance.now() - certProveStart;
    post({ step: "prove", status: "done", kind: certKind, phase: "prove" });
    if (cancelled) return;

    post({
      step: "witness",
      status: "in_progress",
      kind: "userSigRS2048",
    });
    const deviceWitnessStart = performance.now();
    const deviceWtns = await calculateWitness(
      "userSigRS2048",
      inputs.deviceJson,
      deviceWgen,
    );
    const deviceWitnessMs = performance.now() - deviceWitnessStart;
    if (cancelled) return;
    post({ step: "witness", status: "done", kind: "userSigRS2048" });

    post({
      step: "prove",
      status: "in_progress",
      kind: "userSigRS2048",
      phase: "prep",
    });
    const deviceProveStart = performance.now();
    const deviceProofOut = prove(KIND_ENUM["userSigRS2048"], deviceWtns) as {
      proof: ArrayLike<number>;
    };
    const deviceProveMs = performance.now() - deviceProveStart;
    post({
      step: "prove",
      status: "done",
      kind: "userSigRS2048",
      phase: "prove",
    });
    if (cancelled) return;

    const certProofBytes = new Uint8Array(certProofOut.proof);
    const deviceProofBytes = new Uint8Array(deviceProofOut.proof);
    post({
      step: "proving_complete",
      certProofBytes,
      deviceProofBytes,
      certKind,
      challenge: inputs.challenge,
      provingMs: performance.now() - t0,
      certWitnessMs,
      certProveMs,
      deviceWitnessMs,
      deviceProveMs,
      threads: activeThreads,
    });
  } catch (err) {
    postError("prove", err);
  }
}
