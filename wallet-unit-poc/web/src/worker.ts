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
  CIRCUITS,
  hydrateManifest,
  type CircuitKind as Kind,
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
  challengeId: string;
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
      challengeId: string;
      provingMs: number;
      /** Per-circuit timing breakdown for measurement logs. */
      certWitnessMs: number;
      certProveMs: number;
      deviceWitnessMs: number;
      deviceProveMs: number;
      threads: number;
    }
  | { step: "error"; where: string; message: string; retryable: boolean };

const KIND_ENUM: Record<Kind, CircuitKind> = {
  cert_chain_rs2048: CircuitKind.CertChainRs2048,
  cert_chain_rs4096: CircuitKind.CertChainRs4096,
  device_sig_rs2048: CircuitKind.DeviceSigRs2048,
};

const KIND_LABEL: Record<Kind, string> = {
  cert_chain_rs2048: "cert_chain_rs2048",
  cert_chain_rs4096: "cert_chain_rs4096",
  device_sig_rs2048: "device_sig_rs2048",
};

let cancelled = false;
let warming = false;
let proving = false;
let warmed = false;
let smtLoading = false;

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

function postError(where: string, err: unknown): void {
  post({
    step: "error",
    where,
    message: errorMessage(err),
    retryable: true,
  });
}

let activeThreads = 1;

async function runWarmup(): Promise<void> {
  try {
    post({ step: "warmup", status: "in_progress", phase: "init" });
    await init();
    if (cancelled) return;

    const threads = clampThreads();
    activeThreads = threads;
    post({ step: "warmup", status: "in_progress", phase: "threads" });
    if (threads > 1) await initThreadPool(threads);
    if (cancelled) return;

    post({ step: "warmup", status: "in_progress", phase: "manifest" });
    await hydrateManifest();
    if (cancelled) return;

    // Preload all PK + witness assets so proving starts without extra waits.
    const kinds: Kind[] = [
      "cert_chain_rs2048",
      "cert_chain_rs4096",
      "device_sig_rs2048",
    ];
    for (const kind of kinds) {
      const m = CIRCUITS[kind];
      await ensureAsset(m.pkUrl, `${kind}_pk`, m.expected.pk, (p) =>
        post({
          step: "warmup",
          status: "in_progress",
          phase: "download",
          asset: `${KIND_LABEL[kind]} pk`,
          bytesDone: p.bytesDone,
          bytesTotal: p.bytesTotal,
          kind,
        }),
      );
      if (cancelled) return;
      await ensureAsset(
        m.witnessWasmUrl,
        `${kind}_wgen`,
        m.expected.witnessWasm,
        (p) =>
          post({
            step: "warmup",
            status: "in_progress",
            phase: "download",
            asset: `${KIND_LABEL[kind]} witness-wasm`,
            bytesDone: p.bytesDone,
            bytesTotal: p.bytesTotal,
            kind,
          }),
      );
      if (cancelled) return;
    }

    // Load PKs and cache witness-wasm bytes.
    for (const kind of kinds) {
      post({ step: "warmup", status: "in_progress", phase: "load", kind });
      const pk = await assetStore.get(`${kind}_pk`);
      if (!pk) throw new Error(`missing cached PK for ${kind}`);
      load_pk(KIND_ENUM[kind], pk);
      const wgen = await assetStore.get(`${kind}_wgen`);
      if (!wgen) throw new Error(`missing cached witness-wasm for ${kind}`);
      witnessCache[kind] = wgen;
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
    const engine = await loadSmtEngine(issuer, (p) => {
      post({
        step: "smt_load",
        phase: p.phase,
        issuer,
        bytesDone: p.bytesDone,
        bytesTotal: p.bytesTotal,
      });
    });
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
    const deviceWgen = witnessCache["device_sig_rs2048"];
    if (!deviceWgen)
      throw new Error("warmup did not cache witness-wasm for device_sig_rs2048");

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
      kind: "device_sig_rs2048",
    });
    const deviceWitnessStart = performance.now();
    const deviceWtns = await calculateWitness(
      "device_sig_rs2048",
      inputs.deviceJson,
      deviceWgen,
    );
    const deviceWitnessMs = performance.now() - deviceWitnessStart;
    if (cancelled) return;
    post({ step: "witness", status: "done", kind: "device_sig_rs2048" });

    post({
      step: "prove",
      status: "in_progress",
      kind: "device_sig_rs2048",
      phase: "prep",
    });
    const deviceProveStart = performance.now();
    const deviceProofOut = prove(KIND_ENUM["device_sig_rs2048"], deviceWtns) as {
      proof: ArrayLike<number>;
    };
    const deviceProveMs = performance.now() - deviceProveStart;
    post({
      step: "prove",
      status: "done",
      kind: "device_sig_rs2048",
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
      challengeId: inputs.challengeId,
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
