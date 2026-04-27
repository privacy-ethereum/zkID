// Translates Worker Progress events into UI atom updates and FSM dispatches.
// Warmup events feed `$warmup` (setup Assets panel); proving events feed
// the 6-step list + `result`. `proving_complete` carries proof bytes that
// the FSM packages into a ProvingRun for the Review screen.

import { humanBytes } from "./format";
import type { CircuitKind as Kind } from "./manifest";
import { $smt, $warmup } from "./setup-state";
import { dispatch } from "./store";
import {
  STEP_ORDER,
  markDone,
  markError,
  markInProgress,
  result,
  steps,
  type Step,
} from "./ui";
import type { Progress } from "./worker";

const KIND_LABEL: Record<Kind, string> = {
  cert_chain_rs2048: "cert_chain_rs2048",
  cert_chain_rs4096: "cert_chain_rs4096",
  device_sig_rs2048: "device_sig_rs2048",
};

type WarmupEvent = Extract<Progress, { step: "warmup" }>;
type WitnessEvent = Extract<Progress, { step: "witness" }>;
type ProveEvent = Extract<Progress, { step: "prove" }>;
type ProvingCompleteEvent = Extract<Progress, { step: "proving_complete" }>;
type ErrorEvent = Extract<Progress, { step: "error" }>;

function warmupSublabel(p: WarmupEvent): string {
  switch (p.phase) {
    case "init":
      return "initializing wasm runtime";
    case "threads":
      return "starting thread pool";
    case "manifest":
      return "loading manifest";
    case "download": {
      const done = humanBytes(p.bytesDone);
      const total = humanBytes(p.bytesTotal);
      const asset = p.asset ?? "asset";
      if (done && total) return `downloading ${asset} — ${done} / ${total}`;
      if (done) return `downloading ${asset} — ${done}`;
      return `downloading ${asset}`;
    }
    case "load":
      return p.kind ? `loading ${KIND_LABEL[p.kind]}` : "loading proving keys";
    default:
      return "";
  }
}

export function markPriorStepsDone(step: Step): void {
  for (const s of STEP_ORDER) {
    if (s === step) return;
    const cur = steps[s].get();
    if (cur.status === "pending" || cur.status === "in_progress") {
      markDone(s, cur.label);
    }
  }
}

function applyWitness(p: WitnessEvent): void {
  if (!p.kind) return;
  const step: Step = p.kind === "device_sig_rs2048" ? "prove_device" : "prove_cert";
  if (p.status === "in_progress") {
    markPriorStepsDone(step);
    markInProgress(step, "witness");
  }
  // `done` for witness is a sub-phase; the subsequent `prove` in_progress
  // event overwrites the label.
}

function applyProve(p: ProveEvent): void {
  if (!p.kind) return;
  const step: Step = p.kind === "device_sig_rs2048" ? "prove_device" : "prove_cert";
  if (p.status === "in_progress") {
    markPriorStepsDone(step);
    markInProgress(step, p.phase === "prep" ? "prep" : "proving");
  } else {
    markDone(step);
  }
}

export function applyProgress(p: Progress): void {
  switch (p.step) {
    case "warmup": {
      $warmup.set({
        status: "running",
        sublabel: warmupSublabel(p),
        bytesDone: p.bytesDone,
        bytesTotal: p.bytesTotal,
      });
      return;
    }
    case "warmup_done": {
      $warmup.set({ status: "ready" });
      return;
    }
    case "smt_load": {
      $smt.set({
        status: "running",
        issuer: p.issuer,
        phase: p.phase,
        bytesDone: p.bytesDone,
        bytesTotal: p.bytesTotal,
      });
      return;
    }
    case "smt_ready": {
      $smt.set({
        status: "ready",
        issuer: p.issuer,
        rootHex: p.rootHex,
        crlNumber: p.crlNumber,
      });
      return;
    }
    case "smt_proof_done":
    case "smt_proof_error":
      // Routed via addEventListener on the main thread (smt-client.ts).
      // No UI side effect needed here.
      return;
    case "witness": {
      applyWitness(p);
      return;
    }
    case "prove": {
      applyProve(p);
      return;
    }
    case "proving_complete": {
      const done = p as ProvingCompleteEvent;
      // Backstop: mark every step done so the UI is consistent even if a
      // per-step event was dropped or raced before teardown.
      for (const s of STEP_ORDER) {
        const cur = steps[s].get();
        if (cur.status !== "error") markDone(s, cur.label);
      }
      dispatch({
        type: "proving_complete",
        run: {
          challengeId: done.challengeId,
          certChainType:
            done.certKind === "cert_chain_rs4096" ? "rs4096" : "rs2048",
          certProofBytes: done.certProofBytes,
          deviceProofBytes: done.deviceProofBytes,
          certKind: done.certKind,
          provingMs: done.provingMs,
        },
      });
      return;
    }
    case "error": {
      const e = p as ErrorEvent;
      // Warmup / manifest errors route to $warmup (Assets panel); SMT engine
      // load errors route to $smt; proving errors land on whichever proving
      // step is live.
      if (e.where === "manifest") {
        $warmup.set({
          status: "error",
          message: e.message,
          kind: "manifest",
          manifestCode: e.manifestCode,
        });
        return;
      }
      if (e.where === "warmup") {
        $warmup.set({ status: "error", message: e.message, kind: "warmup" });
        return;
      }
      if (e.where === "smt_load") {
        $smt.set({ status: "error", message: e.message });
        return;
      }
      let target: Step | undefined;
      for (const s of STEP_ORDER) {
        if (steps[s].get().status === "in_progress") {
          target = s;
          break;
        }
      }
      if (!target) {
        for (const s of STEP_ORDER) {
          if (steps[s].get().status === "pending") {
            target = s;
            break;
          }
        }
      }
      if (target) markError(target, e.message);
      result.set({ kind: "error", message: `${e.where}: ${e.message}` });
      dispatch({
        type: "pipeline_error",
        where: e.where,
        message: e.message,
      });
      return;
    }
  }
}
