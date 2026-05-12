// Entry point for `/prove`.
// Consumes `ProveInput` from sessionStorage, runs proving with a fresh Worker,
// and drives proving → review → submitting → result.

import "./style.css";
import { markPriorStepsDone } from "./progress";
import { mountRouter } from "./router";
import { clearProveInput, consumeProveInput } from "./storage-handoff";
import { dispatch, $state, type AppState } from "./store";
import { resetUi, result } from "./ui";
import { submitLinkVerify } from "./verifier-client";
import { createWorkerLifecycle } from "./worker-lifecycle";
import type { Progress, WorkerInMsg } from "./worker";

function boot(): void {
  const root = document.querySelector<HTMLElement>("#app");
  if (!root) {
    throw new Error("prove-main.ts: #app root missing in prove.html");
  }

  const proveInput = consumeProveInput();
  if (!proveInput) {
    // No handoff (direct nav/refresh). Restart from `/`.
    clearProveInput();
    window.location.replace("/");
    return;
  }

  // Initialize state before subscriptions to avoid landing flash.
  // Sign-phase steps already completed on `/`, so mark them done up front.
  resetUi();
  markPriorStepsDone("prove_cert");
  result.set({ kind: "running" });
  $state.set({ phase: "proving", startedAt: performance.now() });

  let submitController: AbortController | null = null;
  let postedProve = false;
  let disposeRouter: (() => void) | null = null;
  let redirected = false;

  const { ensureWorker, terminateWorker } = createWorkerLifecycle({
    onProgress: (data, w) => {
      if (data.step === "warmup_done" && !postedProve) {
        postedProve = true;
        const msg: WorkerInMsg = { type: "prove", input: proveInput };
        w.postMessage(msg);
        return;
      }
      if (data.step === "proving_complete") {
        logProvingComplete(data);
      }
    },
  });

  function cancelActiveSubmit(): void {
    submitController?.abort();
    submitController = null;
  }

  // `/prove` cannot render sign-phase screens; redirect transitions to `/`.
  function sendUserBackToSign(): void {
    if (redirected) return;
    redirected = true;
    disposeRouter?.();
    disposeRouter = null;
    terminateWorker();
    clearProveInput();
    window.location.replace("/");
  }

  // Listen before router mount to intercept setup/landing transitions early.
  $state.listen(async (state) => {
    if (redirected) return;
    if (state.phase !== "submitting") cancelActiveSubmit();

    switch (state.phase) {
      case "proving":
      case "review":
        // Keep Worker alive across review for retry/submit.
        return;
      case "submitting":
        await handleSubmittingPhase(state);
        return;
      case "result":
        terminateWorker();
        return;
      case "setup":
      case "landing":
        sendUserBackToSign();
        return;
      case "error":
        terminateWorker();
        return;
    }
  });

  disposeRouter = mountRouter(root);

  async function handleSubmittingPhase(
    state: Extract<AppState, { phase: "submitting" }>,
  ): Promise<void> {
    cancelActiveSubmit();
    submitController = new AbortController();
    const mine = submitController;
    const t0 = performance.now();
    try {
      const res = await submitLinkVerify(
        {
          certChainType: state.run.certChainType,
          certChainProofBytes: state.run.certProofBytes,
          userSigProofBytes: state.run.deviceProofBytes,
        },
        { signal: mine.signal },
      );
      const submitMs = performance.now() - t0;
      dispatch({
        type: "submit_complete",
        verified: res.verified,
        submitMs,
        nullifier: res.verified ? res.nullifier : undefined,
        parsedInputs: res.parsed_inputs,
      });
    } catch (err) {
      if (err instanceof DOMException && err.name === "AbortError") return;
      const message = err instanceof Error ? err.message : String(err);
      dispatch({ type: "pipeline_error", where: "submit", message });
    } finally {
      if (submitController === mine) submitController = null;
    }
  }

  const warmupMsg: WorkerInMsg = { type: "warmup" };
  ensureWorker().postMessage(warmupMsg);
}

// Emit one proving timing record for quick before/after comparisons.
function logProvingComplete(
  data: Extract<Progress, { step: "proving_complete" }>,
): void {
  console.info("[zkid] proving_complete", {
    crossOriginIsolated: globalThis.crossOriginIsolated,
    hardwareConcurrency: navigator.hardwareConcurrency,
    threads: data.threads,
    provingMs: Math.round(data.provingMs),
    certWitnessMs: Math.round(data.certWitnessMs),
    certProveMs: Math.round(data.certProveMs),
    deviceWitnessMs: Math.round(data.deviceWitnessMs),
    deviceProveMs: Math.round(data.deviceProveMs),
  });
}

boot();
