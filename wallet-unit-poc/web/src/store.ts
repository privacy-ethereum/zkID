// App-level finite state machine.
//
// Flow: landing → setup → ready → proving → review → submitting → result.
// Each arrow is driven by an explicit user action. This store owns phase
// transitions and the transient ProvingRun blob that carries proof bytes
// from `proving` through `review` / `submitting`. Per-step progress atoms
// live in `ui.ts`.
//
// The `/prove` document bootstraps by writing `$state` directly to
// `proving` (see prove-main.ts) — it receives a ProveInput via
// sessionStorage from the `/` document and never goes through the usual
// landing → setup → ready → proving sequence. The reducer below still
// governs every subsequent transition on /prove.

import { atom, type WritableAtom } from "nanostores";

import type { CircuitKind } from "./manifest";
import type { ParsedInputs } from "./verifier-client";

export interface ProvingRun {
  /** Verifier-issued per-session field element (decimal string). Held only
   *  for review-screen display; the proof itself is the source of truth. */
  challenge: string;
  certChainType: "rs2048" | "rs4096";
  certProofBytes: Uint8Array;
  deviceProofBytes: Uint8Array;
  certKind: CircuitKind;
  provingMs: number;
}

export type AppState =
  | { phase: "landing" }
  | { phase: "setup" }
  | { phase: "ready" }
  | { phase: "proving"; startedAt: number }
  | { phase: "review"; run: ProvingRun }
  | { phase: "submitting"; run: ProvingRun; startedAt: number }
  | {
      phase: "result";
      verified: boolean;
      provingMs: number;
      submitMs: number;
      nullifier?: string;
      parsedInputs?: ParsedInputs;
    }
  | { phase: "error"; where: string; message: string };

export type AppEvent =
  | { type: "start" }
  | { type: "setup_complete" }
  | { type: "start_proving" }
  | { type: "proving_complete"; run: ProvingRun }
  | { type: "send_proof" }
  | {
      type: "submit_complete";
      verified: boolean;
      submitMs: number;
      nullifier?: string;
      parsedInputs?: ParsedInputs;
    }
  | { type: "retry_proving" }
  | { type: "reset_to_setup" }
  | { type: "pipeline_error"; where: string; message: string }
  | { type: "reset" };

/** Pure reducer. Invalid transitions return the current state unchanged. */
export function transition(state: AppState, event: AppEvent): AppState {
  switch (event.type) {
    case "start":
      return state.phase === "landing" ? { phase: "setup" } : state;
    case "setup_complete":
      return state.phase === "setup" ? { phase: "ready" } : state;
    case "start_proving":
      return state.phase === "ready"
        ? { phase: "proving", startedAt: performance.now() }
        : state;
    case "proving_complete":
      return state.phase === "proving"
        ? { phase: "review", run: event.run }
        : state;
    case "send_proof":
      return state.phase === "review"
        ? {
            phase: "submitting",
            run: state.run,
            startedAt: performance.now(),
          }
        : state;
    case "submit_complete":
      return state.phase === "submitting"
        ? {
            phase: "result",
            verified: event.verified,
            provingMs: state.run.provingMs,
            submitMs: event.submitMs,
            nullifier: event.nullifier,
            parsedInputs: event.parsedInputs,
          }
        : state;
    case "retry_proving":
      // Route to setup (not ready) because the session Pin was consumed
      // during the proving run and needs to be re-verified. The card +
      // warm-runtime panels stay green; the PIN panel resets to pending
      // so the user explicitly re-enters the PIN before the next run.
      // Strict single-use protects against a compromised session
      // extracting the PIN after the first sign.
      return state.phase === "review" || state.phase === "result"
        ? { phase: "setup" }
        : state;
    case "reset_to_setup":
      // "Back to setup" from ready/review and "Cancel" from proving. Setup
      // atoms ($hipki/$pin) are preserved; resetSetup() only fires on
      // reset → landing.
      switch (state.phase) {
        case "ready":
        case "review":
        case "proving":
          return { phase: "setup" };
        default:
          return state;
      }
    case "pipeline_error":
      // Only route errors from active phases. Landing / result / error
      // are terminal — errors from those states are ignored.
      switch (state.phase) {
        case "setup":
        case "ready":
        case "proving":
        case "review":
        case "submitting":
          return { phase: "error", where: event.where, message: event.message };
        default:
          return state;
      }
    case "reset":
      return { phase: "landing" };
  }
}

export type AppStateAtom = WritableAtom<AppState>;

export const $state: AppStateAtom = atom<AppState>({ phase: "landing" });

export function dispatch(event: AppEvent): void {
  $state.set(transition($state.get(), event));
}
