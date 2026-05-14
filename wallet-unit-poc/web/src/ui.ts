// Reactive step-indicator store + DOM renderer for the proving screen.
//
// Six steps (challenge → sign → smt → build → prove cert-chain →
// prove user-sig). Steps 1–4 are main-thread pipeline stages; steps 5–6
// are Worker progress events. Per-step durations are recorded between the
// first `in_progress` and the `done` transition so the row can display them.

import { atom, type WritableAtom } from "nanostores";

import { formatDuration } from "./format";

export type Step =
  | "challenge"
  | "sign"
  | "smt"
  | "build"
  | "prove_cert"
  | "prove_user_sig";

export type StepStatus = "pending" | "in_progress" | "done" | "error";

export interface StepState {
  status: StepStatus;
  label?: string;
  error?: string;
  durationMs?: number;
}

export type StepAtom = WritableAtom<StepState>;

export const STEP_ORDER: Step[] = [
  "challenge",
  "sign",
  "smt",
  "build",
  "prove_cert",
  "prove_user_sig",
];

const STEP_TITLES: Record<Step, string> = {
  challenge: "Fetch challenge",
  sign: "Sign with card",
  smt: "Check revocation locally",
  build: "Build circuit inputs",
  prove_cert: "Prove cert-chain",
  prove_user_sig: "Prove user-sig",
};

export const steps: Record<Step, StepAtom> = {
  challenge: atom<StepState>({ status: "pending" }),
  sign: atom<StepState>({ status: "pending" }),
  smt: atom<StepState>({ status: "pending" }),
  build: atom<StepState>({ status: "pending" }),
  prove_cert: atom<StepState>({ status: "pending" }),
  prove_user_sig: atom<StepState>({ status: "pending" }),
};

export type ResultState =
  | { kind: "idle" }
  | { kind: "running" }
  | { kind: "error"; message: string };

export const result = atom<ResultState>({ kind: "idle" });

const stepStartedAt: Partial<Record<Step, number>> = {};

export function markInProgress(step: Step, label?: string): void {
  if (stepStartedAt[step] == null) {
    stepStartedAt[step] = performance.now();
  }
  const cur = steps[step].get();
  steps[step].set({
    status: "in_progress",
    label,
    durationMs: cur.durationMs,
  });
}

/** Mark a step `done` and record its elapsed time since the first
 *  `in_progress`. If `markInProgress` was never called (e.g., an upstream
 *  `in_progress` event was swallowed by a race), `durationMs` is left
 *  undefined so the row just shows the label. */
export function markDone(step: Step, label?: string): void {
  const start = stepStartedAt[step];
  const durationMs = start != null ? performance.now() - start : undefined;
  steps[step].set({
    status: "done",
    label,
    durationMs,
  });
}

export function markError(step: Step, message: string): void {
  delete stepStartedAt[step];
  steps[step].set({ status: "error", error: message });
}

function stepRowMarkup(step: Step): string {
  const title = STEP_TITLES[step];
  return (
    `<li class="step" data-testid="step-${step}" data-status="pending">` +
    `<span class="step-icon" aria-hidden="true"></span>` +
    `<span class="step-title">${title}</span>` +
    `<span class="step-label" data-testid="step-${step}-label"></span>` +
    `</li>`
  );
}

function paintStepRow(li: HTMLElement, state: StepState): void {
  li.dataset.status = state.status;
  const labelEl = li.querySelector<HTMLElement>(".step-label");
  if (!labelEl) return;
  if (state.status === "error" && state.error) {
    labelEl.textContent = state.error;
    return;
  }
  const parts: string[] = [];
  if (state.label) parts.push(state.label);
  if (state.status === "done" && state.durationMs != null) {
    parts.push(formatDuration(state.durationMs));
  }
  labelEl.textContent = parts.join(" — ");
}

function paintResult(el: HTMLElement, state: ResultState): void {
  el.dataset.kind = state.kind;
  el.textContent = "";
  if (state.kind === "idle") return;

  if (state.kind === "running") {
    const span = document.createElement("span");
    span.className = "result-line";
    span.textContent = "Proving…";
    el.appendChild(span);
    return;
  }

  // Error path: assign upstream text via textContent so injected markup
  // (HiPKI / verifier / input-build responses) can't reach the DOM as HTML.
  const head = document.createElement("div");
  head.className = "result-line";
  head.dataset.testid = "step-error";
  head.textContent = "Error";
  const body = document.createElement("div");
  body.className = "result-line";
  body.textContent = state.message;
  el.append(head, body);
}

/** Render the step list + result banner. Returns a dispose() that detaches
 *  every atom subscription. */
export function mountSteps(
  listEl: HTMLOListElement,
  resultEl: HTMLElement,
): () => void {
  listEl.innerHTML = STEP_ORDER.map(stepRowMarkup).join("");
  resultEl.dataset.kind = "idle";
  resultEl.innerHTML = "";

  const disposers: Array<() => void> = [];
  for (const step of STEP_ORDER) {
    const li = listEl.querySelector<HTMLElement>(`[data-testid="step-${step}"]`);
    if (!li) continue;
    const unsub = steps[step].listen((s) => paintStepRow(li, s));
    paintStepRow(li, steps[step].get());
    disposers.push(unsub);
  }
  const unsubResult = result.listen((r) => paintResult(resultEl, r));
  paintResult(resultEl, result.get());
  disposers.push(unsubResult);

  return () => {
    for (const d of disposers) d();
  };
}

/** Reset step atoms to "pending", result to "idle", and clear timing state. */
export function resetUi(): void {
  for (const step of STEP_ORDER) {
    steps[step].set({ status: "pending" });
    delete stepStartedAt[step];
  }
  result.set({ kind: "idle" });
}
