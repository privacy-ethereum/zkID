// Result screen for both terminal `result` and `error` phases.

import { clearAllAssets } from "../asset-store";
import { escapeText } from "../dom-utils";
import { formatDuration, truncateMiddle } from "../format";
import { $state, dispatch } from "../store";
import type { ParsedInputs } from "../verifier-client";

const shortHex = (h: string): string => truncateMiddle(h, 10, 6);

export function mountResult(root: HTMLElement): () => void {
  const state = $state.get();
  const isResult = state.phase === "result";
  const isError = state.phase === "error";

  let headline: string;
  let detail: string;
  let tone: "done" | "error" = "done";
  let testidBadge: string;

  if (isResult) {
    const total = state.provingMs + state.submitMs;
    if (state.verified) {
      headline = "Proof verified";
      detail = `Verified in ${formatDuration(total)} — proving ${formatDuration(state.provingMs)} + submit ${formatDuration(state.submitMs)}.`;
      testidBadge = "result-verified";
    } else {
      headline = "Proof rejected";
      detail = `Verifier responded in ${formatDuration(state.submitMs)} — not verified.`;
      tone = "error";
      testidBadge = "result-not-verified";
    }
  } else if (isError) {
    headline = "Error";
    detail = `${state.where}: ${state.message}`;
    tone = "error";
    testidBadge = "result-error";
  } else {
    // Defensive fallback; router guards should prevent this branch.
    headline = "";
    detail = "";
    testidBadge = "result-unknown";
  }

  const parsedBlock =
    isResult && state.verified
      ? renderParsedInputs(state.nullifier, state.parsedInputs)
      : "";

  root.innerHTML = `
    <section class="screen screen-result">
      <h1 data-testid="result-headline">${headline}</h1>
      <div class="result-banner" data-kind="${tone}" data-testid="${testidBadge}">
        <div class="result-line" data-testid="result-detail"></div>
      </div>
      ${parsedBlock}
      <div class="button-row">
        <button class="secondary-button" data-testid="result-clear-cache" type="button">
          Clear cached assets
        </button>
        <button class="secondary-button" data-testid="result-home" type="button">
          Home
        </button>
        <button class="primary-button" data-testid="result-prove-again" type="button">
          Prove again
        </button>
      </div>
    </section>
  `;

  root.querySelector<HTMLElement>('[data-testid="result-detail"]')!.textContent = detail;

  const homeBtn = root.querySelector<HTMLButtonElement>('[data-testid="result-home"]')!;
  const againBtn = root.querySelector<HTMLButtonElement>('[data-testid="result-prove-again"]')!;
  const clearBtn = root.querySelector<HTMLButtonElement>('[data-testid="result-clear-cache"]')!;

  // `result` retries from setup (PIN must be re-verified); `error` resets home.
  const onAgain = () => {
    if (isError) dispatch({ type: "reset" });
    else dispatch({ type: "retry_proving" });
  };
  const onHome = () => dispatch({ type: "reset" });

  // Reload so the worker's in-memory PK / witness cache drops with disk.
  const onClear = async () => {
    if (clearBtn.disabled) return;
    clearBtn.disabled = true;
    homeBtn.disabled = true;
    againBtn.disabled = true;
    const priorLabel = clearBtn.textContent;
    clearBtn.textContent = "Clearing…";
    try {
      await clearAllAssets();
      window.location.reload();
    } catch (err) {
      console.error("clearAllAssets failed:", err);
      clearBtn.textContent = priorLabel;
      clearBtn.disabled = false;
      homeBtn.disabled = false;
      againBtn.disabled = false;
    }
  };
  const onClearClick = () => void onClear();

  againBtn.addEventListener("click", onAgain);
  homeBtn.addEventListener("click", onHome);
  clearBtn.addEventListener("click", onClearClick);

  return () => {
    againBtn.removeEventListener("click", onAgain);
    homeBtn.removeEventListener("click", onHome);
    clearBtn.removeEventListener("click", onClearClick);
  };
}

function debugRow(label: string, testid: string, value: string): string {
  return `<div class="debug-row"><span class="debug-label">${label}</span><span class="debug-value mono" data-testid="${testid}">${escapeText(value)}</span></div>`;
}

function formatModulus(limbs: string[] | undefined): string {
  if (!limbs || limbs.length === 0) return "—";
  return `${limbs.length} limbs — ${shortHex(limbs[0])} …`;
}

// Scalar ParsedInputs fields shown as rows; modulus is rendered separately.
const PARSED_FIELDS = [
  "nullifier",
  "pk_commit",
  "smt_root",
  "challenge",
] as const satisfies ReadonlyArray<keyof ParsedInputs>;

function renderParsedInputs(
  nullifier: string | undefined,
  parsed: ParsedInputs | undefined,
): string {
  if (!nullifier && !parsed) return "";
  const rows: string[] = [];
  if (nullifier) {
    rows.push(debugRow("nullifier", "result-nullifier", shortHex(nullifier)));
  }
  if (parsed) {
    for (const key of PARSED_FIELDS) {
      rows.push(debugRow(key, `result-${key.replace(/_/g, "-")}`, shortHex(parsed[key])));
    }
    rows.push(
      debugRow("issuer_rsa_modulus", "result-issuer-modulus", formatModulus(parsed.issuer_rsa_modulus)),
    );
  }
  return `
    <details class="debug-block" data-testid="result-debug">
      <summary>Proof public inputs</summary>
      <div class="debug-grid">
        ${rows.join("\n        ")}
      </div>
    </details>
  `;
}
