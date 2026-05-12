// Ready screen: user-gated checkpoint between setup and proving.
//
// Shows a summary (card, cert-chain type, warmup, PIN lock, challenge) so
// the user can confirm state before the HiPKI popup appears.
//
// Pre-fetches the challenge on mount so the Start-proving click reaches
// window.open with the user-activation window still live. Fetching
// inside the click handler would await a network response first and get
// the HiPKI popup blocked by every modern browser.

import { $challenge, type ChallengeState } from "../challenge-state";
import { $hipki, $pin, $warmup } from "../setup-state";
import { dispatch } from "../store";
import { createChallenge } from "../verifier-client";

export function startButtonStateFor(
  c: ChallengeState,
): { disabled: boolean; label: string } {
  switch (c.status) {
    case "pending":
    case "fetching":
      return { disabled: true, label: "Fetching challenge…" };
    case "ready":
      return { disabled: false, label: "Start proving" };
    case "error":
      return { disabled: false, label: "Retry challenge" };
  }
}

export function mountReady(root: HTMLElement): () => void {
  root.innerHTML = `
    <section class="screen screen-ready">
      <h1>Ready to prove</h1>
      <p class="intro">
        Everything is prepared. Proving fetches a fresh challenge, signs it
        on the card, fetches the revocation proof, then runs both circuits
        locally in your browser. No personal data leaves this device.
      </p>
      <div class="ready-summary" data-testid="ready-summary">
        <div class="ready-row">
          <span class="ready-label">Card</span>
          <span class="ready-value" data-testid="ready-card">—</span>
        </div>
        <div class="ready-row">
          <span class="ready-label">Cert chain</span>
          <span class="ready-value" data-testid="ready-cert-chain">—</span>
        </div>
        <div class="ready-row">
          <span class="ready-label">Runtime</span>
          <span class="ready-value" data-testid="ready-runtime">—</span>
        </div>
        <div class="ready-row">
          <span class="ready-label">PIN</span>
          <span class="ready-value" data-testid="ready-pin">—</span>
        </div>
        <div class="ready-row">
          <span class="ready-label">Challenge</span>
          <span class="ready-value" data-testid="ready-challenge">—</span>
        </div>
      </div>
      <div class="button-row">
        <button class="secondary-button" data-testid="ready-back" type="button">
          Back to setup
        </button>
        <button class="primary-button" data-testid="start-proving" type="button" disabled>
          Start proving
        </button>
      </div>
    </section>
  `;

  const cardEl = root.querySelector<HTMLElement>('[data-testid="ready-card"]')!;
  const chainEl = root.querySelector<HTMLElement>('[data-testid="ready-cert-chain"]')!;
  const runtimeEl = root.querySelector<HTMLElement>('[data-testid="ready-runtime"]')!;
  const pinEl = root.querySelector<HTMLElement>('[data-testid="ready-pin"]')!;
  const challengeEl = root.querySelector<HTMLElement>('[data-testid="ready-challenge"]')!;
  const backBtn = root.querySelector<HTMLButtonElement>('[data-testid="ready-back"]')!;
  const startBtn = root.querySelector<HTMLButtonElement>('[data-testid="start-proving"]')!;

  let fetchController: AbortController | null = null;

  function paint(): void {
    const hipki = $hipki.get();
    const pinState = $pin.get();
    const warmup = $warmup.get();
    const challenge = $challenge.get();

    if (hipki.status === "card_ready") {
      const dn = hipki.subjectDN ? ` — ${hipki.subjectDN}` : "";
      cardEl.textContent = `${hipki.cardSN}${dn}`;
      const chainKind = hipki.card.certKind === "certChainRS4096" ? "RSA-4096 (MOICA-G3)" : "RSA-2048 (MOICA-G2)";
      chainEl.textContent = chainKind;
    } else {
      cardEl.textContent = "Not ready";
      chainEl.textContent = "—";
    }

    runtimeEl.textContent =
      warmup.status === "ready" ? "Ready" : `Status: ${warmup.status}`;

    pinEl.textContent =
      pinState.status === "locked"
        ? "Verified and locked"
        : `Status: ${pinState.status}`;

    if (challenge.status === "ready") {
      const { challenge: decimal } = challenge.challenge;
      challengeEl.textContent = `${decimal.slice(0, 12)}…`;
    } else if (challenge.status === "error") {
      challengeEl.textContent = `Error: ${challenge.message}`;
    } else {
      challengeEl.textContent = "Fetching…";
    }
    const btn = startButtonStateFor(challenge);
    startBtn.disabled = btn.disabled;
    startBtn.textContent = btn.label;
  }

  async function fetchChallenge(): Promise<void> {
    fetchController?.abort();
    fetchController = new AbortController();
    const mine = fetchController;
    $challenge.set({ status: "fetching" });
    try {
      const challenge = await createChallenge({ signal: mine.signal });
      if (fetchController !== mine) return;
      $challenge.set({ status: "ready", challenge });
    } catch (err) {
      if (fetchController !== mine) return;
      if (err instanceof DOMException && err.name === "AbortError") return;
      const message = err instanceof Error ? err.message : String(err);
      $challenge.set({ status: "error", message });
    }
  }

  function onStart(): void {
    if (startBtn.disabled) return;
    const current = $challenge.get();
    if (current.status === "error") {
      void fetchChallenge();
      return;
    }
    // A pre-fetched challenge can expire while the user idles on this screen.
    // Consuming a stale challenge would burn the single-use PIN only to hit a
    // server-side rejection minutes into proving; re-fetch first.
    if (
      current.status === "ready" &&
      isChallengeExpired(current.challenge.expires_at)
    ) {
      void fetchChallenge();
      return;
    }
    dispatch({ type: "start_proving" });
  }
  function onBack(): void {
    fetchController?.abort();
    dispatch({ type: "reset_to_setup" });
  }

  startBtn.addEventListener("click", onStart);
  backBtn.addEventListener("click", onBack);

  const unsubHipki = $hipki.listen(paint);
  const unsubPin = $pin.listen(paint);
  const unsubWarmup = $warmup.listen(paint);
  const unsubChallenge = $challenge.listen(paint);

  paint();

  // Guard against stale state (e.g., PIN cleared). If any precondition
  // regresses, bounce to setup so the user fixes it there instead of
  // hitting an error after Start proving.
  if (
    $hipki.get().status !== "card_ready" ||
    $pin.get().status !== "locked" ||
    $warmup.get().status !== "ready"
  ) {
    dispatch({ type: "reset_to_setup" });
  }

  // Trigger a pre-fetch only if no ready challenge is already cached from a
  // prior visit to this screen.
  const nowChallenge = $challenge.get();
  if (nowChallenge.status === "pending" || nowChallenge.status === "error") {
    void fetchChallenge();
  }

  return () => {
    fetchController?.abort();
    startBtn.removeEventListener("click", onStart);
    backBtn.removeEventListener("click", onBack);
    unsubHipki();
    unsubPin();
    unsubWarmup();
    unsubChallenge();
  };
}

/** Treat unparseable timestamps as expired so we re-fetch rather than trust
 *  a malformed response. 5-second skew buffer to cover clock drift between
 *  the browser and the Go verifier. */
function isChallengeExpired(expiresAt: string): boolean {
  const t = Date.parse(expiresAt);
  if (Number.isNaN(t)) return true;
  return t - Date.now() <= 5_000;
}
