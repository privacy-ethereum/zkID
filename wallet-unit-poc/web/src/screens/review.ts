// Review screen: user-gated checkpoint between `proving` and `submitting`.
// Proofs live only in memory until the user clicks Send.

import { formatDuration, humanBytes, truncateMiddle } from "../format";
import { $state, dispatch, type ProvingRun } from "../store";

const MAX_TOTAL_BYTES = 2 * 1024 * 1024;
const SAFE_THRESHOLD = Math.round(MAX_TOTAL_BYTES * 0.8);

function shortId(id: string): string {
  return truncateMiddle(id, 8, 4);
}

export function mountReview(root: HTMLElement): () => void {
  const state = $state.get();
  if (state.phase !== "review") {
    // Edge case (e.g., manual URL navigation) — router gates on phase.
    dispatch({ type: "retry_proving" });
    return () => {};
  }
  const run: ProvingRun = state.run;

  const certBytes = run.certProofBytes.byteLength;
  const userSigBytes = run.userSigProofBytes.byteLength;
  const totalBytes = certBytes + userSigBytes;
  const overBudget = totalBytes > SAFE_THRESHOLD;

  root.innerHTML = `
    <section class="screen screen-review">
      <h1>Review proof</h1>
      <p class="intro">
        Your proofs are generated and held in memory. Nothing has been sent
        to the server yet — click Send to submit both proofs to the
        verifier.
      </p>
      <div class="review-summary" data-testid="review-summary">
        <div class="review-row">
          <span class="review-label">Challenge id</span>
          <span class="review-value" data-testid="review-challenge"></span>
        </div>
        <div class="review-row">
          <span class="review-label">Cert chain</span>
          <span class="review-value" data-testid="review-chain"></span>
        </div>
        <div class="review-row">
          <span class="review-label">Cert-chain proof</span>
          <span class="review-value" data-testid="review-cert-size"></span>
        </div>
        <div class="review-row">
          <span class="review-label">User-sig proof</span>
          <span class="review-value" data-testid="review-user-sig-size"></span>
        </div>
        <div class="review-row">
          <span class="review-label">Proving time</span>
          <span class="review-value" data-testid="review-proving-ms"></span>
        </div>
      </div>
      <div class="review-guardrail" data-testid="review-guardrail" hidden>
        Proofs approach the verifier's 2 MB body limit (base64 inflates ~33%).
        Submission may fail; consider reducing the cert-chain size if possible.
      </div>
      <div class="button-row">
        <button class="secondary-button" data-testid="review-retry" type="button">
          Retry proving
        </button>
        <button class="primary-button" data-testid="review-send" type="button">
          Send proof to verifier
        </button>
      </div>
    </section>
  `;

  const challengeEl = root.querySelector<HTMLElement>('[data-testid="review-challenge"]')!;
  const chainEl = root.querySelector<HTMLElement>('[data-testid="review-chain"]')!;
  const certSizeEl = root.querySelector<HTMLElement>('[data-testid="review-cert-size"]')!;
  const userSigSizeEl = root.querySelector<HTMLElement>('[data-testid="review-user-sig-size"]')!;
  const provingMsEl = root.querySelector<HTMLElement>('[data-testid="review-proving-ms"]')!;
  const guardrailEl = root.querySelector<HTMLElement>('[data-testid="review-guardrail"]')!;
  const retryBtn = root.querySelector<HTMLButtonElement>('[data-testid="review-retry"]')!;
  const sendBtn = root.querySelector<HTMLButtonElement>('[data-testid="review-send"]')!;

  challengeEl.textContent = shortId(run.challenge);
  chainEl.textContent = run.certChainType.toUpperCase();
  certSizeEl.textContent = humanBytes(certBytes, "0 B");
  userSigSizeEl.textContent = humanBytes(userSigBytes, "0 B");
  provingMsEl.textContent = formatDuration(run.provingMs);
  guardrailEl.hidden = !overBudget;

  const onSend = () => dispatch({ type: "send_proof" });
  const onRetry = () => dispatch({ type: "retry_proving" });

  sendBtn.addEventListener("click", onSend);
  retryBtn.addEventListener("click", onRetry);

  return () => {
    sendBtn.removeEventListener("click", onSend);
    retryBtn.removeEventListener("click", onRetry);
  };
}
