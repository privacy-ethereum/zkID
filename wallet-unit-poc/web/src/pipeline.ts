// Main-thread sign-phase pipeline (challenge → sign → smt → build).
// Returns `ProveInput` for handoff to `/prove`, where proving runs in a
// cross-origin-isolated Worker.

import { cert_modulus_bits, cert_serial_hex } from "./wasm/spartan2_wasm.js";

import { appIdToBytes, base64ToBytes } from "./bytes";
import { fetchPkcs11Info, signTbs } from "./hipki-client";
import { buildInputs, ensureWasm } from "./inputs";
import type { CircuitKind } from "./manifest";
import type { Pin } from "./pin";
import { dispatch } from "./store";
import { fetchSmtProof, type SmtIssuer } from "./smt-client";
import { result, steps, type Step } from "./ui";
import type { Challenge } from "./verifier-client";
import type { ProveInput } from "./worker";

export interface CardContext {
  userCertDer: Uint8Array;
  issuerCertDer: Uint8Array;
  serialHex: string;
  kIssuer: 17 | 34;
  issuer: SmtIssuer;
  certKind: CircuitKind;
  /** Reader the cert came from; reused for signing on `/sign`. */
  slotDescription?: string;
}

/** Setup display fields plus pipeline card context. */
export interface DetectedCard {
  card: CardContext;
  subjectDN?: string;
  cardSN?: string;
}

export interface ProvingContext {
  card: CardContext;
  pin: Pin;
  /** Pre-fetched so popup `window.open` keeps user activation. */
  challenge: Challenge;
  /** Cancels in-flight network calls; Worker cancel is handled separately. */
  signal?: AbortSignal;
}

/** Internal cancellation sentinel to avoid duplicate FSM errors. */
export class PipelineAborted extends Error {
  constructor() {
    super("pipeline aborted");
    this.name = "PipelineAborted";
  }
}

function setStep(step: Step, label?: string): void {
  steps[step].set({ status: "in_progress", label });
}

function stepDone(step: Step, label?: string): void {
  steps[step].set({ status: "done", label });
}

function fail(where: string, err: unknown): never {
  const message = err instanceof Error ? err.message : String(err);
  result.set({ kind: "error", message: `${where}: ${message}` });
  dispatch({ type: "pipeline_error", where, message });
  throw err;
}

function isAbortError(err: unknown): boolean {
  if (err instanceof PipelineAborted) return true;
  return err instanceof DOMException && err.name === "AbortError";
}

function checkAborted(signal: AbortSignal | undefined): void {
  if (signal?.aborted) throw new PipelineAborted();
}

/** Step helper with progress updates and unified error handling. */
async function stage<T>(
  step: Step,
  run: () => Promise<T>,
  labelFrom?: (value: T) => string,
): Promise<T> {
  setStep(step);
  try {
    const value = await run();
    stepDone(step, labelFrom?.(value));
    return value;
  } catch (err) {
    if (isAbortError(err)) throw new PipelineAborted();
    fail(step, err);
  }
}

/** Run sign-phase steps and return a `ProveInput` for `/prove`. */
export async function runSignPhasePipeline(
  worker: Worker,
  ctx: ProvingContext,
): Promise<ProveInput> {
  const { signal, challenge } = ctx;

  // Pre-fetched in Ready; keep this path await-free until `signTbs` so popup
  // user activation remains valid.
  stepDone("challenge", `challenge=${challenge.challenge.slice(0, 12)}…`);
  const appIdBytes = appIdToBytes(challenge.app_id);

  // Popup signing cannot be interrupted; abort on next check. Use cert from
  // `/sign` response, not setup cache, to match actual signing key.
  const { signatureB64: userSignatureB64, userCertDer: signedUserCertDer } =
    await stage("sign", async () => {
      const sig = await signTbs({
        tbs: challenge.app_id,
        pin: ctx.pin.consume(),
        slotDescription: ctx.card.slotDescription,
      });
      if (sig.ret_code !== 0 || sig.last_error !== 0) {
        throw new Error(
          `HiPKI sign failed: ret_code=${sig.ret_code} last_error=${sig.last_error}`,
        );
      }
      if (!sig.certb64) {
        throw new Error("HiPKI sign response missing certb64 (needed to proof-match the signing key)");
      }
      return {
        signatureB64: sig.signature,
        userCertDer: base64ToBytes(sig.certb64),
      };
    });
  checkAborted(signal);

  await ensureWasm();
  const signedSerialHex = cert_serial_hex(signedUserCertDer);

  const smtInputs = await stage(
    "smt",
    async () => {
      const t0 = performance.now();
      const inputs = await fetchSmtProof(worker, {
        issuer: ctx.card.issuer,
        serialHex: signedSerialHex,
        signal,
      });
      return { inputs, ms: Math.round(performance.now() - t0) };
    },
    ({ ms }) => `MerkleProof in ${ms}ms`,
  ).then((x) => x.inputs);
  checkAborted(signal);

  const { certJson, deviceJson } = await stage("build", () =>
    buildInputs({
      card: {
        ...ctx.card,
        userCertDer: signedUserCertDer,
        serialHex: signedSerialHex,
      },
      userSignatureB64,
      appIdBytes,
      smtInputs,
      challenge: challenge.challenge,
    }),
  );
  checkAborted(signal);

  const input: ProveInput = {
    certJson,
    deviceJson,
    certKind: ctx.card.certKind,
    challenge: challenge.challenge,
  };
  return input;
}

/** Select circuit by issuer modulus width, not issuer-DN heuristics. */
async function deriveIssuerFromCert(
  issuerCertDer: Uint8Array,
): Promise<{ issuer: SmtIssuer; kIssuer: 17 | 34; certKind: CircuitKind }> {
  await ensureWasm();
  const bits = cert_modulus_bits(issuerCertDer);
  return bits > 2048
    ? { issuer: "g3", kIssuer: 34, certKind: "certChainRS4096" }
    : { issuer: "g2", kIssuer: 17, certKind: "certChainRS2048" };
}

/** Build `CardContext` from HiPKI `/pkcs11info`, optionally scoped to a slot. */
export async function buildCardContext(
  slotDescription?: string,
): Promise<DetectedCard> {
  const info = await fetchPkcs11Info(slotDescription);
  const slot = slotDescription
    ? info.slots.find((s) => s.slotDescription === slotDescription)
    : info.slots.find((s) => s.token) ?? info.slots[0];
  if (slotDescription && !slot) {
    throw new Error(
      `HiPKI: requested reader '${slotDescription}' not in response`,
    );
  }
  const token = slot?.token;
  if (!token) throw new Error("HiPKI: no token in /pkcs11info response");
  const userEntry = token.certs.find((c) => c.label !== "CA Cert");
  const caEntry = token.certs.find((c) => c.label === "CA Cert");
  if (!userEntry) throw new Error("HiPKI: no user cert in token");
  if (!caEntry) throw new Error("HiPKI: no 'CA Cert' entry in token");

  const issuerCertDer = base64ToBytes(caEntry.certb64);
  const { issuer, kIssuer, certKind } = await deriveIssuerFromCert(issuerCertDer);

  return {
    card: {
      userCertDer: base64ToBytes(userEntry.certb64),
      issuerCertDer,
      serialHex: deriveSerialHex(userEntry.sn, token.serialNumber),
      kIssuer,
      issuer,
      certKind,
      slotDescription: slotDescription ?? slot?.slotDescription,
    },
    subjectDN: userEntry.subjectDN,
    cardSN: token.serialNumber,
  };
}

/** Prefer the cert's own serial number field; fall back to the token serial. */
function deriveSerialHex(
  entrySn: string | undefined,
  tokenSerial: string | undefined,
): string {
  const candidate = entrySn ?? tokenSerial;
  if (!candidate) {
    throw new Error("HiPKI: no serial number on user cert or token");
  }
  return candidate.startsWith("0x") || candidate.startsWith("0X")
    ? candidate
    : `0x${candidate}`;
}
