// Client for go-zkid-verifier REST API.
// Keep snake_case to match server wire format.

import { composeSignal, parsePositiveInt } from "./abort-utils";

const VERIFIER_BASE =
  import.meta.env.VITE_VERIFIER_BASE_URL ?? "http://localhost:8080";

const MAX_RAW_PROOF_BYTES = 700 * 1024;
const APP_ID_BYTES = 31;

export interface Challenge {
  /** Per-session field-element binding (decimal string). Embedded into the
   *  device-sig proof; the verifier extracts it from the public signals and
   *  normalizes it back to decimal for the store lookup. */
  challenge: string;
  /** 31-byte UTF-8 relying-party identifier. Signed by the card and fed
   *  verbatim into the circuit's `app_id_bytes`. */
  app_id: string;
  expires_at: string;
}

/** Raw verifier public inputs (hex strings). */
export interface PublicSignals {
  cert_chain: string[];
  device_sig: string[];
}

/** Named parse of public signals from the verifier response. */
export interface ParsedInputs {
  challenge: string;
  pk_commit: string;
  nullifier: string;
  smt_root: string;
  issuer_rsa_modulus: string[];
}

export interface LinkVerifyResult {
  verified: boolean;
  /** Present only when `verified` is true. */
  nullifier?: string;
  id_verified?: boolean;
  persisted?: boolean;
  public_signals?: PublicSignals;
  parsed_inputs?: ParsedInputs;
}

export interface LinkVerifyParams {
  certChainType: "rs2048" | "rs4096";
  certChainProofBytes: Uint8Array;
  deviceSigProofBytes: Uint8Array;
}

/** Default request timeout; can be overridden by VITE_VERIFIER_TIMEOUT_MS. */
const VERIFIER_TIMEOUT_MS = parsePositiveInt(
  import.meta.env.VITE_VERIFIER_TIMEOUT_MS,
  60_000,
);

export interface CreateChallengeOptions {
  signal?: AbortSignal;
}

export interface SubmitLinkVerifyOptions {
  signal?: AbortSignal;
}

export async function createChallenge(
  opts: CreateChallengeOptions = {},
): Promise<Challenge> {
  const r = await fetch(`${VERIFIER_BASE}/challenge`, {
    method: "POST",
    signal: composeSignal(opts.signal, VERIFIER_TIMEOUT_MS),
  });
  if (!r.ok) {
    throw new Error(`POST /challenge returned ${r.status} ${r.statusText}`);
  }
  const body = (await r.json()) as Partial<Challenge>;
  // Runtime shape guard to catch server field drift early.
  if (
    typeof body?.challenge !== "string" ||
    typeof body?.app_id !== "string"
  ) {
    throw new Error(
      `POST /challenge: unexpected response shape (got keys: ${Object.keys(body ?? {}).join(", ") || "none"})`,
    );
  }
  // The device-sig circuit has 31 fixed `app_id_bytes` slots. A drift here
  // produces a non-verifying proof many seconds later instead of failing
  // fast; assert it at the wire boundary.
  if (new TextEncoder().encode(body.app_id).byteLength !== APP_ID_BYTES) {
    throw new Error(
      `POST /challenge: app_id must be ${APP_ID_BYTES} UTF-8 bytes (got ${body.app_id.length} chars)`,
    );
  }
  return body as Challenge;
}

export async function submitLinkVerify(
  params: LinkVerifyParams,
  opts: SubmitLinkVerifyOptions = {},
): Promise<LinkVerifyResult> {
  assertProofSize("cert_chain_proof", params.certChainProofBytes);
  assertProofSize("device_sig_proof", params.deviceSigProofBytes);

  const body = {
    cert_chain_type: params.certChainType,
    // Go's json.Unmarshal decodes base64 into []byte.
    cert_chain_proof: bytesToBase64(params.certChainProofBytes),
    device_sig_proof: bytesToBase64(params.deviceSigProofBytes),
  };

  const r = await fetch(`${VERIFIER_BASE}/link-verify`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
    signal: composeSignal(opts.signal, VERIFIER_TIMEOUT_MS),
  });
  if (!r.ok) {
    const text = await r.text().catch(() => "");
    throw new Error(
      `POST /link-verify returned ${r.status} ${r.statusText}${text ? ` — ${text}` : ""}`,
    );
  }
  const parsed = (await r.json()) as Partial<LinkVerifyResult>;
  if (typeof parsed?.verified !== "boolean") {
    throw new Error(
      `POST /link-verify: unexpected response shape (got keys: ${Object.keys(parsed ?? {}).join(", ") || "none"})`,
    );
  }
  if (parsed.verified && typeof parsed.nullifier !== "string") {
    throw new Error(
      `POST /link-verify: verified=true response missing string nullifier`,
    );
  }
  return parsed as LinkVerifyResult;
}

function assertProofSize(field: string, bytes: Uint8Array): void {
  if (bytes.byteLength > MAX_RAW_PROOF_BYTES) {
    throw new Error(
      `${field} is ${bytes.byteLength} bytes, exceeds ${MAX_RAW_PROOF_BYTES}-byte raw cap (server limit is 2 MB for the whole JSON body, base64 inflates ~33%)`,
    );
  }
}

function bytesToBase64(b: Uint8Array): string {
  // TextEncoder-free and Worker-safe.
  let s = "";
  // Chunk to avoid hitting String.fromCharCode arg-count limits on large inputs.
  const CHUNK = 0x8000;
  for (let i = 0; i < b.length; i += CHUNK) {
    s += String.fromCharCode(...b.subarray(i, Math.min(i + CHUNK, b.length)));
  }
  return btoa(s);
}
