// Thin wrapper around the `build_split_inputs` wasm export.
//
// Delegates to the shared `zkid-input-builder` Rust crate so the browser
// produces byte-identical JSON to `ecdsa-spartan2`'s `generate_split_inputs`.
// Parity is pinned by `spartan2-wasm/tests/input_builder_drift.rs` — the
// check that prevents `__placeholder__` witness failures from returning
// through input-builder drift.

import init, { build_split_inputs } from "./wasm/spartan2_wasm.js";
import type { CardContext } from "./pipeline";
import type { SmtCircuitInputs } from "./smt-client";

let wasmInit: Promise<unknown> | null = null;

/** Idempotent wasm-bindgen init shared across callers on the main thread. */
export async function ensureWasm(): Promise<void> {
  if (!wasmInit) wasmInit = init();
  await wasmInit;
}

export interface BuildInputsParams {
  card: CardContext;
  /** Raw PKCS#1 v1.5 signature from HiPKI, base64-encoded. */
  userSignatureB64: string;
  /** TBS bytes the user's card just signed (= challenge bytes). */
  tbs: Uint8Array;
  smtInputs: SmtCircuitInputs | null;
  /** Application identifier bound into nullifier (decimal string). */
  appId: string;
}

export interface SplitInputs {
  certJson: string;
  deviceJson: string;
}

/**
 * Returns stringified JSON (not objects) because the circom witness calculator
 * accepts a JSON string; serialising once here avoids a round trip through
 * `JSON.stringify` in the Worker, and lets us `postMessage` without
 * structured-cloning a many-KB object tree.
 */
export async function buildInputs(
  params: BuildInputsParams,
): Promise<SplitInputs> {
  await ensureWasm();
  const { card, userSignatureB64, tbs, smtInputs, appId } = params;
  const out = build_split_inputs(
    card.userCertDer,
    card.issuerCertDer,
    userSignatureB64,
    tbs,
    card.serialHex,
    smtInputs,
    card.kIssuer,
    17,
    appId,
  ) as { cert_chain: unknown; device_sig: unknown };
  return {
    certJson: JSON.stringify(out.cert_chain),
    deviceJson: JSON.stringify(out.device_sig),
  };
}
