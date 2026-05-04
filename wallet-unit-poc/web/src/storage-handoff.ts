// sessionStorage channel used to hand `ProveInput` from the sign document
// (/) to the proving document (/prove). Both documents are same-origin so
// the entry survives the navigation. The payload carries a schema version
// so a stale value from an older build never feeds a fresh proving page.

import type { ProveInput } from "./worker";

const PROVE_INPUT_KEY = "zkid:proveInput";
// Bump on incompatible ProveInput shape changes; stale prior blobs are
// rejected by the version check rather than feeding a fresh proving page.
const SCHEMA_VERSION = 2;

interface StoredProveInput {
  v: typeof SCHEMA_VERSION;
  proveInput: ProveInput;
}

/** Persist `ProveInput` for the /prove document to consume on next nav.
 *  Throws on `QuotaExceededError` so the caller can surface a pipeline
 *  error rather than silently losing the handoff mid-navigation. */
export function saveProveInput(proveInput: ProveInput): void {
  const payload: StoredProveInput = { v: SCHEMA_VERSION, proveInput };
  const serialized = JSON.stringify(payload);
  try {
    sessionStorage.setItem(PROVE_INPUT_KEY, serialized);
  } catch (err) {
    throw new Error(
      `sessionStorage rejected ProveInput handoff (${serialized.length} bytes): ` +
        (err instanceof Error ? err.message : String(err)),
    );
  }
}

/** Read and remove the stored ProveInput. Returns null if absent or stale
 *  (wrong schema version). Removal is unconditional on a successful read so
 *  a reload of /prove can't replay a consumed input. */
export function consumeProveInput(): ProveInput | null {
  const raw = sessionStorage.getItem(PROVE_INPUT_KEY);
  if (!raw) return null;
  sessionStorage.removeItem(PROVE_INPUT_KEY);
  try {
    const parsed = JSON.parse(raw) as Partial<StoredProveInput>;
    if (parsed.v !== SCHEMA_VERSION) return null;
    if (!parsed.proveInput) return null;
    return parsed.proveInput;
  } catch {
    return null;
  }
}

export function clearProveInput(): void {
  sessionStorage.removeItem(PROVE_INPUT_KEY);
}
