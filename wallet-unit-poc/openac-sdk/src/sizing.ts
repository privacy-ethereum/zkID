import { InputError } from "./errors.js";
import type { JwtCircuitParams } from "./types.js";

export type VcSize = "1k" | "2k" | "4k" | "8k";

export const JWT_PARAMS_BY_SIZE: Record<VcSize, JwtCircuitParams> = {
  "1k": {
    maxMessageLength: 1280,
    maxB64PayloadLength: 960,
    maxMatches: 4,
    maxSubstringLength: 50,
    maxClaimLength: 128,
  },
  "2k": {
    maxMessageLength: 2048,
    maxB64PayloadLength: 2000,
    maxMatches: 4,
    maxSubstringLength: 50,
    maxClaimLength: 128,
  },
  "4k": {
    maxMessageLength: 4096,
    maxB64PayloadLength: 4000,
    maxMatches: 4,
    maxSubstringLength: 50,
    maxClaimLength: 128,
  },
  "8k": {
    maxMessageLength: 8192,
    maxB64PayloadLength: 8000,
    maxMatches: 4,
    maxSubstringLength: 50,
    maxClaimLength: 128,
  },
};

export const VC_SIZES: readonly VcSize[] = ["1k", "2k", "4k", "8k"] as const;

export function selectVcSizeForSigningInput(byteLength: number): VcSize {
  for (const size of VC_SIZES) {
    if (byteLength <= JWT_PARAMS_BY_SIZE[size].maxMessageLength) return size;
  }
  throw new InputError(
    "PARAMS_EXCEEDED",
    `Signing input ${byteLength}B exceeds largest circuit (8k = 8192B). Use a smaller credential.`,
  );
}
