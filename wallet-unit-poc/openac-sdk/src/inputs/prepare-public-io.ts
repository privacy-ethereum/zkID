// Reading the JWT (Prepare) proof's public IO.
//
// Circom lays public IO out as `[outputs..., public inputs...]`, so for the JWT
// main components (see circom/circuits/main/jwt*.circom):
//
//   [0 .. n)          normalizedClaimValues[n]   (outputs)
//   [n]               KeyBindingX
//   [n + 1]           KeyBindingY
//   [n + 2]           pubKeyX                    (public inputs from here on)
//   [n + 3]           pubKeyY
//   [n + 4 .. 2n + 4) decodeFlags[n]
//   [2n + 4 .. 3n + 4) claimFormats[n]
//
// where `n = maxMatches - 2`. Total length is `3n + 4`, which determines `n`
// from the vector alone, so nothing has to thread the circuit size through.
//
// Verified against `circom/build/jwt_1k/jwt_1k.sym` (n = 2, length 10); the Rust
// tests in `ecdsa-spartan2/src/utils.rs` assert the same layout against the
// compiled circuits.

import { VerificationError } from "../errors.js";
import type { ClaimNormalization } from "../types.js";

export interface IssuerKeyPoint {
  x: bigint;
  y: bigint;
}

interface PreparePublicIoLayout {
  claimCount: number;
  issuerKeyXIndex: number;
  decodeFlagsStart: number;
  claimFormatsStart: number;
}

/**
 * Derive the public IO layout from the vector's length.
 *
 * Throws `VerificationError("INVALID_PROOF_FORMAT")` for a length no JWT
 * circuit can produce, which is the symptom of a proof from a different circuit
 * or a stale key.
 */
function layoutOf(publicValues: bigint[]): PreparePublicIoLayout {
  const claimCount = (publicValues.length - 4) / 3;
  if (!Number.isInteger(claimCount) || claimCount < 1) {
    throw new VerificationError(
      "INVALID_PROOF_FORMAT",
      `Proof exposes ${publicValues.length} public values, which is not a valid JWT circuit ` +
        `public IO size (expected 3n + 4 for n claim slots)`,
    );
  }
  return {
    claimCount,
    issuerKeyXIndex: claimCount + 2,
    decodeFlagsStart: claimCount + 4,
    claimFormatsStart: 2 * claimCount + 4,
  };
}

/**
 * Extract (pubKeyX, pubKeyY), the issuer key the circuit's ES256 check ran
 * against, from a credential proof's public values.
 */
export function extractIssuerKeyFromPreparePublicValues(
  publicValues: bigint[],
): IssuerKeyPoint {
  const { issuerKeyXIndex } = layoutOf(publicValues);
  return {
    x: publicValues[issuerKeyXIndex]!,
    y: publicValues[issuerKeyXIndex + 1]!,
  };
}

/**
 * Extract the per-claim decode flags and format codes the circuit normalized
 * `normalizedClaimValues` under.
 *
 * A verifier needs these to know what the claim values a predicate compared
 * against actually mean. See `checkNormalizationSupports`.
 */
export function extractClaimNormalizationFromPreparePublicValues(
  publicValues: bigint[],
): ClaimNormalization {
  const { claimCount, decodeFlagsStart, claimFormatsStart } = layoutOf(publicValues);
  const slice = (start: number) =>
    publicValues.slice(start, start + claimCount).map((v) => Number(v));

  return {
    decodeFlags: slice(decodeFlagsStart),
    claimFormats: slice(claimFormatsStart),
  };
}
