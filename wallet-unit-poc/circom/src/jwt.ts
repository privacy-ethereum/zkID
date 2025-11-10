import { strict as assert } from "assert";
import { Es256CircuitParams, generateES256Inputs, JwkEcdsaPublicKey, PemPublicKey } from "./es256.ts";
import { base64urlToBase64, encodeClaims, stringToPaddedBigIntArray } from "./utils.ts";

// The JWT Circuit Parameters
export interface JwtCircuitParams {
  es256: Es256CircuitParams;
  maxB64PayloadLength: number;
  maxMatches: number;
  maxSubstringLength: number;
  maxClaimLength: number;
}

// Generate JWT Circuit Parameters
export function generateJwtCircuitParams(params: number[]): JwtCircuitParams {
  return {
    es256: {
      maxMessageLength: params[0],
    },
    maxB64PayloadLength: params[1],
    maxMatches: params[2],
    maxSubstringLength: params[3],
    maxClaimLength: params[4],
  };
}

// Generate JWT circuit inputs
export function generateJwtInputs(
  params: JwtCircuitParams,
  token: string,
  pk: JwkEcdsaPublicKey | PemPublicKey,
  matches: string[],
  claims: string[],
  decodeFlags: number[]
) {
  // we are not checking the JWT token format, assuming that is correct
  const [b64header, b64payload, b64signature] = token.split(".");

  // check that we are not exceeding the limits
  assert.ok(b64payload.length <= params.maxB64PayloadLength);
  assert.ok(matches.length + 2 <= params.maxMatches);

  // generate inputs for the ES256 validation
  let es256Inputs = generateES256Inputs(params.es256, `${b64header}.${b64payload}`, b64signature, pk);

  const payload = atob(b64payload);

  const patterns = ['"x":"', '"y":"', ...matches];

  assert.ok(patterns.length <= params.maxMatches);

  let matchSubstring: bigint[][] = [];
  let matchLength: number[] = [];
  let matchIndex: number[] = [];
  for (const pattern of patterns) {
    assert.ok(pattern.length <= params.maxSubstringLength);
    const index = payload.indexOf(pattern);
    assert.ok(index != -1);
    matchSubstring.push(stringToPaddedBigIntArray(pattern, params.maxSubstringLength));
    matchLength.push(pattern.length);
    matchIndex.push(index);
  }

  while (matchIndex.length < params.maxMatches) {
    matchSubstring.push(stringToPaddedBigIntArray("", params.maxSubstringLength));
    matchLength.push(0);
    matchIndex.push(0);
  }

  const claimsAligned = ["", "", ...claims];
  let { claimArray, claimLengths } = encodeClaims(claimsAligned, params.maxMatches, params.maxClaimLength);

  const decodeFlagsAligned: number[] = [0, 0, ...decodeFlags];
  while (decodeFlagsAligned.length < params.maxMatches) {
    decodeFlagsAligned.push(0);
  }
  const decodeFlagsOut = decodeFlagsAligned.slice(0, params.maxMatches);

  const ageClaimOffset = claims.findIndex((claim) => {
    try {
      const decoded = Buffer.from(base64urlToBase64(claim), "base64").toString("utf8");
      const parsed = JSON.parse(decoded);
      return Array.isArray(parsed) && parsed[1] === "roc_birthday";
    } catch {
      return false;
    }
  });

  assert.ok(ageClaimOffset >= 0, "roc_birthday claim not found among provided claims");
  const ageClaimIndex = ageClaimOffset + 2;

  // const now = new Date();
  // const currentYear = BigInt(now.getUTCFullYear());
  // const currentMonth = BigInt(now.getUTCMonth() + 1);
  // const currentDay = BigInt(now.getUTCDate());

  return {
    ...es256Inputs,
    periodIndex: token.indexOf("."),
    matchesCount: patterns.length,
    matchSubstring,
    matchLength,
    matchIndex,
    claims: claimArray,
    claimLengths,
    decodeFlags: decodeFlagsOut,
    ageClaimIndex,
  };
}
