// Focused unit tests for the Show statement-binding logic that defeats
// policy-swap and replay attacks (see verifier.ts / inputs/show-statement.ts).
//
// These do NOT run the SNARK: they feed the Verifier a stub WASM bridge that
// returns crafted `showPublicValues` formatted exactly as the real WASM does
// (Rust `{:?}` on a secq256r1 scalar => big-endian, 0x-prefixed, 64 hex chars),
// then assert the verifier accepts only when the proof's bound public values
// match the verifier's expected nonce + policy.

import { describe, it, expect } from "vitest";
import { p256 } from "@noble/curves/nist.js";

import { Verifier } from "../src/verifier.js";
import {
  computeMessageHash,
  buildShowStatementPublicValues,
  compilePredicateExpression,
} from "../src/index.js";
import { issuerPublicKeyToPoint } from "../src/inputs/issuer-key.js";
import { DEFAULT_SHOW_PARAMS } from "../src/types.js";
import {
  P256_SCALAR_ORDER,
  sha256Hash,
  bytesToBigInt,
  bigintToBase64url,
} from "../src/utils.js";
import type {
  DisclosedClaim,
  EcdsaPublicKey,
  ExpectedStatement,
  VerifyingKeys,
} from "../src/types.js";
import type { PredicateExpression } from "../src/predicates.js";

// Minimal claim set: name -> index mapping the verifier derives from the credential.
const CLAIMS: DisclosedClaim[] = [
  { index: 0, salt: "", name: "roc_birthday", value: "0900101", raw: "", digest: "" },
  { index: 1, salt: "", name: "roc_max", value: "0950101", raw: "", digest: "" },
];

const POLICY: PredicateExpression = {
  claim: "roc_birthday",
  op: "<=",
  compareTo: { claim: "roc_max" },
};

const OTHER_POLICY: PredicateExpression = {
  claim: "roc_birthday",
  op: ">=",
  value: 800000,
};

const DUMMY_KEYS: VerifyingKeys = {
  prepareVerifyingKey: new Uint8Array(),
  showVerifyingKey: new Uint8Array(),
};

/** Format a bigint the way the WASM verify formats a scalar: 0x + 64-char big-endian hex. */
function toScalarString(v: bigint): string {
  return "0x" + v.toString(16).padStart(64, "0");
}

/**
 * Build a stub WasmBridge whose `verify` returns a fixed public-value vector.
 * Only `verify` is exercised by the Verifier.
 */
function stubBridge(
  showPublicValues: string[],
  valid = true,
  issuerKey: EcdsaPublicKey = KNOWN_ISSUER,
) {
  const point = issuerPublicKeyToPoint(issuerKey);
  return {
    verify: async () => ({
      valid,
      // Prepare public IO: [claim outputs..., deviceKeyX, deviceKeyY, pubKeyX, pubKeyY].
      // Only the trailing issuer key is read back, so the prefix is filler.
      preparePublicValues: [0n, 0n, 0n, 0n, point.x, point.y].map(toScalarString),
      showPublicValues,
      error: valid ? undefined : "snark failed",
    }),
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
  } as any;
}

/** The public-value vector a proof for (nonce, predicates) would expose, expressionResult first. */
function publicValuesFor(
  nonce: string,
  predicates: PredicateExpression,
  expressionResult: boolean,
): string[] {
  const compiled = compilePredicateExpression(predicates, CLAIMS);
  const statement = buildShowStatementPublicValues(
    DEFAULT_SHOW_PARAMS,
    nonce,
    compiled.predicates,
    compiled.logicExpression,
  );
  return [expressionResult ? 1n : 0n, ...statement].map(toScalarString);
}

// Two distinct P-256 keys, standing in for a known issuer and an unknown one.
function keyFromScalar(k: bigint): EcdsaPublicKey {
  const point = p256.ProjectivePoint.BASE.multiply(k);
  const enc = (v: bigint) => bigintToBase64url(v);
  return { kty: "EC", crv: "P-256", x: enc(point.x), y: enc(point.y) };
}

const KNOWN_ISSUER = keyFromScalar(0x2a2an);
const OTHER_ISSUER = keyFromScalar(0x9f9fn);

const NONCE = "session-nonce-abc";
const compiledPolicy = compilePredicateExpression(POLICY, CLAIMS);
const expected: ExpectedStatement = {
  nonce: NONCE,
  predicates: compiledPolicy.predicates,
  logicExpression: compiledPolicy.logicExpression,
};

async function verifyWith(
  showPublicValues: string[],
  exp: ExpectedStatement = expected,
  issuerKey: EcdsaPublicKey = KNOWN_ISSUER,
) {
  const verifier = new Verifier(stubBridge(showPublicValues, true, issuerKey));
  return verifier.verifyComponents(
    new Uint8Array(),
    new Uint8Array(),
    DUMMY_KEYS,
    new Uint8Array(),
    new Uint8Array(),
    exp,
  );
}

describe("Show statement binding: helpers", () => {
  it("computeMessageHash matches sha256(nonce) mod scalar order", () => {
    const expectedHash =
      bytesToBigInt(sha256Hash(new TextEncoder().encode(NONCE))) % P256_SCALAR_ORDER;
    expect(computeMessageHash(NONCE)).toBe(expectedHash);
  });

  it("buildShowStatementPublicValues has the documented order and length", () => {
    const compiled = compilePredicateExpression(POLICY, CLAIMS);
    const pv = buildShowStatementPublicValues(
      DEFAULT_SHOW_PARAMS,
      NONCE,
      compiled.predicates,
      compiled.logicExpression,
    );
    // messageHash + predicateLen + 4*maxPredicates + 2*maxLogicTokens + exprLen
    const p = DEFAULT_SHOW_PARAMS;
    expect(pv.length).toBe(2 + 4 * p.maxPredicates + 2 * p.maxLogicTokens + 1);
    expect(pv[0]).toBe(computeMessageHash(NONCE)); // first element is the nonce hash
  });
});

describe("Show statement binding: verifier enforcement", () => {
  it("accepts a proof whose public values match the expected nonce + policy", async () => {
    const result = await verifyWith(publicValuesFor(NONCE, POLICY, true));
    expect(result.valid).toBe(true);
    expect(result.expressionResult).toBe(true);
    expect(result.error).toBeUndefined();
  });

  it("reports expressionResult=false when the bound result bit is zero", async () => {
    const result = await verifyWith(publicValuesFor(NONCE, POLICY, false));
    expect(result.valid).toBe(true);
    expect(result.expressionResult).toBe(false);
  });

  it("rejects a replay: proof bound to a different nonce", async () => {
    const result = await verifyWith(publicValuesFor("a-stale-nonce", POLICY, true));
    expect(result.valid).toBe(false);
    expect(result.expressionResult).toBeNull();
    expect(result.error).toMatch(/nonce/i);
  });

  it("rejects a policy swap: proof bound to a different policy", async () => {
    const result = await verifyWith(publicValuesFor(NONCE, OTHER_POLICY, true));
    expect(result.valid).toBe(false);
    expect(result.expressionResult).toBeNull();
    expect(result.error).toMatch(/policy/i);
  });

  it("rejects when the SNARK itself is invalid, regardless of expectation", async () => {
    const verifier = new Verifier(stubBridge(publicValuesFor(NONCE, POLICY, true), false));
    const result = await verifier.verifyComponents(
      new Uint8Array(),
      new Uint8Array(),
      DUMMY_KEYS,
      new Uint8Array(),
      new Uint8Array(),
      expected,
    );
    expect(result.valid).toBe(false);
  });

  it("rejects when the proof exposes the wrong number of public values", async () => {
    const truncated = publicValuesFor(NONCE, POLICY, true).slice(0, 5);
    const result = await verifyWith(truncated);
    expect(result.valid).toBe(false);
    expect(result.error).toMatch(/size mismatch/i);
  });
});

describe("Issuer key reporting", () => {
  it("reports the issuer key the proof was built under", async () => {
    const result = await verifyWith(publicValuesFor(NONCE, POLICY, true));
    expect(result.valid).toBe(true);
    // Reported as exact coordinates and as a directly comparable JWK.
    expect(result.issuerKey?.jwk).toEqual(KNOWN_ISSUER);
    expect(result.issuerKey?.x).toBe(issuerPublicKeyToPoint(KNOWN_ISSUER).x);
    expect(result.issuerKey?.y).toBe(issuerPublicKeyToPoint(KNOWN_ISSUER).y);
  });

  /**
   * Pins the documented contract: an unknown issuer key does not by itself make
   * a presentation invalid, so `valid` stays true and the caller is expected to
   * act on `issuerKey`. Changing this would silently break callers that rely on
   * `issuerKey` to make the trust decision.
   */
  it("reports valid with the proving key when the issuer is unknown", async () => {
    const result = await verifyWith(
      publicValuesFor(NONCE, POLICY, true),
      expected,
      OTHER_ISSUER,
    );
    expect(result.valid).toBe(true);
    expect(result.issuerKey?.jwk).toEqual(OTHER_ISSUER);
    expect(result.issuerKey?.jwk).not.toEqual(KNOWN_ISSUER);

    // The comparison a caller is expected to make, and its outcome here.
    const trustStore = [KNOWN_ISSUER];
    const trusted = trustStore.some(
      (k) => k.x === result.issuerKey?.jwk.x && k.y === result.issuerKey?.jwk.y,
    );
    expect(trusted).toBe(false);
  });

  it("reports no issuer key when verification fails", async () => {
    const result = await verifyWith(publicValuesFor("a-stale-nonce", POLICY, true));
    expect(result.valid).toBe(false);
    expect(result.issuerKey).toBeNull();
  });

  it("fails closed when the Prepare proof exposes too few public values", async () => {
    const verifier = new Verifier({
      verify: async () => ({
        valid: true,
        preparePublicValues: ["0x01"],
        showPublicValues: publicValuesFor(NONCE, POLICY, true),
      }),
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
    } as any);
    const result = await verifier.verifyComponents(
      new Uint8Array(),
      new Uint8Array(),
      DUMMY_KEYS,
      new Uint8Array(),
      new Uint8Array(),
      expected,
    );
    expect(result.valid).toBe(false);
    expect(result.issuerKey).toBeNull();
    expect(result.error).toMatch(/at least 2/i);
  });
});
