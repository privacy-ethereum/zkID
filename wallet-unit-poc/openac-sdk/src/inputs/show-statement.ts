// Canonical construction of the Show circuit's verifier statement: the public
// data that binds a presentation to a specific nonce/challenge and predicate
// policy. This is the SINGLE source of truth shared by the prover (which feeds
// these values into the witness) and the verifier (which recomputes them from
// its expected nonce + policy and compares against the proof's public IO).
//
// The Show circuit exposes its public signals as the contiguous witness prefix
// `witness[1..=num_public]`, in this order (see circom/circuits/main/show.circom):
//   [0] expressionResult   (output; NOT produced here, it is the result bit)
//   [1] messageHash
//   [2] predicateLen
//   [3..]  predicateClaimRefs[maxPredicates]
//          predicateOps[maxPredicates]
//          predicateRhsIsRef[maxPredicates]
//          predicateRhsValues[maxPredicates]
//          predicateClaimIdentifiers[maxPredicates]
//          tokenTypes[maxLogicTokens]
//          tokenValues[maxLogicTokens]
//          exprLen
//
// The order is the input DECLARATION order in circuits/show.circom, not the
// order of the `public[...]` list in the generated main component -- circom
// assigns public positions by declaration. `predicateClaimIdentifiers` is
// declared between predicateRhsValues and tokenTypes, so it flattens there.
//
// `buildShowStatementFields` returns the padded arrays; `buildShowStatementPublicValues`
// flattens them (excluding expressionResult) into the exact order above.

import { sha256 } from "@noble/hashes/sha2";
import { bytesToBigInt, P256_SCALAR_ORDER } from "../utils.js";
import { InputError } from "../errors.js";
import { PredicateOp } from "./show-input-builder.js";
import type { PredicateSpec } from "./show-input-builder.js";
import type { ShowCircuitParams } from "../types.js";

export interface ShowStatementFields {
  /** Scalar-field-reduced hash of the verifier nonce. */
  messageHash: bigint;
  predicateLen: bigint;
  predicateClaimRefs: bigint[];
  predicateOps: bigint[];
  predicateRhsIsRef: bigint[];
  predicateRhsValues: bigint[];
  /** Attribute identity the verifier bound each predicate to (0 = unbound). */
  predicateClaimIdentifiers: bigint[];
  tokenTypes: bigint[];
  tokenValues: bigint[];
  exprLen: bigint;
}

/** Reduce sha256(nonce) into the P-256 scalar field, matching the Show circuit's messageHash. */
export function computeMessageHash(nonce: string): bigint {
  const digest = sha256(new TextEncoder().encode(nonce));
  return bytesToBigInt(digest) % P256_SCALAR_ORDER;
}

/**
 * Build the padded predicate/token arrays and message hash exactly as the Show
 * witness does. The padding conventions here MUST match the circuit witness:
 * unused predicateOps slots default to EQ, everything else defaults to 0.
 */
export function buildShowStatementFields(
  params: ShowCircuitParams,
  nonce: string,
  predicates: PredicateSpec[],
  logicExpression: Array<{ type: number; value: number }>,
): ShowStatementFields {
  if (predicates.length > params.maxPredicates) {
    throw new InputError(
      "PARAMS_EXCEEDED",
      `Predicate count (${predicates.length}) exceeds maxPredicates (${params.maxPredicates})`,
    );
  }
  if (logicExpression.length > params.maxLogicTokens) {
    throw new InputError(
      "PARAMS_EXCEEDED",
      `Logic expression length (${logicExpression.length}) exceeds maxLogicTokens (${params.maxLogicTokens})`,
    );
  }

  const predicateClaimRefs: bigint[] = Array(params.maxPredicates).fill(0n);
  const predicateOps: bigint[] = Array(params.maxPredicates).fill(BigInt(PredicateOp.EQ));
  const predicateRhsIsRef: bigint[] = Array(params.maxPredicates).fill(0n);
  const predicateRhsValues: bigint[] = Array(params.maxPredicates).fill(0n);
  // JWT credentials carry no per-attribute identity -- their claims are
  // disclosure digests, not named elements -- so every slot stays 0. The mdoc
  // path sets these to the identifier hash the predicate is bound to.
  const predicateClaimIdentifiers: bigint[] = Array(params.maxPredicates).fill(0n);

  for (let i = 0; i < predicates.length; i++) {
    const spec = predicates[i]!;
    predicateClaimRefs[i] = BigInt(spec.claimRef);
    predicateOps[i] = BigInt(spec.op);
    if (spec.rhs.kind === "literal") {
      predicateRhsIsRef[i] = 0n;
      predicateRhsValues[i] = spec.rhs.value;
    } else {
      predicateRhsIsRef[i] = 1n;
      predicateRhsValues[i] = BigInt(spec.rhs.index);
    }
  }

  const tokenTypes: bigint[] = Array(params.maxLogicTokens).fill(0n);
  const tokenValues: bigint[] = Array(params.maxLogicTokens).fill(0n);
  for (let i = 0; i < logicExpression.length; i++) {
    tokenTypes[i] = BigInt(logicExpression[i]!.type);
    tokenValues[i] = BigInt(logicExpression[i]!.value);
  }

  return {
    messageHash: computeMessageHash(nonce),
    predicateLen: BigInt(predicates.length),
    predicateClaimRefs,
    predicateOps,
    predicateRhsIsRef,
    predicateRhsValues,
    predicateClaimIdentifiers,
    tokenTypes,
    tokenValues,
    exprLen: BigInt(logicExpression.length),
  };
}

/**
 * Flatten the statement fields into the public-value vector in circuit order,
 * EXCLUDING the leading `expressionResult` (public index 0). The returned array
 * therefore corresponds to public indices `1..num_public`.
 */
export function buildShowStatementPublicValues(
  params: ShowCircuitParams,
  nonce: string,
  predicates: PredicateSpec[],
  logicExpression: Array<{ type: number; value: number }>,
): bigint[] {
  const f = buildShowStatementFields(params, nonce, predicates, logicExpression);
  return [
    f.messageHash,
    f.predicateLen,
    ...f.predicateClaimRefs,
    ...f.predicateOps,
    ...f.predicateRhsIsRef,
    ...f.predicateRhsValues,
    ...f.predicateClaimIdentifiers,
    ...f.tokenTypes,
    ...f.tokenValues,
    f.exprLen,
  ];
}
