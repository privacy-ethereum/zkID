import { p256 } from "@noble/curves/p256";
import { sha256 } from "@noble/hashes/sha2";
import { Field } from "@noble/curves/abstract/modular";

import {
  base64urlToBigInt,
  bytesToBigInt,
  P256_SCALAR_ORDER,
} from "../utils.js";
import { InputError } from "../errors.js";
import type { ShowCircuitParams, ShowCircuitInputs, EcdsaPublicKey, EcdsaPrivateKey } from "../types.js";

const Fq = Field(BigInt("0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551"));

export function signDeviceNonce(nonce: string, privateKey: EcdsaPrivateKey): string {
  const privateKeyBytes =
    typeof privateKey === "string"
      ? hexToBytes(privateKey)
      : privateKey;

  const messageHash = sha256(new TextEncoder().encode(nonce));
  const signature = p256.sign(messageHash, privateKeyBytes);

  return bytesToBase64url(signature.toCompactRawBytes());
}

/** Predicate operator codes matching eval-predicate.circom */
export const PredicateOp = {
  LE: 0,
  GE: 1,
  EQ: 2,
} as const;

/** Logic token types for postfix expression evaluation */
export const LogicToken = {
  REF: 0,
  AND: 1,
  OR: 2,
  NOT: 3,
} as const;

export interface PredicateSpec {
  claimRef: number;
  op: number;
  compareValue: bigint;
}

export interface ShowInputOptions {
  /** Normalized claim values (from JWT circuit output). */
  normalizedClaimValues?: bigint[];
  /** Predicate specifications. Defaults to a single EQ predicate on claim 0. */
  predicates?: PredicateSpec[];
  /** Postfix logic expression as [tokenType, tokenValue] pairs. Defaults to REF(0). */
  logicExpression?: Array<{ type: number; value: number }>;
}

export function buildShowCircuitInputs(
  params: ShowCircuitParams,
  nonce: string,
  deviceSignature: string,
  deviceKey: EcdsaPublicKey,
  options: ShowInputOptions = {},
): ShowCircuitInputs {
  // decode the device signature
  const sigBytes = base64Decode(deviceSignature);
  const sigHex = Array.from(sigBytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
  const sigDecoded = p256.Signature.fromCompact(sigHex);
  const sigSInverse = Fq.inv(sigDecoded.s);

  // decode device key
  if (deviceKey.kty !== "EC" || deviceKey.crv !== "P-256") {
    throw new InputError("INVALID_KEY", "Device key must be P-256 EC key");
  }
  const deviceKeyX = base64urlToBigInt(deviceKey.x);
  const deviceKeyY = base64urlToBigInt(deviceKey.y);

  // verify signature off-chain
  const pubkey = p256.ProjectivePoint.fromAffine({ x: deviceKeyX, y: deviceKeyY });
  const msgHash = sha256(new TextEncoder().encode(nonce));
  const sigForVerify = sigDecoded.toDERRawBytes();
  const isValid = p256.verify(sigForVerify, msgHash, pubkey.toRawBytes());
  if (!isValid) {
    throw new InputError("INVALID_SIGNATURE", "Device signature verification failed");
  }

  // compute message hash mod scalar field order
  const messageHash = sha256(new TextEncoder().encode(nonce));
  const messageHashBigInt = bytesToBigInt(messageHash);
  const messageHashModQ = messageHashBigInt % P256_SCALAR_ORDER;

  // Build claim values array
  const normalizedValues = options.normalizedClaimValues ?? [0n];
  const claimValues: bigint[] = Array(params.nClaims).fill(0n);
  for (let i = 0; i < Math.min(params.nClaims, normalizedValues.length); i++) {
    claimValues[i] = normalizedValues[i]!;
  }

  // Build predicates
  const predicates = options.predicates ?? [
    { claimRef: 0, op: PredicateOp.EQ, compareValue: claimValues[0]! },
  ];
  const predicateLen = BigInt(predicates.length);

  const predicateClaimRefs: bigint[] = Array(params.maxPredicates).fill(0n);
  const predicateOps: bigint[] = Array(params.maxPredicates).fill(BigInt(PredicateOp.EQ));
  const predicateRhsIsRef: bigint[] = Array(params.maxPredicates).fill(0n);
  const predicateRhsValues: bigint[] = Array(params.maxPredicates).fill(claimValues[0] ?? 0n);

  for (let i = 0; i < Math.min(params.maxPredicates, predicates.length); i++) {
    predicateClaimRefs[i] = BigInt(predicates[i]!.claimRef);
    predicateOps[i] = BigInt(predicates[i]!.op);
    predicateRhsIsRef[i] = 0n; // all predicates use literal RHS values
    predicateRhsValues[i] = predicates[i]!.compareValue;
  }

  // Build logic expression tokens
  const logicExpr = options.logicExpression ?? [{ type: LogicToken.REF, value: 0 }];
  const exprLen = BigInt(logicExpr.length);

  if (logicExpr.length > params.maxLogicTokens) {
    throw new InputError(
      "PARAMS_EXCEEDED",
      `Logic expression length (${logicExpr.length}) exceeds maxLogicTokens (${params.maxLogicTokens})`,
    );
  }

  const tokenTypes: bigint[] = Array(params.maxLogicTokens).fill(0n);
  const tokenValues: bigint[] = Array(params.maxLogicTokens).fill(0n);

  for (let i = 0; i < logicExpr.length; i++) {
    tokenTypes[i] = BigInt(logicExpr[i]!.type);
    tokenValues[i] = BigInt(logicExpr[i]!.value);
  }

  return {
    deviceKeyX,
    deviceKeyY,
    sig_r: sigDecoded.r,
    sig_s_inverse: sigSInverse,
    messageHash: messageHashModQ,
    predicateLen,
    claimValues,
    predicateClaimRefs,
    predicateOps,
    predicateRhsIsRef,
    predicateRhsValues,
    tokenTypes,
    tokenValues,
    exprLen,
  };
}

function hexToBytes(hex: string): Uint8Array {
  const cleanHex = hex.startsWith("0x") ? hex.slice(2) : hex;
  const bytes = new Uint8Array(cleanHex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(cleanHex.slice(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

function base64Decode(input: string): Uint8Array {
  // handle base64url
  let b64 = input.replace(/-/g, "+").replace(/_/g, "/");
  const pad = (4 - (b64.length % 4)) % 4;
  b64 += "=".repeat(pad);

  const binStr = atob(b64);
  const bytes = new Uint8Array(binStr.length);
  for (let i = 0; i < binStr.length; i++) {
    bytes[i] = binStr.charCodeAt(i);
  }
  return bytes;
}

function bytesToBase64url(bytes: Uint8Array): string {
  const B64_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  let result = "";
  for (let i = 0; i < bytes.length; i += 3) {
    const a = bytes[i]!;
    const b = bytes[i + 1] ?? 0;
    const c = bytes[i + 2] ?? 0;
    const triplet = (a << 16) | (b << 8) | c;
    result += B64_CHARS[(triplet >> 18) & 0x3f];
    result += B64_CHARS[(triplet >> 12) & 0x3f];
    result += i + 1 < bytes.length ? B64_CHARS[(triplet >> 6) & 0x3f]! : "";
    result += i + 2 < bytes.length ? B64_CHARS[triplet & 0x3f]! : "";
  }
  return result.replace(/\+/g, "-").replace(/\//g, "_");
}
