import { p256 } from "@noble/curves/nist.js";
import { sha256 } from "@noble/hashes/sha2";
import { sha256Pad } from "@zk-email/helpers";
import { Field } from "@noble/curves/abstract/modular";
import { strict as assert } from "assert";
import { JwkEcdsaPublicKey } from "./es256.ts";
import { JwtCircuitParams } from "./jwt.ts";
import { base64urlToBigInt, base64urlToBase64, bufferToBigInt } from "./utils.ts";

export interface ShowCircuitParams {
  maxClaimsLength: number;
}

export function generateShowCircuitParams(params: number[] | JwtCircuitParams): ShowCircuitParams {
  const maxClaimsLength = Array.isArray(params) ? params.at(-1) : params.maxClaimLength;

  assert.ok(
    typeof maxClaimsLength === "number" && Number.isFinite(maxClaimsLength) && maxClaimsLength > 0,
    "maxClaimsLength must be a positive finite number"
  );

  return { maxClaimsLength };
}

export function signDeviceNonce(message: string, privateKey: Uint8Array | string): string {
  const privateKeyBytes = typeof privateKey === "string" ? Buffer.from(privateKey, "hex") : privateKey;
  const messageHash = sha256(message);
  const signature = p256.sign(messageHash, privateKeyBytes);
  return Buffer.from(signature.toCompactRawBytes()).toString("base64url");
}
export function generateShowInputs(
  params: ShowCircuitParams,
  nonce: string,
  deviceSignature: string,
  deviceKey: JwkEcdsaPublicKey,
  claim: string,
  currentDate: { year: number; month: number; day: number }
): {
  deviceKeyX: bigint;
  deviceKeyY: bigint;
  sig_r: bigint;
  sig_s_inverse: bigint;
  messageHash: bigint;
  claim: bigint[];
  currentYear: bigint;
  currentMonth: bigint;
  currentDay: bigint;
} {
  assert.ok(nonce.length <= params.maxClaimsLength, `Nonce length exceeds maxClaimsLength`);
  const decodedLen = Math.floor((params.maxClaimsLength * 3) / 4);

  const b64 = base64urlToBase64(claim);
  const decodedClaim = Buffer.from(b64, "base64").toString("utf8");
  assert.ok(decodedClaim.length <= decodedLen, "Decoded claim length exceeds circuit capacity");

  const claimArray = Array(decodedLen).fill(0n);
  for (let i = 0; i < decodedClaim.length; i++) {
    claimArray[i] = BigInt(decodedClaim.charCodeAt(i));
  }

  assert.ok(Number.isInteger(currentDate.year) && currentDate.year > 0, "Current year must be positive integer");
  assert.ok(
    Number.isInteger(currentDate.month) && currentDate.month >= 1 && currentDate.month <= 12,
    "Current month must be between 1 and 12"
  );
  assert.ok(
    Number.isInteger(currentDate.day) && currentDate.day >= 1 && currentDate.day <= 31,
    "Current day must be between 1 and 31"
  );

  const sig = Buffer.from(deviceSignature, "base64url");
  const sig_decoded = p256.Signature.fromCompact(sig.toString("hex"));
  const Fq = Field(BigInt("0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551"));
  const sig_s_inverse = Fq.inv(sig_decoded.s);

  assert.ok(deviceKey.kty === "EC" && deviceKey.crv === "P-256", "Device key must be P-256 EC");
  const deviceKeyX = base64urlToBigInt(deviceKey.x);
  const deviceKeyY = base64urlToBigInt(deviceKey.y);

  const pubkey = new p256.Point(deviceKeyX, deviceKeyY, 1n);
  const isValid = p256.verify(sig, sha256(nonce), pubkey.toRawBytes());
  assert.ok(isValid, "Device signature verification failed");

  const messageHash = sha256(nonce);
  const messageHashBigInt = bufferToBigInt(Buffer.from(messageHash));
  // Reduce message hash modulo scalar field order (required for ECDSA)
  const scalarFieldOrder = BigInt("0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551");
  const messageHashModQ = messageHashBigInt % scalarFieldOrder;

  return {
    deviceKeyX,
    deviceKeyY,
    sig_r: sig_decoded.r,
    sig_s_inverse,
    messageHash: messageHashModQ,
    claim: claimArray,
    currentYear: BigInt(currentDate.year),
    currentMonth: BigInt(currentDate.month),
    currentDay: BigInt(currentDate.day),
  };
}
