import { p256 } from "@noble/curves/nist.js";
import { sha256 } from "@noble/hashes/sha2";
import { sha256Pad } from "@zk-email/helpers";
import { Field } from "@noble/curves/abstract/modular";
import { strict as assert } from "assert";
import { JwkEcdsaPublicKey } from "./es256.ts";
import { base64urlToBigInt, bufferToBigInt, uint8ArrayToBigIntArray } from "./utils.ts";

export interface ShowCircuitParams {
  maxNonceLength: number;
}

export function generateShowCircuitParams(params: number[]): ShowCircuitParams {
  return { maxNonceLength: params[0] };
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
  deviceKey: JwkEcdsaPublicKey
): {
  deviceKeyX: bigint;
  deviceKeyY: bigint;
  sig_r: bigint;
  sig_s_inverse: bigint;
  messageHash: bigint;
} {
  assert.ok(nonce.length <= params.maxNonceLength, `Nonce length exceeds maxNonceLength`);

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
  };
}
