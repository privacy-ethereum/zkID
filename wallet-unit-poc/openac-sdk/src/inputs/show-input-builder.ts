import { p256 } from "@noble/curves/p256";
import { sha256 } from "@noble/hashes/sha2";
import { Field } from "@noble/curves/abstract/modular";

import {
  base64urlToBase64,
  base64Decode,
  base64urlToBigInt,
  bytesToBigInt,
  utf8Decode,
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

export function buildShowCircuitInputs(
  params: ShowCircuitParams,
  nonce: string,
  userSignature: string,
  deviceKey: EcdsaPublicKey,
  claim: string,
  currentDate: { year: number; month: number; day: number }
): ShowCircuitInputs {
  const decodedLen = Math.floor((params.maxClaimsLength * 3) / 4);

  // decode the claim from base64url
  const b64 = base64urlToBase64(claim);
  const decodedClaimBytes = base64Decode(b64);
  const decodedClaim = utf8Decode(decodedClaimBytes);

  if (decodedClaim.length > decodedLen) {
    throw new InputError(
      "PARAMS_EXCEEDED",
      `Decoded claim length (${decodedClaim.length}) exceeds circuit capacity (${decodedLen})`
    );
  }

  const claimArray: bigint[] = Array(decodedLen).fill(0n) as bigint[];
  for (let i = 0; i < decodedClaim.length; i++) {
    claimArray[i] = BigInt(decodedClaim.charCodeAt(i));
  }

  // validate date
  if (!Number.isInteger(currentDate.year) || currentDate.year <= 0) {
    throw new InputError("INVALID_KEY", "Current year must be a positive integer");
  }
  if (!Number.isInteger(currentDate.month) || currentDate.month < 1 || currentDate.month > 12) {
    throw new InputError("INVALID_KEY", "Current month must be between 1 and 12");
  }
  if (!Number.isInteger(currentDate.day) || currentDate.day < 1 || currentDate.day > 31) {
    throw new InputError("INVALID_KEY", "Current day must be between 1 and 31");
  }

  // decode the device signature
  const sigBytes = base64Decode(userSignature);
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

  return {
    deviceKeyX,
    deviceKeyY,
    sig_r: sigDecoded.r,
    sig_s_inverse: sigSInverse,
    messageHash: messageHashModQ,
    claim: claimArray,
    currentYear: BigInt(currentDate.year),
    currentMonth: BigInt(currentDate.month),
    currentDay: BigInt(currentDate.day),
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
