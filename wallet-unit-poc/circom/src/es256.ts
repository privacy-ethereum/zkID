import { p256 } from "@noble/curves/p256";
import { sha256Pad } from "@zk-email/helpers";
import { sha256 } from "@noble/hashes/sha2";
import { strict as assert } from "assert";
import { extractXYFromPEM, base64ToBigInt, base64urlToBase64, uint8ArrayToBigIntArray } from "./utils.ts";
import { Field } from "@noble/curves/abstract/modular";

// ES256 Circuit Parameters
export interface Es256CircuitParams {
  maxMessageLength: number;
}

// ECDSA Public Key
export interface JwkEcdsaPublicKey {
  kty: string;
  crv: string;
  kid?: string;
  x: string;
  y: string;
}

// PEM Public Key
export interface PemPublicKey {
  pem: string;
}

// Generate ES256 Circuit Parameters
export function generateEs256CircuitParams(params: number[]): Es256CircuitParams {
  return {
    maxMessageLength: params[0],
  };
}

// Generate inputs for the ES256 circuit
export function generateES256Inputs(
  params: Es256CircuitParams,
  message: string,
  b64Signature: string,
  pk: JwkEcdsaPublicKey | PemPublicKey
) {
  assert.ok(message.length <= params.maxMessageLength);

  // decode signature
  let sig = Buffer.from(b64Signature, "base64url");
  let sig_decoded = p256.Signature.fromCompact(sig.toString("hex"));
  // We need to invert `s` in the scalar field of p256
  let Fq = Field(BigInt("0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551"));
  let sig_s_inverse = Fq.inv(sig_decoded.s);

  // decode public key
  let x, y;
  if ("pem" in pk) {
    let pk1 = pk.pem
      .replace("-----BEGIN PUBLIC KEY-----", "")
      .replace("-----END PUBLIC KEY-----", "")
      .replaceAll("\n", "");
    [x, y] = extractXYFromPEM(pk1);
  } else {
    assert.ok(pk.kty == "EC");
    assert.ok(pk.crv == "P-256");
    [x, y] = [base64ToBigInt(base64urlToBase64(pk.x)), base64ToBigInt(base64urlToBase64(pk.y))];
  }

  // internal check
  let pubkey = new p256.Point(x, y, 1n);
  let check = p256.verify(sig, sha256(message), pubkey.toRawBytes());
  assert.ok(check, "internal check of signature failed");

  // generate padded message
  const encoder = new TextEncoder();
  const messageUint8Array = encoder.encode(message);

  let [messagePadded, messagePaddedLen] = sha256Pad(messageUint8Array, params.maxMessageLength);

  // return inputs
  return {
    sig_r: sig_decoded.r,
    sig_s_inverse: sig_s_inverse,
    pubKeyX: x,
    pubKeyY: y,
    message: uint8ArrayToBigIntArray(messagePadded),
    messageLength: messagePaddedLen,
  };
}
