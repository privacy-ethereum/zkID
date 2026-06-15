import { p256 } from "@noble/curves/p256";
import { sha256 } from "@noble/hashes/sha2";
import { Field } from "@noble/curves/abstract/modular";

import {
  base64urlToBase64,
  base64Decode,
  base64ToBigInt,
  base64urlEncode,
  bytesToBigInt,
  uint8ArrayToBigIntArray,
  stringToPaddedBigIntArray,
  sha256Pad,
  encodeClaims,
  utf8Decode,
  utf8Encode,
} from "../utils.js";
import { InputError } from "../errors.js";
import { Credential } from "../credential.js";
import type {
  JwtCircuitParams,
  JwtCircuitInputs,
  EcdsaPublicKey,
  PemPublicKey,
  IssuerPublicKey,
} from "../types.js";

const Fq = Field(
  BigInt("0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551"),
);

/**
 * Convert a PEM-encoded ECDSA P-256 public key to JWK format.
 * Handles SubjectPublicKeyInfo (SPKI) format commonly used in X.509 certificates.
 */
function pemToJwk(pem: string): EcdsaPublicKey {
  // Remove PEM headers and whitespace
  const base64 = pem
    .replace(/-----BEGIN PUBLIC KEY-----/, "")
    .replace(/-----END PUBLIC KEY-----/, "")
    .replace(/-----BEGIN EC PUBLIC KEY-----/, "")
    .replace(/-----END EC PUBLIC KEY-----/, "")
    .replace(/\s/g, "");

  const der = base64Decode(base64);

  // Find the uncompressed point in the DER structure
  // P-256 uncompressed points are 65 bytes: 0x04 || 32-byte X || 32-byte Y
  // In SPKI format, this appears after the algorithm identifier
  let pointStart = -1;
  for (let i = 0; i < der.length - 64; i++) {
    if (der[i] === 0x04 && der.length - i >= 65) {
      // Verify this looks like a valid uncompressed point position
      // The byte before 0x04 in SPKI should be the BIT STRING content
      pointStart = i;
      break;
    }
  }

  if (pointStart === -1) {
    throw new InputError(
      "INVALID_KEY",
      "Could not parse PEM public key: uncompressed point marker (0x04) not found",
    );
  }

  const x = der.slice(pointStart + 1, pointStart + 33);
  const y = der.slice(pointStart + 33, pointStart + 65);

  // Validate the point is on the P-256 curve
  const xBigInt = bytesToBigInt(x);
  const yBigInt = bytesToBigInt(y);

  try {
    p256.ProjectivePoint.fromAffine({ x: xBigInt, y: yBigInt });
  } catch {
    throw new InputError(
      "INVALID_KEY",
      "PEM public key is not a valid P-256 curve point",
    );
  }

  return {
    kty: "EC",
    crv: "P-256",
    x: base64urlEncode(x),
    y: base64urlEncode(y),
  };
}

export function buildJwtCircuitInputs(
  credential: Credential,
  issuerPublicKey: IssuerPublicKey,
  params: JwtCircuitParams,
  additionalMatches: string[],
  decodeFlags: number[],
  claimFormats: number[] = [],
): JwtCircuitInputs {
  const { b64Header, b64Payload, b64Signature } = credential;

  if (b64Payload.length > params.maxB64PayloadLength) {
    throw new InputError(
      "PARAMS_EXCEEDED",
      `Payload length (${b64Payload.length}) exceeds maxB64PayloadLength (${params.maxB64PayloadLength})`,
    );
  }

  const signingInput = `${b64Header}.${b64Payload}`;

  if (signingInput.length > params.maxMessageLength) {
    throw new InputError(
      "PARAMS_EXCEEDED",
      `Message length (${signingInput.length}) exceeds maxMessageLength (${params.maxMessageLength})`,
    );
  }

  // decode signature
  const sigBytes = base64Decode(b64Signature);
  const sigHex = Array.from(sigBytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
  const sigDecoded = p256.Signature.fromCompact(sigHex);
  const sigSInverse = Fq.inv(sigDecoded.s);

  // decode public key
  let pubKeyX: bigint;
  let pubKeyY: bigint;

  if ("pem" in issuerPublicKey) {
    const jwk = pemToJwk((issuerPublicKey as PemPublicKey).pem);
    pubKeyX = base64ToBigInt(base64urlToBase64(jwk.x));
    pubKeyY = base64ToBigInt(base64urlToBase64(jwk.y));
  } else {
    const jwk = issuerPublicKey as EcdsaPublicKey;
    if (jwk.kty !== "EC" || jwk.crv !== "P-256") {
      throw new InputError(
        "INVALID_KEY",
        "Issuer public key must be P-256 EC key",
      );
    }
    pubKeyX = base64ToBigInt(base64urlToBase64(jwk.x));
    pubKeyY = base64ToBigInt(base64urlToBase64(jwk.y));
  }

  // verify signature off-chain
  const pubkey = p256.ProjectivePoint.fromAffine({ x: pubKeyX, y: pubKeyY });
  const sigForVerify = sigDecoded.toDERRawBytes();
  const check = p256.verify(
    sigForVerify,
    sha256(signingInput),
    pubkey.toRawBytes(),
  );
  if (!check) {
    throw new InputError(
      "INVALID_SIGNATURE",
      "JWT signature verification failed",
    );
  }

  // SHA-256 pad the message
  const messageBytes = utf8Encode(signingInput);
  const [messagePadded, messagePaddedLen] = sha256Pad(
    messageBytes,
    params.maxMessageLength,
  );

  // payload matching
  const decodedPayload = utf8Decode(base64Decode(b64Payload));

  // first two patterns are always "x":" and "y":" for device key extraction
  const patterns = ['"x":"', '"y":"', ...additionalMatches];

  if (patterns.length > params.maxMatches) {
    throw new InputError(
      "PARAMS_EXCEEDED",
      `Total patterns (${patterns.length}) exceeds maxMatches (${params.maxMatches})`,
    );
  }

  const matchSubstring: bigint[][] = [];
  const matchLength: number[] = [];
  const matchIndex: number[] = [];

  for (const pattern of patterns) {
    if (pattern.length > params.maxSubstringLength) {
      throw new InputError(
        "PARAMS_EXCEEDED",
        `Pattern "${pattern}" length exceeds maxSubstringLength (${params.maxSubstringLength})`,
      );
    }

    const index = decodedPayload.indexOf(pattern);
    if (index === -1) {
      throw new InputError(
        "CLAIM_NOT_FOUND",
        `Pattern "${pattern}" not found in JWT payload`,
      );
    }

    matchSubstring.push(
      stringToPaddedBigIntArray(pattern, params.maxSubstringLength),
    );
    matchLength.push(pattern.length);
    matchIndex.push(index);
  }

  // pad remaining match slots
  while (matchSubstring.length < params.maxMatches) {
    matchSubstring.push(
      stringToPaddedBigIntArray("", params.maxSubstringLength),
    );
    matchLength.push(0);
    matchIndex.push(0);
  }

  // claims processing: claim-only slots (maxClaims = maxMatches - 2)
  const maxClaims = params.maxMatches - 2;
  const rawDisclosures = credential.claims.map((c) => c.raw);
  const { claimArray, claimLengths } = encodeClaims(
    rawDisclosures,
    maxClaims,
    params.maxClaimLength,
  );

  // align decode flags to claim-only slots
  const decodeFlagsOut: number[] = [];
  for (let i = 0; i < maxClaims; i++) {
    decodeFlagsOut.push(i < decodeFlags.length ? decodeFlags[i]! : 0);
  }

  // Build claimFormats array for claim-only slots
  // Default: uint (1) for unspecified formats
  const claimFormatsOut: bigint[] = [];
  for (let i = 0; i < maxClaims; i++) {
    claimFormatsOut.push(BigInt(i < claimFormats.length ? claimFormats[i]! : 1));
  }

  return {
    sig_r: sigDecoded.r,
    sig_s_inverse: sigSInverse,
    pubKeyX,
    pubKeyY,
    message: uint8ArrayToBigIntArray(messagePadded),
    messageLength: messagePaddedLen,
    periodIndex: credential.token.indexOf("."),
    matchesCount: patterns.length,
    matchSubstring,
    matchLength,
    matchIndex,
    claims: claimArray,
    claimLengths,
    decodeFlags: decodeFlagsOut,
    claimFormats: claimFormatsOut,
  };
}
