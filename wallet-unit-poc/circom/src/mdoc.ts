import { p256 } from "@noble/curves/p256";
import { Field } from "@noble/curves/abstract/modular";
import { sha256 } from "@noble/hashes/sha2";
import { sha256Pad } from "@zk-email/helpers";
import { strict as assert } from "assert";
import { uint8ArrayToBigIntArray } from "./utils.ts";

export const ISO_NAMESPACE = "org.iso.18013.5.1";
export const MDL_DOCTYPE = "org.iso.18013.5.1.mDL";

export type MdocClaimType = "date" | "string" | "integer" | "reveal_digest";

export interface MdocCircuitParams {
  maxCredLen: number;
  maxPreimageLen: number;
  maxClaims: number;
  maxIdentifierLen: number;
  maxValueLen: number;
}

export interface MdocClaimConfig {
  type: MdocClaimType;
  identifier: string;
  preimage: Uint8Array;
  identifierCborPos: number;
  elementValueLabelPos: number;
  digestId: number;
  valueStart: number;
  valueEnd: number;
}

export interface ParsedIssuerSignedItem {
  identifier: string;
  digestId: number;
  preimage: Uint8Array;
  identifierCborPos: number;
  elementValueLabelPos: number;
  valueStart: number;
  valueEnd: number;
}

export function generateMdocCircuitParams(params: number[]): MdocCircuitParams {
  assert.equal(params.length, 5, `Expected 5 MDOC params, got ${params.length}`);
  return {
    maxCredLen: params[0],
    maxPreimageLen: params[1],
    maxClaims: params[2],
    maxIdentifierLen: params[3],
    maxValueLen: params[4],
  };
}

const Fn = Field(p256.CURVE.n);
const UTF8 = new TextEncoder();

// CBOR: text(10)"validUntil" || tag(0) || text(20)
const VALID_UNTIL_PREFIX = concatBytes(Uint8Array.of(0x6a), UTF8.encode("validUntil"), Uint8Array.of(0xc0, 0x74));

const VALUE_TYPE: Record<MdocClaimType, bigint> = {
  date: 0n,
  string: 1n,
  integer: 2n,
  reveal_digest: 3n,
};

function concatBytes(...parts: Uint8Array[]): Uint8Array {
  const total = parts.reduce((n, p) => n + p.length, 0);
  const out = new Uint8Array(total);
  let off = 0;
  for (const p of parts) {
    out.set(p, off);
    off += p.length;
  }
  return out;
}

function mustFind(haystack: Uint8Array, needle: Uint8Array, label: string): number {
  outer: for (let i = 0; i <= haystack.length - needle.length; i++) {
    for (let j = 0; j < needle.length; j++) {
      if (haystack[i + j] !== needle[j]) continue outer;
    }
    return i;
  }
  throw new Error(`${label}: not found`);
}

function encodeIdentifierCbor(identifier: string): Uint8Array {
  const utf8 = UTF8.encode(identifier);
  assert.ok(utf8.length < 24, `Identifier too long for single-byte CBOR length: ${identifier}`);
  const out = new Uint8Array(1 + utf8.length);
  out[0] = 0x60 | utf8.length;
  out.set(utf8, 1);
  return out;
}

function zeroPad(data: Uint8Array, targetLen: number): bigint[] {
  const out = new Array<bigint>(targetLen).fill(0n);
  for (let i = 0; i < Math.min(data.length, targetLen); i++) out[i] = BigInt(data[i]);
  return out;
}

function bytesToBigIntBE(bytes: Uint8Array): bigint {
  let n = 0n;
  for (const b of bytes) n = (n << 8n) | BigInt(b);
  return n;
}

function assertSignatureValid(tbsData: Uint8Array, signature: Uint8Array, issuerPubKeyRaw: Uint8Array): void {
  const msgHash = sha256(tbsData);
  if (!p256.verify(signature, msgHash, issuerPubKeyRaw)) {
    throw new Error("Internal ECDSA signature verification failed");
  }
}

interface ClaimSlotInputs {
  preimage: bigint[];
  preimageLength: bigint;
  identifierCbor: bigint[];
  identifierLength: bigint;
  identifierPosition: bigint;
  digestId: bigint;
  encodedDigestPosition: bigint;
  elementValueLabelPosition: bigint;
  valueStart: bigint;
  valueEnd: bigint;
  valueType: bigint;
  claimFlag: bigint;
  digestInputPadded: bigint[];
  digestInputPaddedLen: bigint;
}

function encodeActiveSlot(params: MdocCircuitParams, tbsData: Uint8Array, claim: MdocClaimConfig): ClaimSlotInputs {
  assert.ok(
    claim.preimage.length <= params.maxPreimageLen,
    `Preimage for "${claim.identifier}" too long: ${claim.preimage.length} > ${params.maxPreimageLen}`,
  );

  const [paddedPreimage, paddedPreimageLen] = sha256Pad(claim.preimage, params.maxPreimageLen);

  const idCbor = encodeIdentifierCbor(claim.identifier);
  assert.ok(
    idCbor.length <= params.maxIdentifierLen,
    `Identifier CBOR for "${claim.identifier}" too long: ${idCbor.length} > ${params.maxIdentifierLen}`,
  );

  // digestId (1B) || 0x58 0x20 (bytes(32)) || SHA-256(preimage)
  const preimageHash = sha256(claim.preimage);
  const encodedDigest = new Uint8Array(35);
  encodedDigest[0] = claim.digestId;
  encodedDigest[1] = 0x58;
  encodedDigest[2] = 0x20;
  encodedDigest.set(preimageHash, 3);
  const encodedDigestPos = mustFind(tbsData, encodedDigest, `encoded digest for "${claim.identifier}"`);

  // reveal_digest hashes value bytes in-circuit; others get a padded zero.
  const digestInput =
    claim.type === "reveal_digest" ? claim.preimage.slice(claim.valueStart, claim.valueEnd) : Uint8Array.of(0);
  const [paddedDigestInput, paddedDigestInputLen] = sha256Pad(digestInput, params.maxValueLen);

  return {
    preimage: uint8ArrayToBigIntArray(paddedPreimage),
    preimageLength: BigInt(paddedPreimageLen),
    identifierCbor: zeroPad(idCbor, params.maxIdentifierLen),
    identifierLength: BigInt(idCbor.length),
    identifierPosition: BigInt(claim.identifierCborPos),
    digestId: BigInt(claim.digestId),
    encodedDigestPosition: BigInt(encodedDigestPos),
    elementValueLabelPosition: BigInt(claim.elementValueLabelPos),
    valueStart: BigInt(claim.valueStart),
    valueEnd: BigInt(claim.valueEnd),
    valueType: VALUE_TYPE[claim.type],
    claimFlag: 1n,
    digestInputPadded: uint8ArrayToBigIntArray(paddedDigestInput),
    digestInputPaddedLen: BigInt(paddedDigestInputLen),
  };
}

function encodeInactiveSlot(params: MdocCircuitParams): ClaimSlotInputs {
  const dummy = Uint8Array.of(0);
  const [paddedPreimage, paddedPreimageLen] = sha256Pad(dummy, params.maxPreimageLen);
  const [paddedDigestInput, paddedDigestInputLen] = sha256Pad(dummy, params.maxValueLen);

  return {
    preimage: uint8ArrayToBigIntArray(paddedPreimage),
    preimageLength: BigInt(paddedPreimageLen),
    identifierCbor: new Array<bigint>(params.maxIdentifierLen).fill(0n),
    identifierLength: 0n,
    identifierPosition: 0n,
    digestId: 0n,
    encodedDigestPosition: 0n,
    elementValueLabelPosition: 0n,
    valueStart: 0n,
    valueEnd: 0n,
    valueType: VALUE_TYPE.string,
    claimFlag: 0n,
    digestInputPadded: uint8ArrayToBigIntArray(paddedDigestInput),
    digestInputPaddedLen: BigInt(paddedDigestInputLen),
  };
}

export function generateMdocInputs(
  params: MdocCircuitParams,
  tbsData: Uint8Array,
  signature: Uint8Array,
  issuerPubKeyRaw: Uint8Array,
  claims: MdocClaimConfig[],
  deviceKeyPos: number,
) {
  assert.ok(tbsData.length <= params.maxCredLen, `tbsData too long: ${tbsData.length} > ${params.maxCredLen}`);
  assert.ok(claims.length <= params.maxClaims, `Too many claims: ${claims.length} > ${params.maxClaims}`);
  assert.equal(signature.length, 64, `Signature must be 64 bytes (R||S), got ${signature.length}`);
  assert.equal(issuerPubKeyRaw.length, 65, `Issuer pubkey must be 65 bytes (04||x||y), got ${issuerPubKeyRaw.length}`);
  assert.equal(issuerPubKeyRaw[0], 0x04, "Issuer pubkey must start with 0x04");

  assertSignatureValid(tbsData, signature, issuerPubKeyRaw);

  const [messagePadded, messagePaddedLen] = sha256Pad(tbsData, params.maxCredLen);

  const sigR = bytesToBigIntBE(signature.slice(0, 32));
  const sigS = bytesToBigIntBE(signature.slice(32, 64));

  const validUntilPrefixPos = mustFind(tbsData, VALID_UNTIL_PREFIX, "validUntil prefix");

  const slots: ClaimSlotInputs[] = [];
  for (let i = 0; i < params.maxClaims; i++) {
    slots.push(i < claims.length ? encodeActiveSlot(params, tbsData, claims[i]) : encodeInactiveSlot(params));
  }

  return {
    message: uint8ArrayToBigIntArray(messagePadded),
    messageLength: BigInt(messagePaddedLen),
    pubKeyX: bytesToBigIntBE(issuerPubKeyRaw.slice(1, 33)),
    pubKeyY: bytesToBigIntBE(issuerPubKeyRaw.slice(33, 65)),
    sig_r: sigR,
    sig_s_inverse: Fn.inv(sigS),
    validUntilPrefixPos: BigInt(validUntilPrefixPos),
    deviceKeyPos: BigInt(deviceKeyPos),
    preimages: slots.map((s) => s.preimage),
    preimageLengths: slots.map((s) => s.preimageLength),
    identifierCbor: slots.map((s) => s.identifierCbor),
    identifierLengths: slots.map((s) => s.identifierLength),
    identifierPositions: slots.map((s) => s.identifierPosition),
    digestIds: slots.map((s) => s.digestId),
    encodedDigestPositions: slots.map((s) => s.encodedDigestPosition),
    elementValueLabelPositions: slots.map((s) => s.elementValueLabelPosition),
    valueStarts: slots.map((s) => s.valueStart),
    valueEnds: slots.map((s) => s.valueEnd),
    valueTypes: slots.map((s) => s.valueType),
    claimFlags: slots.map((s) => s.claimFlag),
    digestInputsPadded: slots.map((s) => s.digestInputPadded),
    digestInputsPaddedLen: slots.map((s) => s.digestInputPaddedLen),
  };
}

// COSE_Key EC2 coordinate markers: `-2: bytes(32)` and `-3: bytes(32)`.
const COSE_X_MARKER = Uint8Array.of(0x21, 0x58, 0x20);
const COSE_Y_MARKER = Uint8Array.of(0x22, 0x58, 0x20);

function matchesAt(haystack: Uint8Array, needle: Uint8Array, pos: number): boolean {
  if (pos < 0 || pos + needle.length > haystack.length) return false;
  return needle.every((b, i) => haystack[pos + i] === b);
}

// Returns the index of the 0x21 marker, i.e. 3 bytes before the x coordinate.
// The circuit constrains both markers, so a credential whose COSE_Key uses a
// non-canonical encoding must fail here rather than at witness generation.
function locateDeviceKeyPos(tbsData: Uint8Array, deviceKeyX: Uint8Array): number {
  const dkXPos = mustFind(tbsData, deviceKeyX, "device key x-coord");
  const pos = dkXPos - 3;
  assert.ok(matchesAt(tbsData, COSE_X_MARKER, pos), "device key x is not preceded by COSE -2: bytes(32)");
  assert.ok(
    matchesAt(tbsData, COSE_Y_MARKER, dkXPos + 32),
    "device key y does not follow x at the canonical COSE -3: bytes(32) offset",
  );
  return pos;
}

export function parseMdocClaims(
  tbsData: Uint8Array,
  items: ParsedIssuerSignedItem[],
  deviceKeyX: Uint8Array,
  claimConfig: Record<string, { type: MdocClaimType }>,
): { claims: MdocClaimConfig[]; deviceKeyPos: number } {
  const claims: MdocClaimConfig[] = [];
  for (const item of items) {
    const cfg = claimConfig[item.identifier];
    if (!cfg) continue;
    claims.push({
      type: cfg.type,
      identifier: item.identifier,
      preimage: item.preimage,
      identifierCborPos: item.identifierCborPos,
      elementValueLabelPos: item.elementValueLabelPos,
      digestId: item.digestId,
      valueStart: item.valueStart,
      valueEnd: item.valueEnd,
    });
  }
  return { claims, deviceKeyPos: locateDeviceKeyPos(tbsData, deviceKeyX) };
}
