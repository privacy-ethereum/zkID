import {
  generateMdocCircuitParams,
  generateMdocInputs,
  parseMdocClaims,
  type MdocClaimType,
} from "../../src/mdoc.ts";
import { createTestMdocCredential, type TestMdocCredential } from "../../src/mdoc-fixture.ts";

export const MDOC_PARAMS = [1792, 256, 4, 32, 64, 64] as const;

export type MdocClaimConfig = Record<string, { type: MdocClaimType }>;

export async function buildMdocWitness(
  claimConfig: MdocClaimConfig,
  claimValues?: Record<string, string>,
): Promise<{
  cred: TestMdocCredential;
  inputs: ReturnType<typeof generateMdocInputs>;
}> {
  const cred = await createTestMdocCredential(claimValues);
  const params = generateMdocCircuitParams([...MDOC_PARAMS]);
  const { claims, deviceKeyPrefixData } = parseMdocClaims(cred.tbsData, cred.items, cred.deviceKeyX, claimConfig);
  const inputs = generateMdocInputs(
    params,
    cred.tbsData,
    cred.signature,
    cred.issuerPubRaw,
    claims,
    deviceKeyPrefixData,
  );
  return { cred, inputs };
}

/** "YYYY-MM-DD" -> YYYYMMDD integer (matches the circuit's date path). */
export function ymdToYyyymmdd(ymd: string): bigint {
  const [y, m, d] = ymd.split("-").map(Number);
  return BigInt(y * 10000 + m * 100 + d);
}

/** UTF-8 string -> base-256 BigInt, LSB first (matches RevealClaimValue). */
export function packString(s: string): bigint {
  const buf = Buffer.from(s, "utf-8");
  let n = 0n;
  for (let i = 0; i < buf.length; i++) n += BigInt(buf[i]) * 256n ** BigInt(i);
  return n;
}
