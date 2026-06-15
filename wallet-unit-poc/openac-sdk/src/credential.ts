import { sha256 } from "@noble/hashes/sha2";
import {
  base64Decode,
  base64urlToBase64,
  base64urlEncode,
  utf8Decode,
} from "./utils.js";
import { InputError } from "./errors.js";
import type { DisclosedClaim, EcdsaPublicKey } from "./types.js";

export class Credential {
  readonly header: Record<string, unknown>;
  readonly payload: Record<string, unknown>;
  readonly signature: Uint8Array;
  readonly token: string;
  readonly claims: DisclosedClaim[];
  readonly b64Header: string;
  readonly b64Payload: string;
  readonly b64Signature: string;

  private constructor(
    token: string,
    header: Record<string, unknown>,
    payload: Record<string, unknown>,
    signature: Uint8Array,
    claims: DisclosedClaim[],
    b64Header: string,
    b64Payload: string,
    b64Signature: string
  ) {
    this.token = token;
    this.header = header;
    this.payload = payload;
    this.signature = signature;
    this.claims = claims;
    this.b64Header = b64Header;
    this.b64Payload = b64Payload;
    this.b64Signature = b64Signature;
  }

  static parse(jwt: string, disclosures: string[]): Credential {
    const parts = jwt.split(".");
    if (parts.length !== 3) {
      throw new InputError("INVALID_JWT", `Invalid JWT format: expected 3 parts, got ${parts.length}`);
    }

    const [b64Header, b64Payload, b64Signature] = parts as [string, string, string];

    let header: Record<string, unknown>;
    let payload: Record<string, unknown>;

    try {
      header = JSON.parse(utf8Decode(base64Decode(b64Header)));
    } catch (e) {
      throw new InputError("INVALID_JWT", "Failed to decode JWT header", e);
    }

    try {
      payload = JSON.parse(utf8Decode(base64Decode(b64Payload)));
    } catch (e) {
      throw new InputError("INVALID_JWT", "Failed to decode JWT payload", e);
    }

    const signature = base64Decode(b64Signature);

    const claims: DisclosedClaim[] = disclosures.map((raw, index) => {
      return parseDisclosure(raw, index);
    });

    return new Credential(jwt, header, payload, signature, claims, b64Header, b64Payload, b64Signature);
  }

  findBirthdayClaim(): number | null {
    const birthdayKeys = ["roc_birthday", "birthdate", "birthday", "date_of_birth"];

    for (const claim of this.claims) {
      if (birthdayKeys.includes(claim.name)) {
        return claim.index;
      }
    }

    return null;
  }

  get deviceBindingKey(): EcdsaPublicKey | null {
    const cnf = this.payload.cnf as { jwk?: EcdsaPublicKey } | undefined;
    if (!cnf?.jwk) return null;

    const jwk = cnf.jwk;
    if (jwk.kty !== "EC" || jwk.crv !== "P-256" || !jwk.x || !jwk.y) {
      return null;
    }

    return jwk;
  }

  get decodedPayload(): string {
    return utf8Decode(base64Decode(this.b64Payload));
  }

  get sdDigests(): string[] {
    const vc = this.payload.vc as { credentialSubject?: { _sd?: string[] } } | undefined;
    return vc?.credentialSubject?._sd ?? [];
  }

  get disclosureHashes(): string[] {
    return this.claims.map((c) => c.digest);
  }
}

// SD-JWT disclosure: base64url(JSON([salt, claim_name, claim_value]))
function parseDisclosure(raw: string, index: number): DisclosedClaim {
  let decoded: string;
  try {
    const b64 = base64urlToBase64(raw);
    decoded = utf8Decode(base64Decode(b64));
  } catch (e) {
    throw new InputError("MISSING_DISCLOSURE", `Failed to decode disclosure at index ${index}`, e);
  }

  let parsed: unknown[];
  try {
    parsed = JSON.parse(decoded);
  } catch (e) {
    throw new InputError("MISSING_DISCLOSURE", `Failed to parse disclosure JSON at index ${index}`, e);
  }

  if (!Array.isArray(parsed) || parsed.length < 3) {
    throw new InputError(
      "MISSING_DISCLOSURE",
      `Invalid disclosure format at index ${index}: expected [salt, name, value]`
    );
  }

  const [salt, name, value] = parsed;

  const digestBytes = sha256(new TextEncoder().encode(raw));
  const digest = base64urlEncode(digestBytes);

  return {
    index,
    salt: String(salt),
    name: String(name),
    value: String(value),
    raw,
    digest,
  };
}
