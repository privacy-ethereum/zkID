import { describe, it, expect } from "vitest";
import { Credential } from "../src/credential.js";
import { base64urlEncode } from "../src/utils.js";

const NOW = 1_800_000_000;

function jwt(
  header: Record<string, unknown>,
  payloadOverrides: Record<string, unknown> = {},
) {
  const payload = {
    iss: "did:key:issuer",
    nbf: NOW - 1000,
    exp: NOW + 1000,
    cnf: {
      jwk: { kty: "EC", crv: "P-256", x: "eA", y: "eQ" },
    },
    vc: { credentialSubject: { _sd: [], _sd_alg: "sha-256" } },
    ...payloadOverrides,
  };
  const enc = (o: unknown) =>
    base64urlEncode(new TextEncoder().encode(JSON.stringify(o)));
  return `${enc(header)}.${enc(payload)}.c2ln`;
}

const GOOD_HEADER = { alg: "ES256", typ: "vc+sd-jwt" };

describe("credential profile + validity gate", () => {
  it("accepts an in-profile, in-validity credential", () => {
    expect(() =>
      Credential.parse(jwt(GOOD_HEADER), [], { now: NOW }),
    ).not.toThrow();
  });

  it.each([
    ["alg none", { alg: "none", typ: "vc+sd-jwt" }, {}],
    ["alg HS256", { alg: "HS256", typ: "vc+sd-jwt" }, {}],
    ["unknown typ", { alg: "ES256", typ: "at+jwt" }, {}],
    ["crit header", { ...GOOD_HEADER, crit: ["x"] }, {}],
  ])("rejects %s", (_name, header, payload) => {
    expect(() => Credential.parse(jwt(header, payload), [], { now: NOW })).toThrow(
      /INVALID_JWT|Unsupported/,
    );
  });

  it.each([
    ["expired", { exp: NOW - 3600 }],
    ["not yet valid", { nbf: NOW + 3600 }],
    ["non-numeric exp", { exp: "9999999999" }],
    ["wrong _sd_alg", { vc: { credentialSubject: { _sd: [], _sd_alg: "sha-512" } } }],
  ])("rejects %s", (_name, payload) => {
    expect(() =>
      Credential.parse(jwt(GOOD_HEADER, payload), [], { now: NOW }),
    ).toThrow();
  });

  it("rejects a missing exp only when requireExpiry is set", () => {
    const noExp = jwt(GOOD_HEADER, { exp: undefined });
    expect(() => Credential.parse(noExp, [], { now: NOW })).not.toThrow();
    expect(() =>
      Credential.parse(noExp, [], { now: NOW, requireExpiry: true }),
    ).toThrow(/no exp/);
  });
});
