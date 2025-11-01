import { WitnessTester } from "circomkit";
import { circomkit } from "../common";
import { generateJwtCircuitParams, generateJwtInputs } from "../../src/jwt";
import { sha256 } from "@noble/hashes/sha2";

describe("JWT Verifier", () => {
  let circuit: WitnessTester<
    [
      "message",
      "messageLength",
      "periodIndex",
      "sig_r",
      "sig_s_inverse",
      "pubKeyX",
      "pubKeyY",
      "matchesCount",
      "matchSubstring",
      "matchLength",
      "matchIndex",
      "claims",
      "claimLengths",
      "decodeFlags"
    ],
    ["jwtClaims"]
  >;

  describe("Age JWT Claim", () => {
    before(async () => {
      const RECOMPILE = true;
      circuit = await circomkit.WitnessTester(`JWT`, {
        file: "jwt",
        template: "JWT",
        params: [2048, 2000, 4, 50, 128],
        recompile: RECOMPILE,
      });
      console.log("#constraints:", await circuit.getConstraintCount());
    });

    it("should verify Taiwan Vc JWT", async () => {
      const token_with_claims =
        "eyJqa3UiOiJodHRwczovL2lzc3Vlci12Yy11YXQud2FsbGV0Lmdvdi50dy9hcGkva2V5cyIsImtpZCI6ImtleS0xIiwidHlwIjoidmMrc2Qtand0IiwiYWxnIjoiRVMyNTYifQ.eyJzdWIiOiJkaWQ6a2V5OnpZcU52VkNrWVhhTXNGVVhEemJvRk1DMXRSV0ZjOHBUTGRONTgzb3FhcG9LNk1veno5dEVWVWpYU2lDN3Y2eXlOR0I4TW5DZUh1SE5hWlpzczFYS1E5dktzY2EyN0VIM0NQTXFSSnN5b2pqdXRyNEtrMzJaWVE0TDRjdHpZaDVHMWhrR1I3VFlhQ0Q3ekczWU1WS0V2dWQxejhZVnR5N2lxZzhBVTZxQ3hvS25ibkVVNnJEQSIsIm5iZiI6MTczOTgxNjY3MiwiaXNzIjoiZGlkOmtleTp6MmRtekQ4MWNnUHg4VmtpN0pidXVNbUZZcldQZ1lveXR5a1VaM2V5cWh0MWo5S2JzWTlEUnFTQ2d6elJ1RmJwcTlxd0pUTGtCbm1tQlhoZFNkcTZCREpSTXg2dENHMWp0a2R3Z0tYTmZOMXFXRVJEdnhhYzVyWTZoY25GUDdIdjYzaU01eTNWeHRNTjRUc3h5WnZibnJhcFcyUnBGb3ZFMURKNG03ZURWTFN1cUd0YzFpIiwiY25mIjp7Imp3ayI6eyJrdHkiOiJFQyIsImNydiI6IlAtMjU2IiwieCI6IlBrcV82ZDJpeUIwZGVvalYyLXlta0ZWeUpNeElfTDlHZVF4aDBORExoNDQ9IiwieSI6IjBOZnFMdmUtSXEwSFZZUE11eEctWHpRNUlmNktaOFhvQ0hkNmZOaDhsZFU9In19LCJleHAiOjY3OTc3NzcxODcyLCJ2YyI6eyJAY29udGV4dCI6WyJodHRwczovL3d3dy53My5vcmcvMjAxOC9jcmVkZW50aWFscy92MSJdLCJ0eXBlIjpbIlZlcmlmaWFibGVDcmVkZW50aWFsIiwiOTM1ODE5MjVfZGQiXSwiY3JlZGVudGlhbFN0YXR1cyI6eyJ0eXBlIjoiU3RhdHVzTGlzdDIwMjFFbnRyeSIsImlkIjoiaHR0cHM6Ly9pc3N1ZXItdmMtdWF0LndhbGxldC5nb3YudHcvYXBpL3N0YXR1cy1saXN0LzkzNTgxOTI1X2RkL3IwIzYiLCJzdGF0dXNMaXN0SW5kZXgiOiI2Iiwic3RhdHVzTGlzdENyZWRlbnRpYWwiOiJodHRwczovL2lzc3Vlci12Yy11YXQud2FsbGV0Lmdvdi50dy9hcGkvc3RhdHVzLWxpc3QvOTM1ODE5MjVfZGQvcjAiLCJzdGF0dXNQdXJwb3NlIjoicmV2b2NhdGlvbiJ9LCJjcmVkZW50aWFsU2NoZW1hIjp7ImlkIjoiaHR0cHM6Ly9mcm9udGVuZC11YXQud2FsbGV0Lmdvdi50dy9hcGkvc2NoZW1hLzkzNTgxOTI1L2RkL1YxL2Q0ZDFhMGY5LTNmMDktNGMyZS1iODk5LTA4YzM0NDkwYzhlYSIsInR5cGUiOiJKc29uU2NoZW1hIn0sImNyZWRlbnRpYWxTdWJqZWN0Ijp7Il9zZCI6WyJKY2lHYzViS2lkT0dteGp1dkM4TGRVeWthVlhCWEJQaEJYMWtYcERlLUxvIiwicFZPdzJOajU3RzJOa2VWSEJDV3doRUJqdWZTSmhwOWxwM201VzltQWg5QSJdLCJfc2RfYWxnIjoic2hhLTI1NiJ9fSwibm9uY2UiOiJCSElDVTI2TiIsImp0aSI6Imh0dHBzOi8vaXNzdWVyLXZjLXVhdC53YWxsZXQuZ292LnR3L2FwaS9jcmVkZW50aWFsLzRmYzNiYTY1LTY1ZGQtNDEyNC05ZTczLWNhOWY0OWNkNzc2NyJ9.h0wBjwjBDb48wZ_XVWnnrRrWh2Sgd4Lq7sc72N54svJFklnFuHebxvn-Ui6jftnQbPnLTKEyJbE75DatCkfkdQ~WyJ1cWJ5Y0VSZlN4RXF1a0dtWGwyXzl3IiwibmFtZSIsImRlbmtlbmkiXQ~WyJYMXllNDloV0s1bTJneWFBLXROQXRnIiwicm9jX2JpcnRoZGF5IiwiMDc1MDEwMSJd";
      // let hashedClaims = ["JciGc5bKidOGmxjuvC8LdUykaVXBXBPhBX1kXpDe-Lo", "pVOw2Nj57G2NkeVHBCWwhEBjufSJhp9lp3m5W9mAh9A"];

      const [token, ...claims] = token_with_claims.split("~");

      let hashedClaims = claims.map((claim) => {
        const claimBuffer = Buffer.from(claim, "utf8");
        return Buffer.from(sha256(claimBuffer)).toString("base64url");
      });

      // JSON Web Key Set(JWKS) taken from "jku":"https://issuer-vc-uat.wallet.gov.tw/api/keys",
      const jwk = {
        kty: "EC",
        crv: "P-256",
        kid: "key-1",
        x: "rJUIrWnliWn5brtxVJPlGNZl2hKTosVMlWDc-G-gScM",
        y: "mm3p9quG010NysYgK-CAQz2E-wTVSNeIHl_HvWaaM6I",
      };

      const params = generateJwtCircuitParams([2048, 2000, 4, 50, 128]);

      const decodeFlags = [0, 0, 1, 1];
      const inputs = generateJwtInputs(params, token, jwk, hashedClaims, claims, decodeFlags);

      const witness = await circuit.calculateWitness(inputs);

      await circuit.expectConstraintPass(witness);
    });
  });
});
