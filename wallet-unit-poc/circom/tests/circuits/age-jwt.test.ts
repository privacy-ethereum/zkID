import { WitnessTester } from "circomkit";
import { circomkit } from "../common";
import { generateJwtCircuitParams, generateJwtInputs } from "../../src/jwt";
import { sha256 } from "@noble/hashes/sha2";

describe("Selective Disclosure", () => {
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

  describe("Age Claim Below 18 ", () => {
    before(async () => {
      const RECOMPILE = true;
      circuit = await circomkit.WitnessTester(`JWT`, {
        file: "jwt",
        template: "JWT",
        params: [1024 * 3, 2200, 8, 50, 128],
        recompile: RECOMPILE,
      });
      console.log("#constraints:", await circuit.getConstraintCount());
    });

    it("should verify Taiwan Vc JWT", async () => {
      const token_with_claims =
        "eyJqa3UiOiJodHRwczovL2lzc3Vlci12Yy53YWxsZXQuZ292LnR3L2FwaS9rZXlzIiwia2lkIjoia2V5LTEiLCJ0eXAiOiJ2YytzZC1qd3QiLCJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJkaWQ6a2V5OnoyZG16RDgxY2dQeDhWa2k3SmJ1dU1tRllyV1BvZHJaU3FNYkN5OU5kdTRVZ1VHeTNSTmtoSDQ3OWVMUHBiZkFoVlNOdTdCNG9KdlV3THp5eGlQNEp0NWs5Y3FxbUNoYW54QWF6VEd4Sk12R3hZREFwTmtYZURXNU1QWmdaUmtqUmdEMXlhaWc1S0NFZ0FhVmJnOHpydllqTVRpMUJ6cWREcFBwa2VTRm1Kd2llajlZTlkiLCJuYmYiOjE3NDg0NDk5OTksImlzcyI6ImRpZDprZXk6ejJkbXpEODFjZ1B4OFZraTdKYnV1TW1GWXJXUGdZb3l0eWtVWjNleXFodDFqOUticlRRV1BUSk10MkZ1MTZIODR5bXdiYkc5TEdOaW5XN1luajUzWkNBVzE2Z3JBaEJpd3Y1M0FuYnY3ODdodDZueGFLTUdHQWdZOVdqdEZ4WVozaGpHZE1kMVNodVFvU3ZOZVh4Y2o1SmNiazJ1WXRmR2J3aW9GU2laUVhmekg3Y3RoaSIsImNuZiI6eyJqd2siOnsia3R5IjoiRUMiLCJjcnYiOiJQLTI1NiIsIngiOiI0OXJrcUxQb2JSRWdjcDZSSHpKNTJsNWdjQXpmSG9yZWVXbWtMTTdhQzJ3IiwieSI6IlQ2SFB5OWZnN1FOV2RvTWt2UFVOajBLeFgtUVIzeS14NUdKbmtnc2hzZnMifX0sImV4cCI6MjA2Mzk4Mjc5OSwidmMiOnsiQGNvbnRleHQiOlsiaHR0cHM6Ly93d3cudzMub3JnLzIwMTgvY3JlZGVudGlhbHMvdjEiXSwidHlwZSI6WyJWZXJpZmlhYmxlQ3JlZGVudGlhbCIsIjAwMDAwMDAwX2RlbW9fZHJpdmluZ2xpY2Vuc2VfMjAyNTA0MjUxNDE4Il0sImNyZWRlbnRpYWxTdGF0dXMiOnsidHlwZSI6IlN0YXR1c0xpc3QyMDIxRW50cnkiLCJpZCI6Imh0dHBzOi8vaXNzdWVyLXZjLndhbGxldC5nb3YudHcvYXBpL3N0YXR1cy1saXN0LzAwMDAwMDAwX2RlbW9fZHJpdmluZ2xpY2Vuc2VfMjAyNTA0MjUxNDE4L3IwIzIwIiwic3RhdHVzTGlzdEluZGV4IjoiMjAiLCJzdGF0dXNMaXN0Q3JlZGVudGlhbCI6Imh0dHBzOi8vaXNzdWVyLXZjLndhbGxldC5nb3YudHcvYXBpL3N0YXR1cy1saXN0LzAwMDAwMDAwX2RlbW9fZHJpdmluZ2xpY2Vuc2VfMjAyNTA0MjUxNDE4L3IwIiwic3RhdHVzUHVycG9zZSI6InJldm9jYXRpb24ifSwiY3JlZGVudGlhbFNjaGVtYSI6eyJpZCI6Imh0dHBzOi8vZnJvbnRlbmQud2FsbGV0Lmdvdi50dy9hcGkvc2NoZW1hLzAwMDAwMDAwL2RlbW9kcml2aW5nbGljZW5zZTIwMjUwNDI1MTQxOC9WMS9iNjUzYWQ0Yi0zYjNhLTQ2ZjktYmVjMi1kNjg3Y2U5YzMyMjIiLCJ0eXBlIjoiSnNvblNjaGVtYSJ9LCJjcmVkZW50aWFsU3ViamVjdCI6eyJfc2QiOlsiQWVsYmY0WVl0YzhCRGZhck9NMlA5NWRocHBMWU9rb2hmNkR0Z1VqZmhZVSIsIkdPdjR1Y0pjS0drMEVfb0UwZ2VJbXhTRjg5bm5IcHotUWJOclZWOXcyUm8iLCJMSkxCaGVHa3VFU1N1RXlHQkJ2U01XOXRiMHFab1B1NUtrZjVnMUMzQmZrIiwiWS0tUWIyOG5kcUVHX2YtSEdLczZvMnJJUVpVUGd2RmticWJxTGhzY0hjZyIsImNWMGROYm0wNTlfSEo2c000bkM2eUVSNE1neTdneVV2SVlGUG8tc3U0RkUiLCJyZTU0VTFZZHV5alhXLTQwVlIxc2U5cVhZM081U19UdDFpSzNsUXlUa0Y4Il0sIl9zZF9hbGciOiJzaGEtMjU2In19LCJub25jZSI6Ikk5UTBPQzNOIiwianRpIjoiaHR0cHM6Ly9pc3N1ZXItdmMud2FsbGV0Lmdvdi50dy9hcGkvY3JlZGVudGlhbC9iNzZiOTg4OC01MTFmLTQ5YTAtYjI2Yi0yYjU4YzhjNTczMDIifQ.eGndfGnmzkxRoVMLJaLVZiqxmpiccnMcdq1ytef72fGSRyqSY_tz6EF7nlyNH9FsSOBCZ6RKgfPk6HGNbk3SKg~WyJPVWpCZ1E4RFVnenRRR3dxaWVhZE13IiwibmFtZSIsIumZs-etseeOsiJd~WyJRdWRNTnlPelV2TEJQYXVrT1pfcVlnIiwiaWRfbnVtYmVyIiwiQTIzNDU2Nzg5MCJd~WyI4STBWclR0QnpNdlFFSmxmV2hqS2FBIiwicm9jX2JpcnRoZGF5IiwiMTA0MDYwNSJd~WyJhVVBlVWhVOEtRLTE4eG9DTGVDN1FRIiwidHlwZSIsIuaZrumAmuWwj-Wei-i7iiJd~WyJvQndUa0JUdmQzS2pBSXB3U21XUjNBIiwiY29udHJvbG51bWJlciIsIjQwMTA0MDIwOTE0NDUiXQ~WyJlcGtGMjdwejFVY01naHRYRV96Vi1BIiwiZ0RhdGUiLCIxMDIwNzAxIl0~";

      let [token, ...claims] = token_with_claims.split("~");
      claims = claims.filter((claim) => claim.length > 0);

      let hashedClaims = claims.map((claim) => {
        const claimBuffer = Buffer.from(claim, "utf8");
        return Buffer.from(sha256(claimBuffer)).toString("base64url");
      });

      // JSON Web Key Set(JWKS) taken from "jku":"https://issuer-vc.wallet.gov.tw/api/keys",
      const jwk = {
        kty: "EC",
        crv: "P-256",
        kid: "key-1",
        x: "dnQ2W9ZTsILYac3XdcvxrYNgIgjSkGJUMecMXVJk7XM",
        y: "0WhT_VgvnhNNj9aabTn4E4enR-iqbCrQtY9UWqD4XJY",
      };

      const params = generateJwtCircuitParams([1024 * 3, 2200, 8, 50, 128]);
      let decodeFlags = [0, 0, 1, 0, 0, 0, 0, 0];
      let inputs = generateJwtInputs(params, token, jwk, hashedClaims, claims, decodeFlags);

      const witness = await circuit.calculateWitness(inputs);
      await circuit.expectConstraintPass(witness);
    });
  });

  describe("Age Claim Above 18 ", () => {
    before(async () => {
      const RECOMPILE = true;
      circuit = await circomkit.WitnessTester(`JWT`, {
        file: "jwt",
        template: "JWT",
        params: [1024 * 3, 2200, 8, 50, 128],
        recompile: RECOMPILE,
      });
      console.log("#constraints:", await circuit.getConstraintCount());
    });

    it("should verify Taiwan Vc JWT", async () => {
      const token_with_claims =
        "eyJqa3UiOiJodHRwczovL2lzc3Vlci12Yy53YWxsZXQuZ292LnR3L2FwaS9rZXlzIiwia2lkIjoia2V5LTEiLCJ0eXAiOiJ2YytzZC1qd3QiLCJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJkaWQ6a2V5OnoyZG16RDgxY2dQeDhWa2k3SmJ1dU1tRllyV1BvZHJaU3FNYkN5OU5kdTRVZ1VHeTNSTmtoSDQ3OWVMUHBiZkFoVlNOdTdCNG9KdlV3THp5eGlQNEp0NWs5Y3FxbUNoYW54QWF6VEd4Sk12R3hZREFwTmtYZURXNU1QWmdaUmtqUmdEMXlhaWc1S0NFZ0FhVmJnOHpydllqTVRpMUJ6cWREcFBwa2VTRm1Kd2llajlZTlkiLCJuYmYiOjE3NDgzNjY5NTMsImlzcyI6ImRpZDprZXk6ejJkbXpEODFjZ1B4OFZraTdKYnV1TW1GWXJXUGdZb3l0eWtVWjNleXFodDFqOUticlRRV1BUSk10MkZ1MTZIODR5bXdiYkc5TEdOaW5XN1luajUzWkNBVzE2Z3JBaEJpd3Y1M0FuYnY3ODdodDZueGFLTUdHQWdZOVdqdEZ4WVozaGpHZE1kMVNodVFvU3ZOZVh4Y2o1SmNiazJ1WXRmR2J3aW9GU2laUVhmekg3Y3RoaSIsImNuZiI6eyJqd2siOnsia3R5IjoiRUMiLCJjcnYiOiJQLTI1NiIsIngiOiI0OXJrcUxQb2JSRWdjcDZSSHpKNTJsNWdjQXpmSG9yZWVXbWtMTTdhQzJ3IiwieSI6IlQ2SFB5OWZnN1FOV2RvTWt2UFVOajBLeFgtUVIzeS14NUdKbmtnc2hzZnMifX0sImV4cCI6MjA2Mzg5OTc1MywidmMiOnsiQGNvbnRleHQiOlsiaHR0cHM6Ly93d3cudzMub3JnLzIwMTgvY3JlZGVudGlhbHMvdjEiXSwidHlwZSI6WyJWZXJpZmlhYmxlQ3JlZGVudGlhbCIsIjAwMDAwMDAwX2RlbW9fZHJpdmluZ2xpY2Vuc2VfMjAyNTA0MjUxNDE4Il0sImNyZWRlbnRpYWxTdGF0dXMiOnsidHlwZSI6IlN0YXR1c0xpc3QyMDIxRW50cnkiLCJpZCI6Imh0dHBzOi8vaXNzdWVyLXZjLndhbGxldC5nb3YudHcvYXBpL3N0YXR1cy1saXN0LzAwMDAwMDAwX2RlbW9fZHJpdmluZ2xpY2Vuc2VfMjAyNTA0MjUxNDE4L3IwIzE5Iiwic3RhdHVzTGlzdEluZGV4IjoiMTkiLCJzdGF0dXNMaXN0Q3JlZGVudGlhbCI6Imh0dHBzOi8vaXNzdWVyLXZjLndhbGxldC5nb3YudHcvYXBpL3N0YXR1cy1saXN0LzAwMDAwMDAwX2RlbW9fZHJpdmluZ2xpY2Vuc2VfMjAyNTA0MjUxNDE4L3IwIiwic3RhdHVzUHVycG9zZSI6InJldm9jYXRpb24ifSwiY3JlZGVudGlhbFNjaGVtYSI6eyJpZCI6Imh0dHBzOi8vZnJvbnRlbmQud2FsbGV0Lmdvdi50dy9hcGkvc2NoZW1hLzAwMDAwMDAwL2RlbW9kcml2aW5nbGljZW5zZTIwMjUwNDI1MTQxOC9WMS9iNjUzYWQ0Yi0zYjNhLTQ2ZjktYmVjMi1kNjg3Y2U5YzMyMjIiLCJ0eXBlIjoiSnNvblNjaGVtYSJ9LCJjcmVkZW50aWFsU3ViamVjdCI6eyJfc2QiOlsiLXUxU0NkeVdPdmtXTkxqWVUtZEdCLUNIOVFWTTRBaTJzS0p1aVluMFprbyIsIjlFM2JJRmM1Y0Y3VDZGNmowNUV5Y3NhUGxkbnRVNjJaT2JheC11VmJyQWMiLCJGbk40ME1mMGNwTWhrU0thYWFROUR2d1NEcndfbFB0SEdiS0NPNWtHWm1BIiwiV3B2Nm93b0NyMmY2X0ZpYnB4YXBHekVLY1gzYjMxcHNfaHBxRWZEMGJEMCIsIl9FUlltdkt6d1pjbzdQNzNoNE9McGczSzE3Y2t4TkFBZlpSeUFuYVdhYUEiLCJhMDVPSDFQUmF3cHF6OFM5TXlZbndTQnVtREYyZjU4QkJvZ1Fsc0tOVVBBIl0sIl9zZF9hbGciOiJzaGEtMjU2In19LCJub25jZSI6IktaQ0k3U1MzIiwianRpIjoiaHR0cHM6Ly9pc3N1ZXItdmMud2FsbGV0Lmdvdi50dy9hcGkvY3JlZGVudGlhbC8zZmQwMTE4Yy0yZDc3LTQ4M2UtOTRjYS1iMDAzMjdmNTllNzAifQ.OqGYU5HVhUCaLfg4hK1DU0XM78WzVxEl24fNKT6vNI8jFzDilb-HGpWQ1mrGWGvi-KOI_YQQ_R9ZWpypK8y_iw~WyJmSGlPTE9ZRVFhZkF3MjBCZjRxZXpBIiwibmFtZSIsIumZs-etseeOsiJd~WyJLVXYxVF9BNXpvVDlJbXFURmUwdUxnIiwiaWRfbnVtYmVyIiwiQTIzNDU2Nzg5MCJd~WyJuTDVDa2VaV2paSG13UjcxV05lWlZ3Iiwicm9jX2JpcnRoZGF5IiwiMDU3MDYwNSJd~WyJvZFNweWFjaUNuZUJneld1VEFyM0pRIiwidHlwZSIsIuaZrumAmuWwj-Wei-i7iiJd~WyJJdFVGQUV2S0kybFJCV2MzU19LTjhnIiwiY29udHJvbG51bWJlciIsIjQwMTA0MDIwOTE0NDUiXQ~WyJROWEySWM3b1IxUjRFQ0VXX3RYaUlRIiwiZ0RhdGUiLCIxMDIwNzAxIl0~";

      let [token, ...claims] = token_with_claims.split("~");
      claims = claims.filter((claim) => claim.length > 0);

      let hashedClaims = claims.map((claim) => {
        const claimBuffer = Buffer.from(claim, "utf8");
        return Buffer.from(sha256(claimBuffer)).toString("base64url");
      });

      // JSON Web Key Set(JWKS) taken from "jku":"https://issuer-vc.wallet.gov.tw/api/keys",
      const jwk = {
        kty: "EC",
        crv: "P-256",
        kid: "key-1",
        x: "dnQ2W9ZTsILYac3XdcvxrYNgIgjSkGJUMecMXVJk7XM",
        y: "0WhT_VgvnhNNj9aabTn4E4enR-iqbCrQtY9UWqD4XJY",
      };

      const params = generateJwtCircuitParams([1024 * 3, 2200, 8, 50, 128]);
      let decodeFlags = [0, 0, 1, 0, 0, 0, 0, 0];
      let inputs = generateJwtInputs(params, token, jwk, hashedClaims, claims, decodeFlags);

      const witness = await circuit.calculateWitness(inputs);
      await circuit.expectConstraintPass(witness);
    });
  });
});
