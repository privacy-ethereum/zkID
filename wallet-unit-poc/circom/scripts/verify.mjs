import { toByteArray, fromByteArray } from 'base64-js';
import jwt from 'jsonwebtoken';
import { strict as assert } from 'assert';
import pkg from 'safer-buffer';
const { Buffer } = pkg;
import { Ber } from 'asn1';
import crypto from 'crypto';
import jwkToPem from 'jwk-to-pem';
import { sha256 } from '@noble/hashes/sha256';

function toByteArrayPad(s) {
  while (s.length % 4 != 0) {
    s = s + "=";
  }
  return toByteArray(s);
}

function get_x_y_from_der(pk) {
  const pk1 = toByteArray(pk);
  var reader = new Ber.Reader(Buffer.from(pk1));
  reader.readSequence();
  reader.readSequence();
  reader.readOID();
  reader.readOID();

  let buffer = Buffer.alloc(64)
  buffer = reader.readString(3, buffer);

  const xy = buffer.slice(2)
  const x = xy.slice(0, 32);
  const y = xy.slice(32);

  return [x, y]
}

function get_jwt_from_der(pk) {
  let [x, y] = get_x_y_from_der(pk)
  return {
    "kty": "EC",
    "crv": "P-256",
    "x": fromByteArray(x),
    "y": fromByteArray(y),
    "kid": "the key id"
  };
}

async function verify_jwt(jwt, jwk) {

  let [h, p, s] = jwt.split(".")

  const import_pk = await crypto.subtle.importKey(
    "jwk",
    jwk
    ,
    {
      name: "ECDSA",
      namedCurve: "P-256"
    },
    true,
    ["verify"]
  );

  const success = await crypto.subtle.verify(
    {
      name: "ECDSA",
      hash: { name: "SHA-256" },
    },
    import_pk,
    toByteArrayPad(s),
    Buffer.from(h + "." + p),
  );

  return success;
}

async function verify_sdjwt() {
  // generated in https://www.sdjwt.co/present
  const token_with_claims = `eyJ0eXAiOiJzZCtqd3QiLCJhbGciOiJFUzI1NiJ9.eyJpZCI6IjEyMzQiLCJfc2QiOlsiYkRUUnZtNS1Zbi1IRzdjcXBWUjVPVlJJWHNTYUJrNTdKZ2lPcV9qMVZJNCIsImV0M1VmUnlsd1ZyZlhkUEt6Zzc5aGNqRDFJdHpvUTlvQm9YUkd0TW9zRmsiLCJ6V2ZaTlMxOUF0YlJTVGJvN3NKUm4wQlpRdldSZGNob0M3VVphYkZyalk4Il0sIl9zZF9hbGciOiJzaGEtMjU2In0.n27NCtnuwytlBYtUNjgkesDP_7gN7bhaLhWNL4SWT6MaHsOjZ2ZMp987GgQRL6ZkLbJ7Cd3hlePHS84GBXPuvg~WyI1ZWI4Yzg2MjM0MDJjZjJlIiwiZmlyc3RuYW1lIiwiSm9obiJd~WyJjNWMzMWY2ZWYzNTg4MWJjIiwibGFzdG5hbWUiLCJEb2UiXQ~WyJmYTlkYTUzZWJjOTk3OThlIiwic3NuIiwiMTIzLTQ1LTY3ODkiXQ~`;
  const [token, ...claims] = token_with_claims.split("~");

  const jwk = {
    "crv": "P-256",
    "kty": "EC",
    "x": "h29tWfkCJ73nJbP51C4SotdI0CuttfQS3Svt0se6gFU",
    "y": "mBavlbiJLFhGsuIJRz7wYLiW15gpiWEDLjE1gfVh_7k"
  };
  const pem = jwkToPem(jwk);
  jwt.verify(token, pem);
  assert.ok(await verify_jwt(token, jwk));
}

async function verify_taiwan() {
  const token_with_claims = "eyJqa3UiOiJodHRwczovL2lzc3Vlci12Yy11YXQud2FsbGV0Lmdvdi50dy9hcGkva2V5cyIsImtpZCI6ImtleS0xIiwidHlwIjoidmMrc2Qtand0IiwiYWxnIjoiRVMyNTYifQ.eyJzdWIiOiJkaWQ6a2V5OnpZcU52VkNrWVhhTXNGVVhEemJvRk1DMXRSV0ZjOHBUTGRONTgzb3FhcG9LNk1veno5dEVWVWpYU2lDN3Y2eXlOR0I4TW5DZUh1SE5hWlpzczFYS1E5dktzY2EyN0VIM0NQTXFSSnN5b2pqdXRyNEtrMzJaWVE0TDRjdHpZaDVHMWhrR1I3VFlhQ0Q3ekczWU1WS0V2dWQxejhZVnR5N2lxZzhBVTZxQ3hvS25ibkVVNnJEQSIsIm5iZiI6MTczOTgxNjY3MiwiaXNzIjoiZGlkOmtleTp6MmRtekQ4MWNnUHg4VmtpN0pidXVNbUZZcldQZ1lveXR5a1VaM2V5cWh0MWo5S2JzWTlEUnFTQ2d6elJ1RmJwcTlxd0pUTGtCbm1tQlhoZFNkcTZCREpSTXg2dENHMWp0a2R3Z0tYTmZOMXFXRVJEdnhhYzVyWTZoY25GUDdIdjYzaU01eTNWeHRNTjRUc3h5WnZibnJhcFcyUnBGb3ZFMURKNG03ZURWTFN1cUd0YzFpIiwiY25mIjp7Imp3ayI6eyJrdHkiOiJFQyIsImNydiI6IlAtMjU2IiwieCI6IlBrcV82ZDJpeUIwZGVvalYyLXlta0ZWeUpNeElfTDlHZVF4aDBORExoNDQ9IiwieSI6IjBOZnFMdmUtSXEwSFZZUE11eEctWHpRNUlmNktaOFhvQ0hkNmZOaDhsZFU9In19LCJleHAiOjY3OTc3NzcxODcyLCJ2YyI6eyJAY29udGV4dCI6WyJodHRwczovL3d3dy53My5vcmcvMjAxOC9jcmVkZW50aWFscy92MSJdLCJ0eXBlIjpbIlZlcmlmaWFibGVDcmVkZW50aWFsIiwiOTM1ODE5MjVfZGQiXSwiY3JlZGVudGlhbFN0YXR1cyI6eyJ0eXBlIjoiU3RhdHVzTGlzdDIwMjFFbnRyeSIsImlkIjoiaHR0cHM6Ly9pc3N1ZXItdmMtdWF0LndhbGxldC5nb3YudHcvYXBpL3N0YXR1cy1saXN0LzkzNTgxOTI1X2RkL3IwIzYiLCJzdGF0dXNMaXN0SW5kZXgiOiI2Iiwic3RhdHVzTGlzdENyZWRlbnRpYWwiOiJodHRwczovL2lzc3Vlci12Yy11YXQud2FsbGV0Lmdvdi50dy9hcGkvc3RhdHVzLWxpc3QvOTM1ODE5MjVfZGQvcjAiLCJzdGF0dXNQdXJwb3NlIjoicmV2b2NhdGlvbiJ9LCJjcmVkZW50aWFsU2NoZW1hIjp7ImlkIjoiaHR0cHM6Ly9mcm9udGVuZC11YXQud2FsbGV0Lmdvdi50dy9hcGkvc2NoZW1hLzkzNTgxOTI1L2RkL1YxL2Q0ZDFhMGY5LTNmMDktNGMyZS1iODk5LTA4YzM0NDkwYzhlYSIsInR5cGUiOiJKc29uU2NoZW1hIn0sImNyZWRlbnRpYWxTdWJqZWN0Ijp7Il9zZCI6WyJKY2lHYzViS2lkT0dteGp1dkM4TGRVeWthVlhCWEJQaEJYMWtYcERlLUxvIiwicFZPdzJOajU3RzJOa2VWSEJDV3doRUJqdWZTSmhwOWxwM201VzltQWg5QSJdLCJfc2RfYWxnIjoic2hhLTI1NiJ9fSwibm9uY2UiOiJCSElDVTI2TiIsImp0aSI6Imh0dHBzOi8vaXNzdWVyLXZjLXVhdC53YWxsZXQuZ292LnR3L2FwaS9jcmVkZW50aWFsLzRmYzNiYTY1LTY1ZGQtNDEyNC05ZTczLWNhOWY0OWNkNzc2NyJ9.h0wBjwjBDb48wZ_XVWnnrRrWh2Sgd4Lq7sc72N54svJFklnFuHebxvn-Ui6jftnQbPnLTKEyJbE75DatCkfkdQ~WyJ1cWJ5Y0VSZlN4RXF1a0dtWGwyXzl3IiwibmFtZSIsImRlbmtlbmkiXQ~WyJYMXllNDloV0s1bTJneWFBLXROQXRnIiwicm9jX2JpcnRoZGF5IiwiMDc1MDEwMSJd~\\";
  const [token, ...claims] = token_with_claims.split("~");

  // JSON Web Key Set(JWKS)
  // "jku":"https://issuer-vc-uat.wallet.gov.tw/api/keys",
  const jku =
  {
    "keys": [
      {
        "kty": "EC",
        "crv": "P-256",
        "kid": "key-1",
        "x": "rJUIrWnliWn5brtxVJPlGNZl2hKTosVMlWDc-G-gScM",
        "y": "mm3p9quG010NysYgK-CAQz2E-wTVSNeIHl_HvWaaM6I"
      },
      {
        "kty": "EC",
        "crv": "P-256",
        "kid": "key-2",
        "x": "9CNEmxkQimYxZtsoLuHyu2w_dHrVWrXapZzpYE0qm78",
        "y": "1FNwzxeSbIAcMlsvtx3iGzyUwoAyldffbvshNooWy2Q"
      }
    ]
  };

  let verified = false;
  for (const jwk of jku["keys"]) {
    const works = await verify_jwt(token, jwk);
    if (works) {
      console.log(jwk);
      verified = true;
    }
  }

  assert.ok(verified);

  let [h, p, s] = token.split(".");
  let payload = JSON.parse(atob(p));
  for (let i = 0; i < payload.vc.credentialSubject._sd.length; i++) {
    assert.ok(payload.vc.credentialSubject._sd[i] == Buffer.from(sha256(claims[i])).toString("base64url"));
  }

}

async function check_es256() {
  const token = "eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJEaW5vQ2hpZXNhLmdpdGh1Yi5pbyIsInN1YiI6ImFyeWEiLCJhdWQiOiJraW5hIiwiaWF0IjoxNzQzNjgyNzE3LCJleHAiOjE4NDM2ODMzMTcsImFhYSI6eyJwcm9wWCI6eyJhYWEiOiJpcHhhbXAwZWdjY3QweWYyb2t1dGo5In19fQ.2g_jAb5PeW8vErjOKbHbZIsxjcIFN_mD4-XqXZzcNKy8lM9Ef5DYALjOS-6sKW2j9kLWLwJ6g7bOj-erJTT6cg";
  const pk = `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE4zBhqu2TOhVW3BBZ2kYPgk5g2R8B
/cs8T/3PQxSPcsANh7Q9OXjDn+QVizLrWTze7hi0wAQzyl4ACRMV1PBZDg==
-----END PUBLIC KEY-----`;

  // verify with jsonwebtoken 
  assert.ok(jwt.verify(token, pk));

  const pk1 = pk
    .replace("-----BEGIN PUBLIC KEY-----", "")
    .replace("-----END PUBLIC KEY-----", "")
    .replaceAll(" ", "")
    .replaceAll("\n", "");

  const jwk = get_jwt_from_der(pk1);
  assert.ok(await verify_jwt(token, jwk));

  const modified_token = token.replace("eyJhbGciOiJFUzI1NiJ9", "eyJhbGciOiJFUzI1NiJ0");
  assert.ok(!await verify_jwt(modified_token, jwk));
}

await check_es256();
await verify_sdjwt();
await verify_taiwan();
console.log("All checks ok");