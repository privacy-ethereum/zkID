const latest_token =
  "eyJqa3UiOiJodHRwczovL2lzc3Vlci12Yy53YWxsZXQuZ292LnR3L2FwaS9rZXlzIiwia2lkIjoia2V5LTEiLCJ0eXAiOiJ2YytzZC1qd3QiLCJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJkaWQ6a2V5OnoyZG16RDgxY2dQeDhWa2k3SmJ1dU1tRllyV1BvZHJaU3FNYkN5OU5kdTRVZ1VHeTNSTmtoSDQ3OWVMUHBiZkFoVlNOdTdCNG9KdlV3THp5eGlQNEp0NWs5Y3FxbUNoYW54QWF6VEd4Sk12R3hZREFwTmtYZURXNU1QWmdaUmtqUmdEMXlhaWc1S0NFZ0FhVmJnOHpydllqTVRpMUJ6cWREcFBwa2VTRm1Kd2llajlZTlkiLCJuYmYiOjE3NDg0NDk5OTksImlzcyI6ImRpZDprZXk6ejJkbXpEODFjZ1B4OFZraTdKYnV1TW1GWXJXUGdZb3l0eWtVWjNleXFodDFqOUticlRRV1BUSk10MkZ1MTZIODR5bXdiYkc5TEdOaW5XN1luajUzWkNBVzE2Z3JBaEJpd3Y1M0FuYnY3ODdodDZueGFLTUdHQWdZOVdqdEZ4WVozaGpHZE1kMVNodVFvU3ZOZVh4Y2o1SmNiazJ1WXRmR2J3aW9GU2laUVhmekg3Y3RoaSIsImNuZiI6eyJqd2siOnsia3R5IjoiRUMiLCJjcnYiOiJQLTI1NiIsIngiOiI0OXJrcUxQb2JSRWdjcDZSSHpKNTJsNWdjQXpmSG9yZWVXbWtMTTdhQzJ3IiwieSI6IlQ2SFB5OWZnN1FOV2RvTWt2UFVOajBLeFgtUVIzeS14NUdKbmtnc2hzZnMifX0sImV4cCI6MjA2Mzk4Mjc5OSwidmMiOnsiQGNvbnRleHQiOlsiaHR0cHM6Ly93d3cudzMub3JnLzIwMTgvY3JlZGVudGlhbHMvdjEiXSwidHlwZSI6WyJWZXJpZmlhYmxlQ3JlZGVudGlhbCIsIjAwMDAwMDAwX2RlbW9fZHJpdmluZ2xpY2Vuc2VfMjAyNTA0MjUxNDE4Il0sImNyZWRlbnRpYWxTdGF0dXMiOnsidHlwZSI6IlN0YXR1c0xpc3QyMDIxRW50cnkiLCJpZCI6Imh0dHBzOi8vaXNzdWVyLXZjLndhbGxldC5nb3YudHcvYXBpL3N0YXR1cy1saXN0LzAwMDAwMDAwX2RlbW9fZHJpdmluZ2xpY2Vuc2VfMjAyNTA0MjUxNDE4L3IwIzIwIiwic3RhdHVzTGlzdEluZGV4IjoiMjAiLCJzdGF0dXNMaXN0Q3JlZGVudGlhbCI6Imh0dHBzOi8vaXNzdWVyLXZjLndhbGxldC5nb3YudHcvYXBpL3N0YXR1cy1saXN0LzAwMDAwMDAwX2RlbW9fZHJpdmluZ2xpY2Vuc2VfMjAyNTA0MjUxNDE4L3IwIiwic3RhdHVzUHVycG9zZSI6InJldm9jYXRpb24ifSwiY3JlZGVudGlhbFNjaGVtYSI6eyJpZCI6Imh0dHBzOi8vZnJvbnRlbmQud2FsbGV0Lmdvdi50dy9hcGkvc2NoZW1hLzAwMDAwMDAwL2RlbW9kcml2aW5nbGljZW5zZTIwMjUwNDI1MTQxOC9WMS9iNjUzYWQ0Yi0zYjNhLTQ2ZjktYmVjMi1kNjg3Y2U5YzMyMjIiLCJ0eXBlIjoiSnNvblNjaGVtYSJ9LCJjcmVkZW50aWFsU3ViamVjdCI6eyJfc2QiOlsiQWVsYmY0WVl0YzhCRGZhck9NMlA5NWRocHBMWU9rb2hmNkR0Z1VqZmhZVSIsIkdPdjR1Y0pjS0drMEVfb0UwZ2VJbXhTRjg5bm5IcHotUWJOclZWOXcyUm8iLCJMSkxCaGVHa3VFU1N1RXlHQkJ2U01XOXRiMHFab1B1NUtrZjVnMUMzQmZrIiwiWS0tUWIyOG5kcUVHX2YtSEdLczZvMnJJUVpVUGd2RmticWJxTGhzY0hjZyIsImNWMGROYm0wNTlfSEo2c000bkM2eUVSNE1neTdneVV2SVlGUG8tc3U0RkUiLCJyZTU0VTFZZHV5alhXLTQwVlIxc2U5cVhZM081U19UdDFpSzNsUXlUa0Y4Il0sIl9zZF9hbGciOiJzaGEtMjU2In19LCJub25jZSI6Ikk5UTBPQzNOIiwianRpIjoiaHR0cHM6Ly9pc3N1ZXItdmMud2FsbGV0Lmdvdi50dy9hcGkvY3JlZGVudGlhbC9iNzZiOTg4OC01MTFmLTQ5YTAtYjI2Yi0yYjU4YzhjNTczMDIifQ.eGndfGnmzkxRoVMLJaLVZiqxmpiccnMcdq1ytef72fGSRyqSY_tz6EF7nlyNH9FsSOBCZ6RKgfPk6HGNbk3SKg";

const keys = [
  {
    kty: "EC",
    crv: "P-256",
    kid: "key-1",
    x: "dnQ2W9ZTsILYac3XdcvxrYNgIgjSkGJUMecMXVJk7XM",
    y: "0WhT_VgvnhNNj9aabTn4E4enR-iqbCrQtY9UWqD4XJY",
  },
];

async function verifyJWTWithKeys(token, keys) {
  const [b64Header, b64Payload, b64Signature] = token.split(".");
  const header = JSON.parse(Buffer.from(b64Header, "base64url").toString("utf8"));
  const kid = header.kid;

  const key = keys.find((k) => k.kid === kid);
  if (!key) {
    console.error(`❌ No matching key for kid: ${kid}`);
    return false;
  }

  const message = `${b64Header}.${b64Payload}`;
  const messageBytes = new TextEncoder().encode(message);

  const sig = Buffer.from(b64Signature, "base64url");

  const jwk = {
    kty: key.kty,
    crv: key.crv,
    x: key.x,
    y: key.y,
    ext: true,
  };

  try {
    const cryptoKey = await crypto.subtle.importKey(
      "jwk",
      jwk,
      {
        name: "ECDSA",
        namedCurve: "P-256",
      },
      false,
      ["verify"]
    );

    const verified = await crypto.subtle.verify(
      {
        name: "ECDSA",
        hash: { name: "SHA-256" },
      },
      cryptoKey,
      sig,
      messageBytes
    );

    return verified;
  } catch (err) {
    console.error("Verification error:", err);
    return false;
  }
}

async function main() {
  const old_res = await verifyJWTWithKeys(latest_token, keys);
  console.log("Old verification result:", old_res);
}
main();
