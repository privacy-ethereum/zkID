// Byte-array conversion helpers. Tight, shared across clients + pipeline.

/** Encodes the verifier-issued `app_id` (a 31-byte UTF-8 string) into the
 *  exact bytes the card signs and the user-sig circuit consumes as
 *  `app_id_bytes`. Do NOT hex-decode: `app_id` is an opaque UTF-8 string and
 *  may not be valid hex (it is often 31 characters — odd-length). The native
 *  prover uses the same `.as_bytes()` path. */
export function appIdToBytes(appId: string): Uint8Array {
  return new TextEncoder().encode(appId);
}

export function hexToBytes(hex: string): Uint8Array {
  const clean = hex.startsWith("0x") || hex.startsWith("0X") ? hex.slice(2) : hex;
  if (clean.length % 2 !== 0) {
    throw new Error(`hexToBytes: odd-length hex string (${clean.length})`);
  }
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) {
    const byte = Number.parseInt(clean.slice(i * 2, i * 2 + 2), 16);
    if (Number.isNaN(byte)) {
      throw new Error(`hexToBytes: non-hex character at offset ${i * 2}`);
    }
    out[i] = byte;
  }
  return out;
}

export function bytesToHex(bytes: Uint8Array): string {
  let s = "";
  for (let i = 0; i < bytes.length; i++) {
    s += bytes[i].toString(16).padStart(2, "0");
  }
  return s;
}

export function base64ToBytes(b64: string): Uint8Array {
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}
