import { describe, expect, it, vi } from "vitest";

import { setupFetchMock } from "./test-utils";
import { createChallenge, submitLinkVerify } from "./verifier-client";

const VERIFIER = "http://localhost:8080";

describe("verifier-client", () => {
  setupFetchMock({ VITE_VERIFIER_BASE_URL: VERIFIER });

  it("POSTs /challenge and returns the parsed body", async () => {
    const payload = {
      challenge_id: "abc",
      challenge_bytes: "AAAA",
      expires_at: "2026-04-20T12:00:00Z",
    };
    const fetchSpy = vi.fn(async (url: RequestInfo | URL, init?: RequestInit) => {
      expect(String(url)).toMatch(/\/challenge$/);
      expect(init?.method).toBe("POST");
      return new Response(JSON.stringify(payload), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      });
    }) as typeof fetch;
    globalThis.fetch = fetchSpy;

    await expect(createChallenge()).resolves.toEqual(payload);
  });

  it("throws on non-2xx /challenge response", async () => {
    globalThis.fetch = vi.fn(
      async () => new Response("", { status: 503, statusText: "Unavailable" }),
    ) as typeof fetch;
    await expect(createChallenge()).rejects.toThrow(/503/);
  });

  it("throws when /challenge response is missing challenge_id or challenge_bytes", async () => {
    globalThis.fetch = vi.fn(
      async () =>
        new Response(
          JSON.stringify({ id: "abc", bytes: "AA", expires_at: "x" }),
          { status: 200, headers: { "Content-Type": "application/json" } },
        ),
    ) as typeof fetch;
    await expect(createChallenge()).rejects.toThrow(/unexpected response shape/);
  });

  it("base64-encodes proofs and POSTs to /link-verify without challenge_id or nullifier", async () => {
    const certProof = new Uint8Array([1, 2, 3, 4]);
    const deviceProof = new Uint8Array([9, 9, 9, 9, 9]);
    const fetchSpy = vi.fn(async (url: RequestInfo | URL, init?: RequestInit) => {
      expect(String(url)).toMatch(/\/link-verify$/);
      expect(init?.method).toBe("POST");
      const body = JSON.parse(String(init?.body));
      expect(body.cert_chain_type).toBe("rs2048");
      // Base64 of [1,2,3,4] = "AQIDBA=="; of [9,9,9,9,9] = "CQkJCQk="
      expect(body.cert_chain_proof).toBe("AQIDBA==");
      expect(body.device_sig_proof).toBe("CQkJCQk=");
      // Server derives both — client must not send them.
      expect(body).not.toHaveProperty("challenge_id");
      expect(body).not.toHaveProperty("nullifier");
      return new Response(
        JSON.stringify({
          verified: true,
          nullifier: "0xabc",
          id_verified: true,
          persisted: true,
        }),
        { status: 200 },
      );
    }) as typeof fetch;
    globalThis.fetch = fetchSpy;

    const res = await submitLinkVerify({
      certChainType: "rs2048",
      certChainProofBytes: certProof,
      deviceSigProofBytes: deviceProof,
    });
    expect(res).toEqual({
      verified: true,
      nullifier: "0xabc",
      id_verified: true,
      persisted: true,
    });
  });

  it("passes public_signals and parsed_inputs through on the response", async () => {
    const fetchSpy = vi.fn(
      async () =>
        new Response(
          JSON.stringify({
            verified: true,
            nullifier: "0xabc",
            id_verified: true,
            persisted: true,
            public_signals: {
              cert_chain: ["0x1", "0x2"],
              device_sig: ["0x2", "0x3"],
            },
            parsed_inputs: {
              challenge: "0xdead",
              pk_commit: "0x2",
              nullifier: "0xabc",
              smt_root: "0xbeef",
              issuer_rsa_modulus: ["0xaaaa", "0xbbbb"],
            },
          }),
          { status: 200 },
        ),
    ) as typeof fetch;
    globalThis.fetch = fetchSpy;

    const res = await submitLinkVerify({
      certChainType: "rs2048",
      certChainProofBytes: new Uint8Array([1]),
      deviceSigProofBytes: new Uint8Array([1]),
    });
    expect(res.public_signals?.cert_chain).toEqual(["0x1", "0x2"]);
    expect(res.parsed_inputs?.nullifier).toBe("0xabc");
    expect(res.parsed_inputs?.issuer_rsa_modulus).toEqual(["0xaaaa", "0xbbbb"]);
  });

  it("tolerates verified=false without a nullifier", async () => {
    globalThis.fetch = vi.fn(
      async () => new Response(JSON.stringify({ verified: false }), { status: 200 }),
    ) as typeof fetch;
    const res = await submitLinkVerify({
      certChainType: "rs2048",
      certChainProofBytes: new Uint8Array([1]),
      deviceSigProofBytes: new Uint8Array([1]),
    });
    expect(res.verified).toBe(false);
  });

  it("rejects verified=true responses missing a nullifier", async () => {
    globalThis.fetch = vi.fn(
      async () => new Response(JSON.stringify({ verified: true }), { status: 200 }),
    ) as typeof fetch;
    await expect(
      submitLinkVerify({
        certChainType: "rs2048",
        certChainProofBytes: new Uint8Array([1]),
        deviceSigProofBytes: new Uint8Array([1]),
      }),
    ).rejects.toThrow(/verified=true response missing string nullifier/);
  });

  it("refuses to submit a proof that exceeds the raw cap", async () => {
    // 701 KB — one byte over the 700 KB cap.
    const huge = new Uint8Array(700 * 1024 + 1);
    const small = new Uint8Array([1]);
    globalThis.fetch = vi.fn(async () => new Response("{}", { status: 200 })) as typeof fetch;
    await expect(
      submitLinkVerify({
        certChainType: "rs2048",
        certChainProofBytes: huge,
        deviceSigProofBytes: small,
      }),
    ).rejects.toThrow(/raw cap/);
  });

  it("surfaces server error body on non-2xx /link-verify", async () => {
    globalThis.fetch = vi.fn(
      async () => new Response("invalid cert_chain_type", { status: 400 }),
    ) as typeof fetch;
    await expect(
      submitLinkVerify({
        certChainType: "rs2048",
        certChainProofBytes: new Uint8Array([1]),
        deviceSigProofBytes: new Uint8Array([1]),
      }),
    ).rejects.toThrow(/invalid cert_chain_type/);
  });
});
