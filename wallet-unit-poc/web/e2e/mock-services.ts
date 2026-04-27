// Playwright mocks for external services.
// HiPKI popup calls are injected via `__HIPKI_TEST_HANDLER__` (cannot be
// intercepted by `page.route()`), while verifier HTTP stays on `page.route()`.
// SMT is stubbed via `__SMT_TEST_ENGINE__`/`__SMT_TEST_PROOF__` so tests skip
// real Go WASM bootstrap. Fixtures come from Rust testdata for parity.

import type { Page } from "@playwright/test";
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

// ESM replacement for `__dirname`.
const HERE = dirname(fileURLToPath(import.meta.url));

const TESTDATA = resolve(HERE, "../../ecdsa-spartan2/tests/testdata");
const SIGN_FIXTURE_RAW = readFileSync(
  resolve(TESTDATA, "response_sign_test.json"),
  "utf8",
);

/** Patch Rust fixture gaps needed by the web setup flow (`slotDescription`,
 *  token `serialNumber`, and user-cert `sn`) without mutating shared testdata. */
const PKCS11_FIXTURE = (() => {
  const raw = readFileSync(
    resolve(TESTDATA, "pkcs11info_test.json"),
    "utf8",
  );
  interface Cert {
    label?: string;
    sn?: string;
    [k: string]: unknown;
  }
  interface Token {
    serialNumber?: string;
    certs?: Cert[];
    [k: string]: unknown;
  }
  interface Slot {
    slotDescription?: string;
    token?: Token;
    [k: string]: unknown;
  }
  const parsed = JSON.parse(raw) as { slots?: Slot[] };
  parsed.slots?.forEach((slot, i) => {
    if (!slot.slotDescription) slot.slotDescription = `Mock Reader ${i}`;
    if (slot.token && !slot.token.serialNumber) {
      slot.token.serialNumber = `MOCKSN${String(i).padStart(6, "0")}`;
    }
    slot.token?.certs?.forEach((cert) => {
      if (cert.label !== "CA Cert" && !cert.sn) {
        cert.sn = "0xDEADBEEF";
      }
    });
  });
  return JSON.stringify(parsed);
})();

export interface InstallMockOptions {
  /** Set to a non-2xx status to simulate verifier downtime. */
  linkVerifyStatus?: number;
  /** Override the response body the verifier returns. */
  linkVerifyBody?: unknown;
  /** Force `signTbs` to fail with a non-zero ret_code (wrong PIN). */
  signRejectsPin?: boolean;
  /** Replace the fake SMT proof payload (hex fields, same shape as smt.wasm). */
  smtBody?: {
    root: string;
    entry: string[];
    matchingEntry?: string[];
    siblings: string[];
  };
}

export async function installMockServices(
  page: Page,
  opts: InstallMockOptions = {},
): Promise<void> {
  await installHipkiPopupHandler(page, {
    pkcs11Fixture: PKCS11_FIXTURE,
    signFixture: SIGN_FIXTURE_RAW,
    signRejectsPin: opts.signRejectsPin ?? false,
  });

  await installSmtTestEngine(page, {
    smtBody: opts.smtBody ?? {
      root: "2a",
      entry: ["270f"],
      matchingEntry: ["7", "b"],
      siblings: ["64"],
    },
  });

  // Verifier -----------------------------------------------------------
  await page.route("**/challenge", async (route, req) => {
    if (req.method() !== "POST") return route.fallback();
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({
        challenge_id: "e2e-challenge-0001",
        challenge_bytes: "deadbeef",
        expires_at: new Date(Date.now() + 10 * 60_000).toISOString(),
      }),
    });
  });

  await page.route("**/link-verify", async (route, req) => {
    if (req.method() !== "POST") return route.fallback();
    if (opts.linkVerifyStatus && opts.linkVerifyStatus >= 400) {
      await route.fulfill({
        status: opts.linkVerifyStatus,
        contentType: "text/plain",
        body: "verifier down",
      });
      return;
    }
    const body = req.postDataJSON();
    const shapeOk =
      typeof body?.cert_chain_proof === "string" &&
      typeof body?.device_sig_proof === "string" &&
      body.cert_chain_proof.length > 0 &&
      body.device_sig_proof.length > 0 &&
      ["rs2048", "rs4096"].includes(body?.cert_chain_type) &&
      // Server derives these fields; client must not send them.
      !("challenge_id" in (body ?? {})) &&
      !("nullifier" in (body ?? {}));
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify(
        opts.linkVerifyBody ??
          (shapeOk
            ? {
                verified: true,
                nullifier: "0xmocksubjectdnhash",
                id_verified: true,
                persisted: true,
                public_signals: {
                  cert_chain: ["0xmocksubjectdnhash", "0xmockpkcommit"],
                  device_sig: ["0xmockpkcommit", "0xmockpackedtbs"],
                },
                parsed_inputs: {
                  challenge: "0xdeadbeef",
                  pk_commit: "0xmockpkcommit",
                  nullifier: "0xmocksubjectdnhash",
                  smt_root: "0xmocksmtroot",
                  serial_number: "0xdeadbeef",
                  issuer_rsa_modulus: ["0xaaaa", "0xbbbb"],
                },
              }
            : { verified: false }),
      ),
    });
  });

  // Fail any legacy SMT network path so regressions are loud.
  await page.route("**/smt-snapshot/**", async (route) => {
    await route.fulfill({
      status: 410,
      contentType: "text/plain",
      body: "snapshot download should be stubbed by __SMT_TEST_ENGINE__ in e2e",
    });
  });
  await page.route("**/proof/**", async (route) => {
    await route.fulfill({
      status: 410,
      contentType: "text/plain",
      body: "remote SMT proof endpoint is gone — browser uses __SMT_TEST_ENGINE__",
    });
  });
}

interface SmtEngineOpts {
  smtBody: {
    root: string;
    entry: string[];
    matchingEntry?: string[];
    siblings: string[];
  };
}

/** Seed `__SMT_TEST_PROOF__` so SMT client paths return fixture data directly. */
async function installSmtTestEngine(
  page: Page,
  opts: SmtEngineOpts,
): Promise<void> {
  await page.addInitScript((injected) => {
    const body = injected.smtBody;
    interface ProofGlobal {
      __SMT_TEST_PROOF__?: {
        root: string;
        entry: string[];
        matchingEntry?: string[];
        siblings: string[];
      };
    }
    (globalThis as ProofGlobal).__SMT_TEST_PROOF__ = body;
  }, opts);
}

interface PopupHandlerOpts {
  pkcs11Fixture: string;
  signFixture: string;
  signRejectsPin: boolean;
}

/** Install popup handler before app boot; keep closure payload JSON-safe. */
async function installHipkiPopupHandler(
  page: Page,
  opts: PopupHandlerOpts,
): Promise<void> {
  await page.addInitScript((injected) => {
    const { pkcs11Fixture, signFixture, signRejectsPin } = injected;
    interface HandlerGlobal {
      __HIPKI_TEST_HANDLER__?: (
        payload: Record<string, unknown>,
      ) => Promise<string>;
    }
    const g = globalThis as HandlerGlobal;
    g.__HIPKI_TEST_HANDLER__ = async (payload) => {
      const func = payload.func;
      if (func === "CheckEnvir" || func === "GetUserCert") {
        return pkcs11Fixture;
      }
      if (func === "MakeSignature") {
        if (signRejectsPin) {
          const fixture = JSON.parse(signFixture) as Record<string, unknown>;
          return JSON.stringify({
            ...fixture,
            ret_code: 1,
            last_error: 0x6982,
          });
        }
        return signFixture;
      }
      throw new Error(`mock popup handler: unknown func ${String(func)}`);
    };
  }, opts);
}
