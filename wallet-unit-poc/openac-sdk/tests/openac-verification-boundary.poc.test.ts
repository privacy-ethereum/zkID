import { describe, it, expect, beforeAll } from "vitest";
import { existsSync, readFileSync } from "fs";
import { readFile } from "fs/promises";
import { join, dirname } from "path";
import { fileURLToPath } from "url";
import { OpenAC } from "../src/index.js";
import { generateDummyCredential } from "../src/testing/index.js";
import type { KeySet, VerifyingKeys } from "../src/types.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const ASSETS_DIR = join(__dirname, "..", "assets");
const KEYS_DIR = join(__dirname, "..", "..", "ecdsa-spartan2", "keys");
const WASM_PKG_DIR = join(__dirname, "..", "wasm", "pkg");

const REQUIRED_LOCAL_ARTIFACTS = [
  join(KEYS_DIR, "1k_prepare_proving.key"),
  join(KEYS_DIR, "1k_prepare_verifying.key"),
  join(KEYS_DIR, "1k_show_proving.key"),
  join(KEYS_DIR, "1k_show_verifying.key"),
  join(WASM_PKG_DIR, "openac_wasm.js"),
  join(WASM_PKG_DIR, "openac_wasm_bg.wasm"),
];

function requireLocalArtifacts() {
  const missing = REQUIRED_LOCAL_ARTIFACTS.filter((path) => !existsSync(path));
  if (missing.length > 0) {
    throw new Error(
      "Missing generated 1k Spartan/WASM artifacts. Generate them with the " +
        "setup commands in the paired openac-findings verification-boundary " +
        `report before running this PoC:\n${missing.join("\n")}`,
    );
  }
}

async function loadWasmModule() {
  const mod = await import(
    /* webpackIgnore: true */ join(WASM_PKG_DIR, "openac_wasm.js")
  );
  const bin = await readFile(join(WASM_PKG_DIR, "openac_wasm_bg.wasm"));
  mod.initSync({ module: bin });
  return mod;
}

function loadLocalKeySet(): KeySet {
  const prepareProvingKey = new Uint8Array(
    readFileSync(join(KEYS_DIR, "1k_prepare_proving.key")),
  );
  const prepareVerifyingKey = new Uint8Array(
    readFileSync(join(KEYS_DIR, "1k_prepare_verifying.key")),
  );
  const showProvingKey = new Uint8Array(
    readFileSync(join(KEYS_DIR, "1k_show_proving.key")),
  );
  const showVerifyingKey = new Uint8Array(
    readFileSync(join(KEYS_DIR, "1k_show_verifying.key")),
  );
  return {
    prepareProvingKey,
    prepareVerifyingKey,
    showProvingKey,
    showVerifyingKey,
    verifyingKeys(): VerifyingKeys {
      return { prepareVerifyingKey, showVerifyingKey };
    },
    serialize() {
      return {
        prepareProvingKey,
        prepareVerifyingKey,
        showProvingKey,
        showVerifyingKey,
      };
    },
  };
}

describe("OpenAC verification boundary PoC", () => {
  let openac: OpenAC;
  let keys: KeySet;

  beforeAll(async () => {
    requireLocalArtifacts();
    const wasmModule = await loadWasmModule();
    openac = await OpenAC.init({ assetsDir: ASSETS_DIR, wasmModule });
    keys = loadLocalKeySet();
  });

  it("rejects mixing Prepare proof A with Show proof B through spoofed external instances", async () => {
    const credA = generateDummyCredential({
      size: "1k",
      claims: [
        { key: "roc_birthday", value: "0900101" },
        { key: "roc_max", value: "0950101" },
      ],
    });
    const credB = generateDummyCredential({
      size: "1k",
      claims: [
        { key: "roc_birthday", value: "0800101" },
        { key: "roc_max", value: "0990101" },
      ],
    });
    const predicate = {
      claim: "roc_birthday",
      op: "<=" as const,
      compareTo: { claim: "roc_max" },
    };

    const preA = await openac.precompute({
      jwt: credA.jwt,
      disclosures: credA.disclosures,
      issuerPublicKey: credA.issuerPublicKey,
      keys,
      predicates: predicate,
    });
    const proofA = await openac.present({
      precomputed: preA,
      verifierNonce: "linkage-A",
      devicePrivateKey: credA.devicePrivateKeyHex,
      keys,
      predicates: predicate,
    });
    const preB = await openac.precompute({
      jwt: credB.jwt,
      disclosures: credB.disclosures,
      issuerPublicKey: credB.issuerPublicKey,
      keys,
      predicates: predicate,
    });
    const proofB = await openac.present({
      precomputed: preB,
      verifierNonce: "linkage-B",
      devicePrivateKey: credB.devicePrivateKeyHex,
      keys,
      predicates: predicate,
    });

    const honestA = await openac.verify(proofA, keys.verifyingKeys());
    const honestB = await openac.verify(proofB, keys.verifyingKeys());
    expect(honestA.valid).toBe(true);
    expect(honestB.valid).toBe(true);

    const mismatchedRealInstances = await openac.verifyComponents(
      proofA.prepareProof,
      proofB.showProof,
      keys.verifyingKeys(),
      proofA.prepareInstance,
      proofB.showInstance,
    );
    expect(mismatchedRealInstances.valid).toBe(false);

    const spoofed = await openac.verifyComponents(
      proofA.prepareProof,
      proofB.showProof,
      keys.verifyingKeys(),
      proofA.prepareInstance,
      proofA.showInstance,
    );

    // Prepare A and Show B are not linked, even if the caller supplies A's
    // external show instance to satisfy the wrapper's comm_W_shared comparison.
    // Current vulnerable code accepts if proof verification is not bound to
    // the externally compared instance.
    expect(spoofed.valid).toBe(false);
  }, 900_000);
});
