# openac-sdk

ZK proof SDK for SD-JWT credentials. Prove predicates (`age >= 18`, `balance <= credit_limit`, etc.) without revealing claim values. Built on Spartan2 + Hyrax over secp256r1.

## Install

```bash
npm install openac-sdk
```

Node 18+. Browser usage requires preloading WASM and passing `wasmModule` to `OpenAC.init`.

## Quickstart

```typescript
import { OpenAC } from "openac-sdk";

const openac = await OpenAC.init();
const keys = await openac.loadKeysFromUrl("1k");

const predicate = {
  claim: "roc_birthday",
  op: "<=" as const,
  value: new Date("2008-01-01"),
};

// Precompute once per credential. Pass the predicate so format inference works.
const precomputed = await openac.precompute({
  jwt: sdJwtToken,
  disclosures: ["WyJzYWx0...", "..."],
  issuerPublicKey: { kty: "EC", crv: "P-256", x: "...", y: "..." },
  keys,
  predicates: predicate,
});

// Present per verifier session.
const proof = await openac.present({
  precomputed,
  verifierNonce: "challenge-123",
  devicePrivateKey: "0xabcdef...",
  keys,
  predicates: predicate,
});

const result = await openac.verify(proof, keys.verifyingKeys());
console.log(result.valid, result.expressionResult);
```

## Predicates

```typescript
// Literal comparison
{ claim: "age", op: ">=", value: 18 }

// Date (auto-encoded to ROC date format)
{ claim: "roc_birthday", op: "<=", value: new Date("2008-01-01") }

// Claim-to-claim
{ claim: "balance", op: "<=", compareTo: { claim: "credit_limit" } }

// Nested boolean composition
{
  all: [
    { claim: "age", op: ">=", value: 18 },
    {
      any: [
        { claim: "kyc_tier", op: "==", value: 2 },
        { claim: "kyc_tier", op: "==", value: 3 },
      ],
    },
  ],
}
```

**Operators**: `"<="`, `">="`, `"=="`
**Value types**: `bigint`, `number`, `Date`, `string`
**Combinators**: `all`, `any`, `not` (nest arbitrarily)
**Format**: inferred from value type (`Date` becomes date, numeric becomes uint, string becomes string). Override with `format: "date" | "uint" | "string"` on any predicate.

## Verifier

A verifier only needs the two verifying keys, not the proving keys.

```typescript
import { OpenAC } from "openac-sdk";

const openac = await OpenAC.init();

const result = await openac.verify(proof, {
  prepareVerifyingKey, // Uint8Array
  showVerifyingKey,    // Uint8Array
});
// result.valid            both proofs verified and shared commitment matches
// result.expressionResult  boolean output of the predicate expression
// result.deviceKey         always null; binding flows through comm_W_shared
```

The verifier check includes byte-equality of `comm_W_shared` between the Prepare and Show instances before either SNARK is verified. This is the load-bearing security check that ties the two proofs to the same underlying credential.

## Configuration

```typescript
const openac = await OpenAC.init({
  keysBaseUrl: "https://my-cdn.example/keys", // override the default R2 endpoint
  assetsDir: "./assets",                       // override circuit-WASM asset path
  wasmModule: preloadedWasm,                   // browser: pre-init WASM and pass it
});
```

## Testing helpers

```typescript
import { generateDummyCredential } from "openac-sdk/testing";

const cred = generateDummyCredential({
  size: "1k",
  claims: [
    { key: "roc_birthday", value: "0900101" },
    { key: "roc_max", value: "0950101" },
  ],
});
// cred.jwt, cred.disclosures, cred.issuerPublicKey, cred.devicePrivateKeyHex
```

Deterministic keys; JWT is sized to fit the chosen circuit slot.

## API

| Method | Returns |
|---|---|
| `OpenAC.init(config?)` | `Promise<OpenAC>` |
| `openac.loadKeysFromUrl(size, url?)` | `Promise<KeySet>` |
| `openac.loadKeys(serialized)` | `Promise<KeySet>` |
| `openac.precompute(req)` | `Promise<PrecomputedCredential>` |
| `openac.present(req)` | `Promise<PresentationProof>` |
| `openac.verify(proof, vks)` | `Promise<VerificationResult>` |
| `openac.verifyProof(serialized, vks)` | `Promise<VerificationResult>` |

`size` is `"1k" | "2k" | "4k" | "8k"`. `precompute` auto-picks the smallest size that fits the JWT.

## Build

### Prerequisites

- Node.js >= 18
- Rust nightly with `rust-src` component (for WASM builds)
- [`wasm-pack`](https://rustwasm.github.io/wasm-pack/installer/) (for WASM builds)
- Compiled Circom circuits (see `../circom/`)

### TypeScript library only

```bash
npm install
npm run build:all   # WASM (needs Rust + wasm-pack) + TypeScript
npm test
```

## Dependencies

`@noble/curves` and `@noble/hashes`. The SDK loads circuit assets and the WASM module from disk via Node's `fs`/`path`/`url` builtins, so Node 18+ is required for the default initialization path.

## License

MIT
