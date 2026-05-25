# openac-sdk

ZK proof SDK for SD-JWT credentials. Prove predicates (age >= 18, etc.) without revealing claim values.

Built on [zkID](https://github.com/privacy-scaling-explorations/zkID) (Spartan2 + Hyrax over secp256r1).

## Two-Circuit Protocol

1. **Prepare** — Verify JWT signature (ES256), extract device key, normalize claims
2. **Show** — Prove device key ownership, evaluate predicates over claims

Both proofs share a blinded witness commitment (`comm_W_shared`).

## Install

```bash
npm install openac-sdk
```

## Usage

### Prover: Precompute + Present

```typescript
import { OpenAC, PredicateOp } from "openac-sdk";

const openac = await OpenAC.init({ assetsDir: "./assets" });
const keys = await openac.loadKeysFromUrl("https://cdn.example/keys", "1k");

// Precompute (once per credential, ~2s)
const precomputed = await openac.precompute({
  jwt: sdJwtToken,
  disclosures: ["WyJzYWx0...", "..."],
  issuerPublicKey: { kty: "EC", crv: "P-256", x: "...", y: "..." },
  keys,
});

// Present (per verification, ~100ms)
const proof = await openac.present({
  precomputed,
  verifierNonce: "challenge-123",
  devicePrivateKey: "0xabcdef...",
  keys,
  showInputOptions: {
    normalizedClaimValues: [890615n],
    predicates: [{ claimRef: 0, op: PredicateOp.GE, compareValue: 18n }],
  },
});
```

### Verifier

```typescript
const openac = await OpenAC.init();

const result = await openac.verify(proof, {
  prepareVerifyingKey: /* Uint8Array */,
  showVerifyingKey: /* Uint8Array */,
});

result.valid;            // true
result.expressionResult; // true (predicate passed)
result.deviceKey;        // { x: '0x...', y: '0x...' }
```

### One-Shot (no precompute/present split)

```typescript
const proof = await openac.createProof({
  jwt: sdJwtToken,
  disclosures,
  issuerPublicKey,
  devicePrivateKey: "0xabcdef...",
  verifierNonce: "challenge-123",
  keys,
});

const result = await openac.verifyProof(proof.serialize(), verifyingKeys);
```

## Predicates

```typescript
import { PredicateOp, LogicToken, buildShowCircuitInputs, DEFAULT_SHOW_PARAMS } from "openac-sdk";

// claim[0] >= 18 AND claim[1] == 1
const showInputs = buildShowCircuitInputs(DEFAULT_SHOW_PARAMS, nonce, sig, deviceKey, {
  normalizedClaimValues: [25n, 1n],
  predicates: [
    { claimRef: 0, op: PredicateOp.GE, compareValue: 18n },
    { claimRef: 1, op: PredicateOp.EQ, compareValue: 1n },
  ],
  logicExpression: [
    { type: LogicToken.REF, value: 0 },
    { type: LogicToken.REF, value: 1 },
    { type: LogicToken.AND, value: 0 },
  ],
});
```

Operators: `LE` (<=), `GE` (>=), `EQ` (==). Logic: `REF`, `AND`, `OR`, `NOT`. Evaluated as postfix RPN.

## API

| Method | Description |
|--------|-------------|
| `OpenAC.init(config?)` | Load WASM prover |
| `openac.loadKeysFromUrl(url, size)` | Fetch keys (`'1k'`/`'2k'`/`'4k'`/`'8k'`) |
| `openac.loadKeys(data)` | Load keys from bytes |
| `openac.precompute(req)` | Prove JWT validity (cache this) |
| `openac.present(req)` | Prove predicates + device key |
| `openac.verify(proof, keys)` | Verify proof |
| `openac.createProof(req)` | One-shot prove |
| `openac.verifyProof(bytes, keys)` | Verify serialized proof |

| Utility | |
|---------|---|
| `Credential.parse(jwt, disclosures)` | Parse SD-JWT |
| `buildJwtCircuitInputs(...)` | Build Prepare circuit inputs |
| `buildShowCircuitInputs(...)` | Build Show circuit inputs |
| `signDeviceNonce(nonce, key)` | Sign verifier challenge |
| `WitnessCalculator` | Generate circom witnesses |
| `NativeBackend` | Wrap Rust CLI for server-side proving |

## Build

### Prerequisites

- Node.js >= 18
- Rust nightly with `rust-src` component (for WASM builds)
- [`wasm-pack`](https://rustwasm.github.io/wasm-pack/installer/) (for WASM builds)
- Compiled Circom circuits (see `../circom/`)

### TypeScript library only

```bash
npm install
npm run build        # outputs to dist/
```

### WASM prover (Rust → WebAssembly)

The WASM build requires the nightly toolchain and three sets of flags to enable
rayon thread pools in the browser:

| Flag | Purpose |
|------|---------|
| `-C target-feature=+atomics,+bulk-memory,+mutable-globals` | CPU-level atomics so rayon can use `Atomics.wait` |
| `-C link-arg=--shared-memory` | Marks the `WebAssembly.Memory` segment as shared — **required** so the memory can be sent via `postMessage` to workers without a `DataCloneError` |
| `-C link-arg=--max-memory=2147483648` | Required whenever `--shared-memory` is set; 2 GB covers the Spartan2 1k peak |
| `-C link-arg=--import-memory` | Makes the WASM module import its memory from the JS host instead of defining it inline. `wasm-bindgen`'s threading transform asserts `mem.import.is_some()`; without this flag the build panics with *"assertion failed: mem.import.is_some()"* |
| `-C link-arg=--export=__heap_base` | Forces `wasm-ld` to export the `__heap_base` global (an `i32` marking where the heap starts). `wasm-bindgen`'s `allocate_static_data()` scans the module's export table for this symbol to place its thread-ID counter; without it the build fails with *"failed to find `__heap_base` for injecting thread id"* |

The build script (`scripts/build-wasm.sh`) sets all three. Just run:

```bash
# Install the nightly toolchain declared in wasm/rust-toolchain.toml
rustup toolchain install nightly
rustup component add rust-src --toolchain nightly

# Build WASM module (outputs to wasm/pkg/)
npm run build:wasm
```

After rebuilding, copy the new binary to the web-demo with `npm run setup` in
`web-demo/`. The `initThreadPool` call will succeed and rayon will spawn one
worker per logical CPU core.

### Build everything

```bash
npm run build:all    # WASM then TypeScript
```

### Generate proving/verifying keys

Keys are large binary files (~270 MB each for 1k). Generate them once with the
`ecdsa-spartan2` CLI, which reads the compiled Circom R1CS files:

```bash
cd ../ecdsa-spartan2

# The binary must be run from the ecdsa-spartan2/ directory so keys land in ./keys/
DYLD_LIBRARY_PATH=target/release/build/$(ls target/release/build | grep ecdsa-spartan2 | head -1)/out/witnesscalc/package/lib \
  cargo run --release -- prepare setup --size 1k --input ../circom/inputs/jwt/1k/default.json

DYLD_LIBRARY_PATH=target/release/build/$(ls target/release/build | grep ecdsa-spartan2 | head -1)/out/witnesscalc/package/lib \
  cargo run --release -- show setup --size 1k
```

This writes four files to `ecdsa-spartan2/keys/`:
`1k_prepare_proving.key`, `1k_prepare_verifying.key`,
`1k_show_proving.key`, `1k_show_verifying.key`.

Repeat with `--size 2k / 4k / 8k` for larger JWT payloads.

### Key sizes

| Size | Max JWT payload | Prepare PK/VK | Show PK/VK |
|------|----------------|---------------|------------|
| 1k | 1 280 B | ~270 MB each | ~3 MB each |
| 2k | 2 048 B | ~430 MB each | ~3 MB each |
| 4k | 4 096 B | ~810 MB each | ~3 MB each |
| 8k | 8 192 B | ~1.6 GB each | ~3 MB each |

## Tests

```bash
npm test             # runs all tests with vitest
npm run test:watch   # watch mode
```

Tests expect the TypeScript `dist/` to be present (auto-built on first run) and
keys in `../ecdsa-spartan2/keys/` for the full pipeline test
(`wasm-1k-pipeline.test.ts`).

## Dependencies

`@noble/curves` (P-256 ECDSA), `@noble/hashes` (SHA-256). No Node.js-specific runtime deps.

## License

MIT
