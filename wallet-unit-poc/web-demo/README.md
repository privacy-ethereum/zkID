# zkID Web Demo

Browser demo of the OpenAC ZK proof pipeline. Walks through the full flow —
load a test credential, precompute the Prepare proof, then generate and verify
a Show proof — entirely in-browser using WASM.

## Prerequisites

All of the following must be done before running the demo. Each step is a
one-time setup.

### 1. Compile Circom circuits

```bash
cd ../circom
yarn install
yarn compile:all      # builds jwt_1k, show, and other sizes
```

This produces WASM witness generators in `../circom/build/`.

### 2. Build the WASM prover

```bash
cd ../openac-sdk
npm install
npm run build:all     # TypeScript + Rust→WASM (requires nightly Rust + wasm-pack)
```

See [`openac-sdk/README.md`](../openac-sdk/README.md) for wasm-pack installation
and the nightly toolchain setup.

### 3. Generate proving keys

Keys are large binary files (~270 MB each). Generate them once from
`ecdsa-spartan2/`:

```bash
cd ../ecdsa-spartan2
cargo build --release

# macOS: DYLD_LIBRARY_PATH points to the witnesscalc dylibs built by cargo
LIBDIR=$(ls -d target/release/build/ecdsa-spartan2-*/out/witnesscalc/package/lib | head -1)

DYLD_LIBRARY_PATH=$LIBDIR \
  ./target/release/ecdsa-spartan2 prepare setup --size 1k \
  --input ../circom/inputs/jwt/1k/default.json

DYLD_LIBRARY_PATH=$LIBDIR \
  ./target/release/ecdsa-spartan2 show setup --size 1k
```

Keys land in `ecdsa-spartan2/keys/`. The `public/keys` symlink in this
directory already points there.

### 4. Install dependencies and copy assets

```bash
cd ../web-demo
npm install
npm run setup         # copies WASM files and symlinks keys into public/
```

The `setup` script (`scripts/copy-assets.sh`) does the following:
- Copies `openac_wasm.js` + `openac_wasm_bg.wasm` from `openac-sdk/wasm/pkg/`
- Copies `jwt_1k.wasm` and `show.wasm` from the Circom build
- Copies and patches `witness_calculator.js` (CJS → ESM)
- Creates `public/keys → ../ecdsa-spartan2/keys` symlink

## Running

```bash
npm run dev
```

Open [http://localhost:5173](http://localhost:5173).

The dev server is configured with `Cross-Origin-Opener-Policy: same-origin` and
`Cross-Origin-Embedder-Policy: require-corp` headers, which are required for
`SharedArrayBuffer` (used by the WASM rayon thread pool). These headers are set
in `vite.config.ts`.

## Demo flow

The UI has four steps, each triggered by a button:

| Step | Button | What it does |
|------|--------|-------------|
| 1 | **Load Credential** | Parses the test SD-JWT, decodes disclosures, displays claims |
| 2 | **Precompute** | Loads proving keys (~270 MB), runs JWT witness + Spartan2 Prepare proof (~2–5 s) |
| 3 | **Present** | Signs a verifier nonce, runs Show witness, Spartan2 Show proof, reblind (~1 s) |
| 4 | **Verify** | Verifies both proofs with the verifying keys, displays result |

## Production build

```bash
npm run build         # outputs to dist/
npm run preview       # local preview of the production bundle
```

## Project layout

```
web-demo/
├── src/
│   ├── main.ts                  # UI event handlers and orchestration
│   ├── pipeline.ts              # Core ZK pipeline (init → precompute → present → verify)
│   ├── witness-calc-browser.ts  # Browser wrapper around circom witness_calculator
│   ├── wasm/                    # Copied WASM glue files (openac_wasm.js, ...)
│   └── assets/                  # Copied witness_calculator.js
├── public/
│   ├── openac_wasm_bg.wasm      # Spartan2 prover WASM binary
│   ├── jwt.wasm                 # Circom JWT_1k witness generator
│   ├── show.wasm                # Circom Show witness generator
│   └── keys/                    # Symlink → ecdsa-spartan2/keys/
├── scripts/
│   └── copy-assets.sh           # Asset setup script (run via npm run setup)
└── vite.config.ts               # COOP/COEP headers, fs.allow, @noble alias
```

## Troubleshooting

**Key files return HTML instead of binary**
The `public/keys` symlink is dangling (keys not generated yet). Run Step 3 above.

**`initThreadPool` warning in the console**
The WASM binary in `public/` was built without `--shared-memory`. Rebuild it
with `npm run build:wasm` from `openac-sdk/` (which now passes
`-C link-arg=--shared-memory -C link-arg=--max-memory=2147483648`), then rerun
`npm run setup`. After that, rayon threads will start and the warning disappears.

**`Signal X not found` during witness calculation**
The copied `show.wasm` is older than the current `show.circom`. Re-run `yarn compile:all`
in the circom directory then `npm run setup` to refresh the WASM file.
