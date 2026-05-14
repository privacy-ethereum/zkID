# web — zkID in-browser prover

Vite + TypeScript app that runs cert-chain + user-sig Spartan2 proving fully
in the browser using [`../spartan2-wasm`](../spartan2-wasm). Verification is
**server-side** via [`go-zkid-verifier`](https://github.com/zkmopro/go-zkid-verifier)
(`POST /link-verify`). A dedicated Web Worker handles heavy wasm work; the main
thread orchestrates user-gated checkpoints.

## Flow

Six screens, each gated by an explicit user action:

```
landing → setup → ready → proving → review → submitting → result
  │        │       │        │         │         │           │
Start    Continue  Start    (auto)    Send     (auto)      Prove again
         to prov  proving           proof                  / Home
```

- **Setup** has four panels (proving runtime download + wasm/thread-pool
  warmup, HiPKI card detect + read, per-issuer revocation-tree snapshot
  download + local rebuild, PIN verify with 3-attempt lockout). The
  **Continue to proving** button is disabled until all four are green.
- **Ready** is a confirmation gate before proving starts (and before opening
  the HiPKI signing popup).
- **Proving** runs 6 steps: fetch challenge → sign with card → check
  revocation locally → build inputs → prove cert-chain → prove user-sig.
  Per-step durations appear as each step completes. Cancel returns the
  user to setup. The revocation step queries an SMT that was rebuilt
  in-browser during setup, so the card's serial never leaves the device.
- **Review** shows proof sizes + proving time. Proofs are still local only.
  The nullifier appears only after `/link-verify` returns.
  **Send proof to verifier** submits; **Retry proving** discards and routes
  back through setup for PIN re-verify (single-use PIN policy).
- **Submitting** is a single-spinner screen for the `/link-verify` POST.
- **Result** shows verified/not-verified with both timings, the
  server-derived nullifier, and an expandable debug block with the
  parsed public inputs (`nullifier`, `pkCommit`, `smt_root`,
  `serial_number`, `challenge`, `issuerRsaModulus`). **Prove again**
  routes back to setup for PIN re-verify; card + warm runtime stay green
  so only the PIN panel needs a fresh entry.

## Quickstart

```sh
cd wallet-unit-poc/web
pnpm install

# Build the WASM crate and copy its output into src/wasm/ + public/assets/.
pnpm build:wasm
pnpm copy:assets

# Copy .env.example → .env.local and point the four VITE_* URLs at your
# local services (verifier, HiPKI, SMT). See .env.example for details.
cp .env.example .env.local
pnpm dev
```

Open `http://localhost:5173` and click **Start**. On first setup entry, the
Worker downloads proving keys + witness WASMs (via dev proxy) and caches them;
later runs reuse the cache.

## Architecture

| Module                   | Responsibility                                                                 |
| ------------------------ | ------------------------------------------------------------------------------ |
| `src/manifest.ts`        | `CircuitKind` union + per-circuit URLs + SHA-256 digests fetched from the GitHub Release API |
| `src/asset-store.ts`     | Storage abstraction: OPFS primary, IndexedDB fallback                          |
| `src/asset-download.ts`  | Streaming fetch → `DecompressionStream('gzip')` → `SubtleCrypto.digest` verify |
| `src/witness.ts`         | CJS→ESM shim for circom's `witness_calculator.js` (with strict-mode patch)     |
| `src/verifier-client.ts` | `POST /challenge` + `POST /link-verify` against `go-zkid-verifier`             |
| `src/hipki-client.ts`    | `GET /pkcs11info` + `POST /sign` against the user's HiPKI LocalSignServer      |
| `src/smt-client.ts`      | Worker-backed SMT proof query → `SmtCircuitInputs` (no network)               |
| `src/smt-local.ts`       | Worker-side SMT engine: loads Go `smt.wasm`, streams snapshot, serves proofs  |
| `src/smt-snapshot.ts`    | Binary snapshot parser (header + node chunking); engine-agnostic              |
| `src/inputs.ts`          | Wraps wasm `build_split_inputs` → `{ certJson, userSigJson }`                  |
| `src/pipeline.ts`        | Main-thread sign-phase pipeline on /: challenge → sign → SMT → build → `ProveInput` |
| `src/pin.ts`             | Single-use PIN wrapper; redacts on every observable surface                    |
| `src/worker.ts`          | Two Worker modes: `warmup` (download + load PKs) and `prove` (witness + prove) |
| `src/store.ts`           | Discriminated-union `AppState` + `transition` reducer + `ProvingRun` type      |
| `src/router.ts`          | Subscribes to `$state.phase` and swaps the mounted screen                      |
| `src/screens/*.ts`       | Landing / setup / ready / proving / review / submitting / result mounts        |
| `src/setup-state.ts`     | `$hipki`, `$pin`, `$warmup` atoms + derived `$setupReady`                      |
| `src/ui.ts`              | 6-step atoms + DOM paint for the proving screen with per-step durations        |
| `src/storage-handoff.ts` | sessionStorage channel that carries `ProveInput` from `/` to `/prove`          |
| `src/sign-main.ts`       | `/` entry point: sign route (landing/setup/ready + sign-phase pipeline)        |
| `src/prove-main.ts`      | `/prove` entry point: cross-origin-isolated proving route (warmup + prove)     |

Pipeline (mirrors `src/ui.ts::Step`):

```
challenge → sign → smt → build → prove_cert → prove_user_sig → proving_complete
                                                                │
                                                                ▼
                                                    review → send → submitting → result
                                                             │
                                                     error (at whichever step failed)
```

Main thread owns the network + HiPKI + input-build steps; the Worker owns
the CPU/wasm-bound ones. The Worker has **two modes**:

- **`warmup`** runs once during setup (kicked by `main.ts` on entry to the
  setup phase). It initializes the wasm module, starts the rayon thread
  pool, hydrates per-asset SHA-256 digests from the GitHub Release API,
  downloads every proving key +
  witness wasm, and calls `load_pk` to park each PK in the per-kind static
  Mutex slot. Witness-wasm bytes are cached on the Worker so the prove
  mode can skip another OPFS round-trip.
- **`prove`** runs on `start_proving`, takes the pre-built JSON inputs plus
  the cert-chain kind, and runs witness+prove for each circuit. The
  terminal event `proving_complete` carries the two proof byte-blobs back
  to the main thread; `main.ts` parks them in the `review` phase's
  `ProvingRun` payload until the user clicks Send.

Submission (`POST /link-verify`) runs on the main thread so the user can
explicitly gate it from the Review screen. Verification itself is
server-side — the wasm crate's `verify` / `link_verify` are drift-test
only and never called here.

## Asset sources

On click, the Worker resolves these URLs (all gzipped on the server):

- `/keys/certChainRS2048_proving.key.gz` (or rs4096 if the cert input is 4096)
- `/keys/userSigRS2048_proving.key.gz`
- `/keys/certChainRS2048.wasm.gz` (circom witness-gen)
- `/keys/userSigRS2048.wasm.gz`

SHA-256 digests for the above are read from the GitHub Release API
(`https://api.github.com/repos/zkmopro/zkID/releases/tags/latest`) and verified
against the **gzipped** bytes during streaming download.

Revocation-tree assets (downloaded after the user reads their card, because the
per-issuer snapshot is only known at that point):

- `/smt-snapshot/smt.wasm` (Go SMT engine, ~3.5 MB, raw)
- `/smt-snapshot/wasm_exec.js` (Go's JS shim, ~17 KB, raw)
- `/smt-snapshot/g2-tree-snapshot.bin.gz` (~73 MB gzipped; only fetched when
  the card was issued by MOICA-G2)
- `/smt-snapshot/g3-tree-snapshot.bin.gz` (~21 MB gzipped; MOICA-G3 only)

SMT-side digests come from
`https://api.github.com/repos/moven0831/moica-revocation-smt/releases/tags/snapshot-latest`.

In dev, `/keys/*` is proxied to `https://github.com/zkmopro/zkID/releases/download/latest/<asset>`
and `/smt-snapshot/*` is proxied to
`https://github.com/moven0831/moica-revocation-smt/releases/download/snapshot-latest/<asset>`
via `vite.config.ts`. In prod, configure your host to serve those two paths
same-origin (either via a reverse proxy, or by caching the release assets on a
CORS-enabled origin you control). Pointing either env var directly at a bare
`github.com` release URL is **not supported** — the app never relies on GitHub
Release CORS behaviour; the two paths share a single failure mode.

Verifying keys are **not** downloaded to the browser — verification runs on the
Go server and it has its own copy.

## External services

Two services the browser talks to at runtime, plus one asset source. Each is
configurable via a `VITE_*` env var (see `.env.example`):

| Service / source          | Env var                            | Default                          | Purpose                                            |
| ------------------------- | ---------------------------------- | -------------------------------- | -------------------------------------------------- |
| `go-zkid-verifier`        | `VITE_VERIFIER_BASE_URL`           | `http://localhost:8080`          | Challenge + `link-verify`                          |
| HiPKI LocalSignServer     | `VITE_HIPKI_BASE_URL`              | `http://localhost:61161`         | `pkcs11info` + `sign` via popupForm postMessage    |
| `moica-revocation-smt`    | (dev proxy)                        | `/smt-snapshot` → GH release     | Binary SMT snapshot + `smt.wasm` (read-only asset) |

The 31-byte `app_id` and per-session `challenge` are returned by `POST /challenge` —
no client-side env var. To change `app_id`, set `APP_ID` on the verifier.

The revocation-tree path replaces the previous `moica-revocation-smt` REST
server (`/proof/{issuer}/{serial}`), which leaked user serials per request.
The app now downloads snapshots once, rebuilds the tree in-browser via
`smt.wasm`, and queries locally.

Per-request timeouts are configurable via `VITE_VERIFIER_TIMEOUT_MS`
(default 60000).

### HiPKI CORS + mixed-content (why we use the popup bridge)

HiPKI's LocalSignServer does **not** send `Access-Control-Allow-Origin`
headers. A direct `fetch("http://localhost:61161/pkcs11info")` from the
browser will return 200 *and* be blocked — the browser delivers an opaque
"net::ERR_FAILED 200 (OK)" error to JS and never lets the app see the body.

The app sidesteps this with HiPKI's official `popupForm` postMessage
bridge: each HiPKI operation opens a small popup at
`http://localhost:61161/popupForm` and exchanges JSON over
`window.postMessage`. Because the popup is same-origin with
LocalSignServer, its own XHRs are unblocked. The app serves `/` with
popup-compatible COOP and `/prove` with cross-origin isolation; when
`crossOriginIsolated === false`, proving falls back to single-threaded mode.

Revocation-tree assets ride `/smt-snapshot/*` (same shape as `/keys/*`) —
configure the prod host to reverse-proxy that path to the
`moica-revocation-smt` release, or set `VITE_SMT_SNAPSHOT_BASE_URL` to an
absolute URL on a CORS-enabled origin you control.

## Production deployment

Production needs three things the dev proxy provides for free:

1. **Cross-origin isolation headers** (`Cross-Origin-Opener-Policy:
   same-origin` + `Cross-Origin-Embedder-Policy: require-corp`) for
   SharedArrayBuffer / multi-threaded proving.
2. **A reverse proxy from `/hipki/*` to the user's `localhost:61161`** so
   browser fetches are same-origin and bypass HiPKI's missing CORS headers.
3. **A reverse proxy from `/smt-snapshot/*`** to
   `https://github.com/moven0831/moica-revocation-smt/releases/download/snapshot-latest/`
   (or set `VITE_SMT_SNAPSHOT_BASE_URL` to an absolute URL on a CORS-enabled
   host). GitHub Release CORS behaviour is not a contract the app relies on.

A standard CDN (GitHub Pages, plain Netlify) can do (1) but not (2) — the
HiPKI server runs on the **user's** machine, not the CDN's. Two patterns
that work:

- **Hosted app + user-side mini-proxy.** Ship a small native helper
  (Caddy / nginx / a tiny Go binary) alongside the HiPKI installer that
  exposes `/hipki/*` on the same origin as the deployed app. The helper
  proxies into `localhost:61161` and adds the COOP/COEP headers.
- **Local-first app.** Ship the static bundle as part of the same
  installer that bundles HiPKI. The user runs everything on their own
  machine (`http://localhost:<port>`), and a tiny local server provides
  both the static files and the `/hipki/*` reverse proxy.

A pure cloud-hosted "visit from any browser" deployment is **not viable**
without one of these helpers, because browsers cannot reach a user's local
HiPKI server from a remote origin.

## Browser requirements — two-route COOP

The app is served as **two same-origin documents** with different
`Cross-Origin-Opener-Policy` headers so the HiPKI popup and the rayon
thread pool can both work:

| Route    | COOP                         | `crossOriginIsolated` | Runs                                              |
| -------- | ---------------------------- | --------------------- | ------------------------------------------------- |
| `/`      | `same-origin-allow-popups`   | `false`               | Landing, setup, ready, HiPKI sign, SMT, build     |
| `/prove` | `same-origin`                | `true`                | Worker warmup + witness + prove (rayon threads)   |

When the user clicks **Start proving** on `/`, the sign-phase pipeline runs
(challenge → sign → SMT → build) and hands off `ProveInput` via
`sessionStorage` (see `src/storage-handoff.ts`). Navigation to `/prove` enters
the isolated document, where a fresh Worker warms up and proves. Hosts that
cannot serve path-scoped headers fall back to single-threaded mode.

The Vite dev server enforces this split via a tiny middleware plugin
(`coopPerPath` in `vite.config.ts`). Production hosts need the same
scoping:

- **Netlify / Cloudflare Pages / any `_headers`-aware host** —
  `public/_headers` in this repo is read as-is.
- **nginx** —
  ```nginx
  location = /prove       { more_set_headers "Cross-Origin-Opener-Policy: same-origin"; }
  location = /prove.html  { more_set_headers "Cross-Origin-Opener-Policy: same-origin"; }
  location /              { more_set_headers "Cross-Origin-Opener-Policy: same-origin-allow-popups"; }
  # COEP: require-corp on every location
  ```
- **Cloudflare Workers / Pages Functions** — route-match on `/prove*`
  and set `same-origin`; else set `same-origin-allow-popups`. Always
  set `Cross-Origin-Embedder-Policy: require-corp`.

If the host cannot serve path-scoped headers, fall back to single-threaded mode
(`same-origin-allow-popups` globally). The app still works, but proving is slower.

## Thread-count policy

```
threads = clamp(navigator.hardwareConcurrency - 1, 2, 8)
```

Leave one core for the main thread so UI updates stay smooth during proving.
The 8-thread cap is not arbitrary: wasm32 has a 4 GB linear-memory ceiling and
`certChainRS4096` proofs pressure it at higher thread counts. Override with
`?threads=<n>` on the URL if you want to experiment (clamped to `[1, 32]`).

## Storage inspection

Cached assets live in:

- **OPFS**: DevTools → Application → Storage → Origin Private File System.
  Each asset is stored at a cache key that embeds the upstream SHA-256
  (e.g. `certChainRS2048_pk_<sha>`); a key-hit doubles as proof of prior
  verification, so cached reads skip rehashing.
- **IndexedDB fallback**: database `zkid-assets`, object store `assets`.

To force a re-download, delete the corresponding entry (or run
`navigator.storage.getDirectory().then(d => d.remove(...))` in the console).

## Tests

```sh
pnpm test         # Vitest — asset-download, verifier, hipki, smt client unit tests
pnpm lint         # tsc --noEmit under "strict": true
pnpm build        # Production bundle
pnpm test:e2e     # Playwright against pnpm preview (mock verifier)
```

The e2e suite under `e2e/`:

- **`prove-fixtures.spec.ts`** — runs on every PR. Mocks the verifier +
  SMT via `page.route()` and the HiPKI popup via
  `globalThis.__HIPKI_TEST_HANDLER__` (set in `e2e/mock-services.ts`).
  Fixture PKs are not bundled, so the pipeline reaches `step-error` at the
  download step on a bare checkout — the test accepts either terminal
  state (done or error) to prove the pipeline plumbing works.
- **`prove-negative.spec.ts`** — wrong PIN three times → card-locked
  state with disabled inputs; verifier 500 → error + Retry.
- **`prove-real.spec.ts`** (`@real`) — gated by `E2E_MODE=real`. Runs
  against a live `go-zkid-verifier` and real Release keys. Nightly CI only.

Install browsers before first run: `pnpm exec playwright install --with-deps chromium`.

## Known limitations (v1)

- No resumable downloads. A failed fetch discards partial bytes; retry
  re-downloads from scratch. See `src/asset-download.ts` header comment.
- No `.partial` rename on writer commit — a crash between `pipeTo` close
  and the post-download SHA-256 check leaves bytes under a hash-suffixed
  cache key that the next run will trust via the key-hit fast path. The
  **Clear cached assets** button on the result screen is the operator
  escape hatch until atomic rename lands.
- `link_verify` runs server-side only; the WASM crate's `link_verify` export
  exists for the drift test but is not called from the production pipeline.
- The HiPKI popup bridge is single-shot per operation: every probe needs a
  user gesture, so live polling for card insertion is not possible.
  "Detect readers" + "Read card" are explicit clicks for that reason.
- The Worker can't be cancelled mid-step; `Retry` terminates and respawns
  the Worker, paying a small wasm-init cost in exchange for clean
  cancellation semantics.
