# zkID wallet-unit-poc

Privacy-preserving X.509 certificate verification using zero-knowledge proofs.
Given a MOICA user certificate (RSA-SHA256 / RS256) and a user signature over
the relying-party `app_id`, the prover emits two Spartan2 proofs that together
attest to (a) a valid cert chain to a known issuer, (b) non-revocation of the
user cert against an SMT root, and (c) possession of the user private key —
without revealing personal data from the cert. The `nullifier` is
`Poseidon(user_rsa_signature)`: deterministic per `(card, app_id)`, and
unforgeable without the card's private key. A per-session `challenge` field
element from the verifier is bound into the user-sig proof via a
Semaphore-style dummy square (`challengeSquared <== challenge * challenge`),
so a precomputed proof cannot be replayed against a different session.

Three proving surfaces share the same circuits, input builder, and proving engine:

| Surface | Path | Use for |
|---|---|---|
| **Web prover** | [`web/`](./web) + [`spartan2-wasm/`](./spartan2-wasm) | In-browser proving with server-side verification. Start here for end-user flows. |
| **Native CLI** | [`ecdsa-spartan2/`](./ecdsa-spartan2) | Benchmarks, fixture generation, end-to-end dev loop on a workstation. |
| **Mobile** | [`mobile/`](./mobile) | iOS / Android / Flutter bindings via mopro-ffi. |

Shared crates:

- [`circom/`](./circom) — ZK circuits (`certChainRS2048`,
  `certChainRS4096`, `userSigRS2048`) on the secq256r1 field.
- [`zkid-input-builder/`](./zkid-input-builder) — shared Rust crate that builds
  byte-identical circuit input JSON for both the native and browser provers.
- [`openac-sdk/`](./openac-sdk) — TypeScript SDK for credential handling.

Web prover architecture in short: the app uses two routes with different COOP
headers (`/` for popup-compatible signing, `/prove` for cross-origin-isolated
threaded proving), and hands off `ProveInput` via sessionStorage.

## Quick start (web prover)

```sh
# 1. Compile the three circuits (produces R1CS + C++ + WASM artifacts).
cd wallet-unit-poc/circom
yarn install
yarn compile:all

# 2. Build the wasm prover bundle and start the dev server.
cd ../web
cp .env.example .env.local   # adjust verifier / HiPKI / SMT URLs as needed
pnpm install
pnpm dev                     # runs build:wasm + copy:assets + vite
```

Open the printed URL (typically `http://localhost:5173`). The landing page drives
setup; `/prove` runs the cross-origin-isolated proving document.

## Quick start (native CLI)

Prereqs: Rust stable, `yarn` for circom, system libs listed in
[`CLAUDE.md`](../CLAUDE.md#system-dependencies-for-cilocal).

```sh
cd wallet-unit-poc/circom && yarn install && yarn compile:all
cd ../ecdsa-spartan2

# Generate cert-chain + user-sig inputs from bundled fixtures.
RUST_LOG=info cargo run --release -- generate-split-input

# Setup → prove → verify (cert-chain, RSA-2048 issuer / MOICA-G2).
cargo run --release --features cert_chain_rs2048 -- cert-chain setup
cargo run --release --features cert_chain_rs2048 -- cert-chain prove \
  --input ../circom/inputs/cert_chain_rs2048/input.json
cargo run --release --features cert_chain_rs2048 -- cert-chain verify

# Setup → prove → verify (user-sig, always RSA-2048; default feature).
cargo run --release -- user-sig setup
cargo run --release -- user-sig prove \
  --input ../circom/inputs/user_sig_rs2048/input.json
cargo run --release -- user-sig verify

# Cross-proof link-verify (pk_commit equality).
RUST_LOG=info cargo run --release -- link-verify
```

Benchmarks live in [`ecdsa-spartan2/README.md`](./ecdsa-spartan2/README.md).

## Tests

Each surface has its own test suite; see the per-package README for details.

```sh
# Circuits (mocha)
cd wallet-unit-poc/circom && NODE_OPTIONS=--max-old-space-size=16384 yarn test

# Shared input builder
cd wallet-unit-poc/zkid-input-builder && cargo test --release

# Native prover + E2E split flow
cd wallet-unit-poc/ecdsa-spartan2 && cargo test --release

# Wasm crate unit + drift guards
cd wallet-unit-poc/spartan2-wasm && cargo test --release

# Web app (vitest + tsc + pin-leak guard)
cd wallet-unit-poc/web && pnpm install && pnpm test && pnpm lint
```

CI wires these up across five workflows (`circom-tests`, `rust-tests`,
`web-tests`, `mobile-tests`, plus reusable `compile-circuits`). The full split
E2E (RS2048 + RS4096 cert-chain + user-sig + link-verify) runs on PRs that
touch relevant paths. See [`CLAUDE.md`](../CLAUDE.md#ci-workflows) for the full matrix.

## Repo layout

```
wallet-unit-poc/
├── circom/               # Circuits + inputs + witness calculator
├── zkid-input-builder/   # Shared Rust crate: cert → circuit JSON
├── ecdsa-spartan2/       # Native CLI prover (Spartan2 + Hyrax)
├── spartan2-wasm/        # wasm-bindgen prover for the browser
├── web/                  # Vite app (/ and /prove routes)
├── mobile/               # mopro-ffi bindings + Flutter app
├── openac-sdk/           # TypeScript SDK
```

## Privacy & data handling

Never commit real certificate or personal data from MOICA/HiPKI cards — only
use the bundled test fixtures in `ecdsa-spartan2/tests/testdata/`. The web app
enforces this at build time via `web/scripts/check-no-pin-leak.sh`, which scans
for PIN substrings in any committed source.
