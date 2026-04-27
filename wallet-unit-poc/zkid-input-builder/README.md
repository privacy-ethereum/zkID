# zkid-input-builder

Shared circuit-input builder for the zkID split RS256 pipeline. Produces
cert-chain (Circuit A) and device-sig (Circuit B) input JSON from card + SMT data.

Consumed by two callers:

- [`ecdsa-spartan2`](../ecdsa-spartan2) — the native Rust prover / CLI
- [`spartan2-wasm`](../spartan2-wasm) — the in-browser prover

Both paths call `generate_split_inputs` via a path dependency, so web and CLI
produce byte-identical input JSON. That guarantee is pinned by
[`spartan2-wasm/tests/input_builder_drift.rs`](../spartan2-wasm/tests/input_builder_drift.rs),
which guards against silent input-shape drift (for example,
`Too many values for input signal __placeholder__`).

Scope is deliberately narrow: cert parsing, bigint chunking, SHA-256 padding,
and `generate_split_inputs`. No Spartan2/prover types leak in.

## Test

```sh
cd wallet-unit-poc/zkid-input-builder
cargo test --release
```

CI runs this under `.github/workflows/web-tests.yaml` alongside the drift guard.

## Public surface

- `generate_split_inputs(user_cert, issuer_cert, user_signature_b64, tbs, serial_hex, smt_inputs, k_issuer, k_user, max_cert_length, app_id)`
  — returns `(cert_chain_json, device_sig_json)`. `app_id` is a decimal-string
  field element that is included in `nullifier` as
  `Poseidon(packed_subject_dn, app_id)`, binding the proof to a specific
  application. Must match the value the verifier expects.
- `SmtCircuitInputs` — decimal-string field struct matching the Rust/TS
  interchange format used by both provers.
- `parse_cert_offsets` — DER offset helpers for the cert-chain circuit's
  byte-range signals.

See `src/split_inputs.rs` for the canonical wiring.

## Why a separate crate

- Keeps the browser build free of transitive Spartan2 / ecdsa-spartan2 native deps.
- Makes the byte-identity guarantee enforceable: a single `generate_split_inputs`
  implementation serialized via `serde_json` with stable key order.
- Lets the wasm drift test depend on both provers without creating a cycle.
