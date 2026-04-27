# ecdsa-spartan2

Spartan2-based proving tooling for the zkID wallet proof of concept.

Two linked circuits prove certificate ownership without revealing personal data:
- **cert-chain** (Circuit A): certificate chain verification + SMT revocation + pk_commit
- **device-sig** (Circuit B): device signature verification + pk_commit + packed_tbs

Proofs are bound via `pk_commit = ChunkedPoseidonP256(user_pk_limbs ‖ pk_blind)` — computed identically in both circuits so the verifier can check `pk_commit_A == pk_commit_B`.

## Prerequisites

- **Rust** (stable toolchain)
- **Compiled circuits** — run `cd ../circom && yarn install && yarn compile:all` once
- **Default mode**: no other prerequisites (uses bundled test fixtures)
- **Live mode**: [HiPKI LocalSignServer](https://publicca.hinet.net/HiPKI-01.htm) running on `localhost:61161`, a card reader, a valid Citizen Digital Certificate, and optionally [go-zkid-verifier](https://github.com/user/go-zkid-verifier) for challenge serving

| Feature flag | Circuit | Key size | Issuer | Default |
|---|---|---|---|---|
| `cert_chain_rs2048` | cert-chain (A) | RSA-2048 | MOICA-G2 | no |
| `cert_chain_rs4096` | cert-chain (A) | RSA-4096 | 4096-bit CA | no |
| `device_sig_rs2048` | device-sig (B) | RSA-2048 | (user key) | **yes** |

## E2E Flow with Test Fixtures (no card reader needed)

```bash
cd wallet-unit-poc/ecdsa-spartan2

# 1. Generate split circuit inputs from bundled test fixtures
RUST_LOG=info cargo run --release -- generate-split-input

# 2. Setup proving keys (one-time per circuit)
RUST_LOG=info cargo run --release --features cert_chain_rs2048 -- cert-chain setup
RUST_LOG=info cargo run --release -- device-sig setup

# 3. Generate proofs
RUST_LOG=info cargo run --release --features cert_chain_rs2048 -- cert-chain prove \
  --input ../circom/inputs/cert_chain_rs2048/input.json
RUST_LOG=info cargo run --release -- device-sig prove \
  --input ../circom/inputs/device_sig_rs2048/input.json

# 4. Verify proofs independently
RUST_LOG=info cargo run --release --features cert_chain_rs2048 -- cert-chain verify
RUST_LOG=info cargo run --release -- device-sig verify

# 5. Link-verify: check pk_commit equality across both proofs
RUST_LOG=info cargo run --release -- link-verify
```

For the **RSA-4096 issuer** variant, add `--cert-chain-4096` / `-4` and swap the feature flag:

```bash
RUST_LOG=info cargo run --release -- generate-split-input --cert-chain-4096

RUST_LOG=info cargo run --release --features cert_chain_rs4096 -- cert-chain setup --cert-chain-4096
RUST_LOG=info cargo run --release --features cert_chain_rs4096 -- cert-chain prove \
  --cert-chain-4096 --input ../circom/inputs/cert_chain_rs4096/input.json
RUST_LOG=info cargo run --release --features cert_chain_rs4096 -- cert-chain verify --cert-chain-4096

# device-sig is always rs2048 (user keys are 2048-bit)
RUST_LOG=info cargo run --release -- device-sig setup
RUST_LOG=info cargo run --release -- device-sig prove \
  --input ../circom/inputs/device_sig_rs2048_chain_rs4096/input.json
RUST_LOG=info cargo run --release -- device-sig verify

RUST_LOG=info cargo run --release -- link-verify --cert-chain-4096
```

## E2E Flow with Real Data (HiPKI card + challenge server)

Requires a physical card reader with a valid Citizen Digital Certificate inserted, and [HiPKI LocalSignServer](https://publicca.hinet.net/HiPKI-01.htm) running.

### RSA-2048 (MOICA-G2)

```bash
cd wallet-unit-poc/ecdsa-spartan2

# 1. Generate split inputs — live mode fetches a TBS challenge from
#    the verifier, signs it with the card, and generates circuit inputs
RUST_LOG=info cargo run --release -- generate-split-input \
  --pin <YOUR_PIN>

# With SMT revocation server and custom endpoints:
RUST_LOG=info cargo run --release -- generate-split-input \
  --pin <YOUR_PIN> \
  --smt-server http://localhost:3000 \
  --hipki-server http://localhost:61161 \
  --challenge-server http://localhost:8080

# 2. Setup proving keys (skip if already generated)
RUST_LOG=info cargo run --release --features cert_chain_rs2048 -- cert-chain setup
RUST_LOG=info cargo run --release -- device-sig setup

# 3. Generate proofs
RUST_LOG=info cargo run --release --features cert_chain_rs2048 -- cert-chain prove \
  --input ../circom/inputs/cert_chain_rs2048/input.json
RUST_LOG=info cargo run --release -- device-sig prove \
  --input ../circom/inputs/device_sig_rs2048/input.json

# 4. Verify + link-verify
RUST_LOG=info cargo run --release --features cert_chain_rs2048 -- cert-chain verify
RUST_LOG=info cargo run --release -- device-sig verify
RUST_LOG=info cargo run --release -- link-verify
```

### RSA-4096 (4096-bit issuer)

```bash
RUST_LOG=info cargo run --release -- generate-split-input \
  --cert-chain-4096 --pin <YOUR_PIN>

RUST_LOG=info cargo run --release --features cert_chain_rs4096 -- cert-chain setup --cert-chain-4096
RUST_LOG=info cargo run --release -- device-sig setup

RUST_LOG=info cargo run --release --features cert_chain_rs4096 -- cert-chain prove \
  --cert-chain-4096 --input ../circom/inputs/cert_chain_rs4096/input.json
RUST_LOG=info cargo run --release -- device-sig prove \
  --input ../circom/inputs/device_sig_rs2048_chain_rs4096/input.json

RUST_LOG=info cargo run --release --features cert_chain_rs4096 -- cert-chain verify --cert-chain-4096
RUST_LOG=info cargo run --release -- device-sig verify
RUST_LOG=info cargo run --release -- link-verify --cert-chain-4096
```

### CLI flags for `generate-split-input`

| Flag | Default | Description |
|---|---|---|
| `--pin <PIN>` | *(off)* | Enables live mode — signs TBS via HiPKI card |
| `--cert-chain-4096` / `-4` | rs2048 | Use RSA-4096 issuer (MOICA-G3) |
| `--smt-server <URL>` | *(off)* | Fetch SMT non-membership proof for revocation |
| `--hipki-server <URL>` | `http://localhost:61161` | HiPKI LocalSignServer endpoint |
| `--challenge-server <URL>` | `http://localhost:8080` | go-zkid-verifier challenge endpoint |
| `--app-id <DECIMAL>` | `0` | Application identifier bound into `nullifier`; must match the verifier's expected value |

## Benchmark

```bash
RUST_LOG=info cargo run --release --features cert_chain_rs2048 -- cert-chain benchmark \
  --input ../circom/inputs/cert_chain_rs2048/input.json

RUST_LOG=info cargo run --release -- device-sig benchmark \
  --input ../circom/inputs/device_sig_rs2048/input.json
```

## Tests

```bash
RUST_LOG=info cargo test --release
```

## Regenerating test fixtures

The bundled synthetic fixtures in `tests/testdata/` are generated deterministically
from a fixed seed. Regenerate them after a fresh clone or whenever the synthetic
RSA key material needs to rotate:

```bash
RUST_LOG=info cargo run --example generate_fixtures
RUST_LOG=info cargo test --release fixture_consistency
```
