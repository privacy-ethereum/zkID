## Setup

### Step 1: Compile Circom Circuits

Compile the circom circuits with secq256r1 as native field:

```sh
yarn
yarn compile:jwt
yarn compile:ecdsa
```

This creates a build folder containing R1CS and WASM files for circuits.

> **Note:** JWT R1CS is almost 900MB. We need to find a way to load this inside mobile.

### Step 2: Setup Keys for Circuits

Setup keys for ECDSA circuit:

```sh
RUST_LOG=info cargo run --release -- setup_ecdsa
```

Setup keys for JWT circuit:

```sh
RUST_LOG=info cargo run --release -- setup_jwt
```

### Step 3: Run Circuits

Run ECDSA circuit:

```sh
RUST_LOG=info cargo run --release -- prove_ecdsa
```

Run JWT circuit:

```sh
RUST_LOG=info cargo run --release -- prove_jwt
```

## Benchmarks

### Mobile Benchmarks

(with precomputed witness generation)

| Device                     | Proving Time |
| -------------------------- | ------------ |
| iPhone 17 simulator        | ~2.2s        |
| iPhone 16 (old device)     | ~2.14s       |
| Memory peak (JWT circuits) | 1.97 GiB     |

### PC Benchmarks

(MacBook Pro, 24 GB RAM, 14-core GPU, M4)

| Operation                                         | Time        |
| ------------------------------------------------- | ----------- |
| Complete jwt_prove (include witness generation)   | 2.7 seconds |
| Complete ecdsa_prove (include witness generation) | 69ms        |
