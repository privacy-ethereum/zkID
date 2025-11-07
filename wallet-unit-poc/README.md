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

For the reproduction of mobile benchmarks, please check this repo: https://github.com/moven0831/spartan2-hyrax-mopro

### Prepare Circuits
|    Device    | Prover Time | Verifier Time | Key Setup |
|:------------:|:-----------:|:-------------:|:---------:|
|  iPhone 17   |   2996 ms   |    156 ms     |  3718 ms  |
| Pixel 10 Pro |   6680 ms   |    342 ms     |  9682 ms  |

Peak Memory Usage for Proving: **2.27 GiB**

### Show Circuits
|    Device    | Prover Time | Verifier Time | Key Setup |
|:------------:|:-----------:|:-------------:|:---------:|
|  iPhone 17   |    79 ms    |     12 ms     |   93 ms   |
| Pixel 10 Pro |   344 ms    |     54 ms     |  180 ms   |

Peak Memory Usage for Proving: **1.96 GiB**

### PC Benchmarks

(MacBook Pro, 24 GB RAM, 14-core GPU, M4)

| Operation                                         | Time        |
| ------------------------------------------------- | ----------- |
| Complete jwt_prove (include witness generation)   | 2.7 seconds |
| Complete ecdsa_prove (include witness generation) | 69ms        |
