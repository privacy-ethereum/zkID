## Setup

### Step 1: Compile Circom Circuits

Compile the circom circuits with secq256r1 as native field:

```sh
yarn
yarn compile:jwt
yarn compile:ecdsa
```

This creates a build folder containing R1CS and WASM files for circuits.

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

This section contains comprehensive benchmark results for zkID wallet proof of concept, covering both desktop and mobile implementations.

### Desktop Benchmarks (ecdsa-spartan2)

Performance measurements for different JWT payload sizes running on desktop hardware.

**Test Device:** MacBook Pro, M4, 14-core GPU, 24GB RAM

#### Prepare Circuit Timing

All timing measurements are in milliseconds (ms).

| Payload Size | Setup (ms) | Prove (ms) | Reblind (ms) | Verify (ms) |
| ------------ | ---------- | ---------- | ------------ | ----------- |
| 1KB          | 2,559      | 1,683      | 382          | 35          |
| 1920 Bytes   | 4,157      | 2,727      | 715          | 74          |
| 2KB          | 4,384      | 2,934      | 753          | 83          |
| 3KB          | 6,466      | 4,242      | 1,357        | 119         |
| 4KB          | 8,529      | 5,282      | 1,374        | 131         |
| 5KB          | 10,979     | 6,166      | 1,460        | 140         |
| 6KB          | 12,993     | 8,407      | 2,821        | 280         |
| 7KB          | 15,151     | 8,856      | 2,732        | 230         |
| 8KB          | 16,559     | 9,614      | 2,683        | 246         |

#### Show Circuit Timing

The Show circuit has constant performance regardless of JWT payload size.

| Metric  | Time (ms) |
| ------- | --------- |
| Setup   | ~36       |
| Prove   | ~77       |
| Reblind | ~25       |
| Verify  | ~9        |


#### Prepare Circuit Sizes

| Payload Size | Proving Key (MB) | Verifying Key (MB) | Proof Size (KB) | Witness Size (MB) |
| ------------ | ---------------- | ------------------ | --------------- | ----------------- |
| 1KB          | 252.76           | 252.76             | 75.80           | 32.03             |
| 1920 Bytes   | 420.05           | 420.05             | 109.29          | 64.06             |
| 2KB          | 433.76           | 433.76             | 109.29          | 64.06             |
| 3KB          | 636.35           | 636.35             | 175.77          | 128.13            |
| 4KB          | 836.79           | 836.79             | 175.77          | 128.13            |
| 5KB          | 964.70           | 964.70             | 175.77          | 128.13            |
| 6KB          | 1,222.26         | 1,222.26           | 308.26          | 256.25            |
| 7KB          | 1,382.31         | 1,382.31           | 308.26          | 256.25            |
| 8KB          | 1,542.35         | 1,542.35           | 308.26          | 256.25            |

#### Show Circuit Sizes

The Show circuit has constant sizes regardless of JWT payload size.

| Metric        | Size      |
| ------------- | --------- |
| Proving Key   | 3.45 MB   |
| Verifying Key | 3.45 MB   |
| Proof Size    | 40.41 KB  |
| Witness Size  | 512.52 KB |

#### Running Desktop Benchmarks

```sh
cd ecdsa-spartan2
cargo run --release -- benchmark
```

### Mobile Benchmarks

For the reproduction of mobile benchmarks, please check this repo: https://github.com/moven0831/spartan2-hyrax-mopro

#### Prepare Circuit (Mobile)

- Payload Size: 1920 Bytes
- Peak Memory Usage for Proving: 2.27 GiB

|    Device    | Setup (ms) | Prove (ms) | Reblind (ms) | Verify (ms) |
|:------------:|:----------:|:----------:|:------------:|:-----------:|
|  iPhone 17   |    3499    |    2987    |     856      |     151     |
| Pixel 10 Pro |    9233    |    7318    |     1750     |     318     |

### Show Circuit Timing

The Show circuit has constant performance regardless of JWT payload size.
- Peak Memory Usage for Proving: 1.96 GiB

|    Device    | Setup (ms) | Prove (ms) | Reblind (ms) | Verify (ms) |
|:------------:|:----------:|:----------:|:------------:|:-----------:|
|  iPhone 17   |     47     |     99     |      30      |     13      |
| Pixel 10 Pro |    122     |    340     |     125      |     61      |

| iPhone 17 | Pixel 10 Pro |
|-----------|--------------|
| <img src="https://github.com/user-attachments/assets/45cabf07-66e8-446a-add6-bf036b2f40fa" width="300"> | <img src="https://github.com/user-attachments/assets/2d9499d4-e06e-4dc2-9a12-41fe9033245b" width="300"> |
