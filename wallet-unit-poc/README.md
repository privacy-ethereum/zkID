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

| Device        | Proving Time | Reblind Time | Verifier Time | Key Setup |
|---------------|--------------|--------------|----------------|-----------|
| iPhone 17     | 3460 ms      | 1401 ms      | 1858 ms        | 4602 ms   |
| Pixel 10 Pro  | 8398 ms      | 3113 ms       | 2972 ms        | 12994 ms  |

<!-- Peak Memory Usage for Proving: **2.27 GiB** -->

#### Show Circuit (Mobile)

|    Device     | Prover Time (Includes Reblind) | Verifier Time | Key Setup |
|:-------------:|:-------------------------------:|:-------------:|:---------:|
|   iPhone 17    |              158 ms             |     36 ms     |   60 ms   |
| Pixel 10 Pro  |              609 ms             |    120 ms     |  210 ms   |

<table>
  <tr>
    <th>iPhone 17</th>
    <th>Pixel 10 Pro</th>
  </tr>
  <tr>
    <td align="center">
      <img src="https://github.com/user-attachments/assets/fd1a26aa-6838-46ff-81e5-4b3ee68d4268" width="250">
    </td>
    <td align="center">
      <img src="https://github.com/user-attachments/assets/29b8434b-6eb2-43c7-88f2-e8dd9427f778" width="250">
    </td>
  </tr>
</table>
