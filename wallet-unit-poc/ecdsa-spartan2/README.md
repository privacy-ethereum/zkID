# ecdsa-spartan2

This crate contains the Spartan-based proving tooling used in the zkID wallet proof of concept.
It exposes a collection of CLI subcommands (under `cargo run --release -- …`) that let you
generate setup keys, produce proofs for the "prepare" and "show" circuits, and verify those
proofs against the Circom inputs found in `../circom/inputs`.

## End-to-end flow

```sh
# 1. Generate setup artifacts (keys stored in ./keys)
cargo run --release -- prepare setup --input ../circom/inputs/jwt/default.json
cargo run --release -- show setup --input ../circom/inputs/show/default.json

# 2. Generate shared blinds (shared across circuits)
cargo run --release -- generate_shared_blinds

# 3. Produce and reblind the prepare proof
cargo run --release -- prepare prove   --input ../circom/inputs/jwt/default.json
RUST_LOG=info cargo run --release -- prepare reblind

# 4. Produce and reblind the show proof
RUST_LOG=info cargo run --release -- show prove   --input ../circom/inputs/show/default.json
RUST_LOG=info cargo run --release -- show reblind

# 5. Verify the prepare proof
cargo run --release -- prepare verify

# 6. Verify the show proof
cargo run --release -- show verify
```

## Benchmark Results

The following tables show performance and size measurements for different JWT payload sizes (1KB - 8KB).

### Timing Measurements

All timing measurements are in milliseconds (ms).

**Test Device:** MacBook Pro, M4, 14-core GPU, 24GB RAM

#### Prepare Circuit Timing

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

### Size Measurements

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

### Running Benchmarks

To generate benchmark data for a specific payload size:

```sh
# Run the complete benchmark pipeline
cargo run --release -- benchmark

```
