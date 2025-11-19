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

#### Prepare Circuit Timing

| Payload Size | Setup (ms) | Prove (ms) | Reblind (ms) | Verify (ms) |
| ------------ | ---------- | ---------- | ------------ | ----------- |
| 1KB          | 3,150      | 1,847      | 621          | 1,084       |
| 1920 Bytes   | 5,187      | 3,016      | 1,183        | 1,787       |
| 2KB          | 5,316      | 3,110      | 1,181        | 1,880       |
| 3KB          | 7,257      | 4,174      | 2,023        | 2,461       |
| 4KB          | 9,392      | 5,362      | 2,241        | 3,179       |
| 5KB          | 11,463     | 6,918      | 2,343        | 4,241       |
| 6KB          | 13,033     | 7,627      | 2,446        | 4,310       |
| 7KB          | 15,811     | 9,040      | 4,266        | 5,693       |
| 8KB          | 17,815     | 10,903     | 4,421        | 7,664       |

#### Show Circuit Timing

The Show circuit has constant performance regardless of JWT payload size.

| Metric  | Time (ms) |
| ------- | --------- |
| Setup   | ~45       |
| Prove   | ~83       |
| Reblind | ~37       |
| Verify  | ~32       |

### Size Measurements

#### Prepare Circuit Sizes

| Payload Size | Proving Key (MB) | Verifying Key (MB) | Proof Size (KB) | Witness Size (MB) |
| ------------ | ---------------- | ------------------ | --------------- | ----------------- |
| 1KB          | 252.76           | 252.76             | 75.80           | 32.03             |
| 1920 Bytes   | 420.05           | 420.05             | 109.29          | 64.06             |
| 2KB          | 439.28           | 439.28             | 109.29          | 64.06             |
| 3KB          | 611.44           | 611.44             | 175.77          | 128.13            |
| 4KB          | 768.11           | 768.11             | 175.77          | 128.13            |
| 5KB          | 902.98           | 902.98             | 175.77          | 128.13            |
| 6KB          | 1,035.36         | 1,035.36           | 175.77          | 128.13            |
| 7KB          | 1,263.74         | 1,263.74           | 308.26          | 256.25            |
| 8KB          | 1,396.12         | 1,396.12           | 308.26          | 256.25            |

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
