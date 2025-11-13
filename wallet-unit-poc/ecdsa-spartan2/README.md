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
