## Setup

1. Firstly, we need compile the circom circuits with secq256r1 as native field

To compile the jwt and ecdsa circuits

```sh
yarn
yarn compile:jwt
yarn compile:ecdsa
```

this will create a build folder which contains r1cs and wasm files for circuits
note> JWT R1cs is almost 900mb. we need find a way to load this inside mobile.

2. Porting this circom R1CS inside spartan2

```sh
   RUST_LOG=info cargo run --release -- ecdsa
   RUST_LOG=info cargo run --release -- jwt
```

we need to bench:

- [Background process] Spartan sumcheck for jwt.circom
  - ~14s (Macbook Pro, 24GB RAM, 14 core GPU, M4)
- [Live proving] Spartan sumcheck + Hyrax for ECDSA
  - 181ms (Macbook Pro, 24GB RAM, 14 core GPU, M4)
- [One-time setup] Spartan sumcheck + Hyrax PCS for jwt.circom
  - ~14 + 2.2 = 16.2s (Macbook Pro, 24GB RAM, 14 core GPU, M4)
