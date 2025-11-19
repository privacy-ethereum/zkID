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
|  iPhone 17   |   3460 ms   |    1858 ms     |  4602 ms  |
| Pixel 10 Pro |   8398 ms   |    2972 ms     |  12994 ms  |

Peak Memory Usage for Proving: **2.27 GiB**

### Show Circuits
|    Device    | Prover Time | Verifier Time | Key Setup |
|:------------:|:-----------:|:-------------:|:---------:|
|  iPhone 17   |    115 ms    |     36 ms     |   60 ms   |
| Pixel 10 Pro |   394 ms    |     120 ms     |  210 ms   |


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

