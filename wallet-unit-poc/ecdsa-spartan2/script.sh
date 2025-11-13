## Build

cargo build --release

## SETUP 

RUST_LOG=info cargo run --release -- setup_prepare

RUST_LOG=info cargo run --release -- setup_show

### GENERATE SHARED BLINDS

RUST_LOG=info cargo run --release -- generate_shared_blinds

## RUN

RUST_LOG=info cargo run --release -- prepare prove 

RUST_LOG=info cargo run --release -- prepare reblind


### SHOW
RUST_LOG=info cargo run --release -- show prove 

RUST_LOG=info cargo run --release -- show reblind