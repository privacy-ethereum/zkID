use rust_witness::transpile::transpile_wasm;

fn main() {
    // // Transpile WASM files from the circom build directory to C
    // // This will transpile both ECDSA and JWT circuits
    transpile_wasm("../circom/build/".to_string());
}
