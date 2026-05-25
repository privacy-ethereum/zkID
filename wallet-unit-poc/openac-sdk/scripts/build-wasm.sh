#!/bin/bash
set -euo pipefail

# Build the Spartan2 WASM module using wasm-pack with rayon (multi-threading).
#
# Requires:
#   - nightly Rust with rust-src component (declared in rust-toolchain.toml)
#   - wasm-pack
#
# The +atomics,+bulk-memory,+mutable-globals target features enable SharedArrayBuffer
# (required for rayon thread pools).  The consuming page must be served with:
#   Cross-Origin-Opener-Policy: same-origin
#   Cross-Origin-Embedder-Policy: require-corp

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SDK_DIR="$(dirname "$SCRIPT_DIR")"
WASM_DIR="$SDK_DIR/wasm"

echo "=== Building OpenAC WASM module (rayon enabled) ==="
echo "WASM crate: $WASM_DIR"

# Check for wasm-pack
if ! command -v wasm-pack &> /dev/null; then
    echo "wasm-pack not found. Installing..."
    curl https://rustwasm.github.io/wasm-pack/installer/init.sh -sSf | sh
fi

cd "$WASM_DIR"

echo "Building WASM module..."
# Pass '.' explicitly so wasm-pack doesn't misinterpret '-Z' as the crate path.
# RUSTFLAGS must be an env var — wasm-pack ignores .cargo/config.toml rustflags.
#
# --shared-memory      marks the WebAssembly.Memory type as shared (limits byte
#                      0x03).  Without this the memory cannot be sent via
#                      postMessage to workers (DataCloneError).
# --max-memory=...     required whenever --shared-memory is set; wasm-ld rejects
#                      shared memory without an explicit maximum page count.
#                      2 GB covers the Spartan2 1k peak (~2.3 GB on mobile).
# --import-memory      makes the WASM module import its memory from the JS host
#                      instead of defining it inline.  wasm-bindgen's threading
#                      transform asserts mem.import.is_some(); without this flag
#                      the build panics with: "assertion failed: mem.import.is_some()"
# --export=*           wasm-bindgen's threading transform (transforms/threads/mod.rs)
#                      looks up every TLS and heap symbol via the module's export
#                      table (delete_synthetic_export / get_tls_base).  wasm-ld
#                      does not export these by default when --shared-memory is
#                      active, so each one must be forced:
#
#   __heap_base       i32 global — start of the heap; used to place the
#                     thread-ID counter ("failed to find __heap_base…")
#   __wasm_init_tls   function — initialises TLS for each new thread
#                     ("failed to find __wasm_init_tls")
#   __tls_size        i32 global — byte size of the TLS block
#   __tls_align       i32 global — alignment of the TLS block
#   __tls_base        i32 global — base address of TLS for the current thread
RUSTUP_TOOLCHAIN=nightly \
RUSTFLAGS='-C target-feature=+atomics,+bulk-memory,+mutable-globals -C link-arg=--shared-memory -C link-arg=--max-memory=2147483648 -C link-arg=--import-memory -C link-arg=--export=__heap_base -C link-arg=--export=__wasm_init_tls -C link-arg=--export=__tls_size -C link-arg=--export=__tls_align -C link-arg=--export=__tls_base' \
wasm-pack build . \
    --target web \
    --out-dir pkg \
    --release \
    -- \
    -Z build-std=panic_abort,std

echo "=== WASM build complete ==="
echo "Output: $WASM_DIR/pkg/"

# Copy circuit artifacts if they exist
CIRCOM_BUILD="$SDK_DIR/../circom/build"
ASSETS_DIR="$SDK_DIR/assets"

if [ -d "$CIRCOM_BUILD" ]; then
    echo "Copying circuit artifacts to assets/..."

    if [ -f "$CIRCOM_BUILD/jwt/jwt_js/jwt.r1cs" ]; then
        cp "$CIRCOM_BUILD/jwt/jwt_js/jwt.r1cs" "$ASSETS_DIR/jwt.r1cs"
        echo "  Copied jwt.r1cs"
    fi

    if [ -f "$CIRCOM_BUILD/show/show_js/show.r1cs" ]; then
        cp "$CIRCOM_BUILD/show/show_js/show.r1cs" "$ASSETS_DIR/show.r1cs"
        echo "  Copied show.r1cs"
    fi

    if [ -f "$CIRCOM_BUILD/jwt/jwt_js/jwt.wasm" ]; then
        cp "$CIRCOM_BUILD/jwt/jwt_js/jwt.wasm" "$ASSETS_DIR/jwt.wasm"
        echo "  Copied jwt.wasm (witness calculator)"
    fi

    if [ -f "$CIRCOM_BUILD/show/show_js/show.wasm" ]; then
        cp "$CIRCOM_BUILD/show/show_js/show.wasm" "$ASSETS_DIR/show.wasm"
        echo "  Copied show.wasm (witness calculator)"
    fi

    echo "Circuit artifacts copied to $ASSETS_DIR/"
else
    echo "Warning: Circom build directory not found at $CIRCOM_BUILD"
    echo "Run 'yarn compile:all' from the circom directory first."
fi

echo "=== Build complete ==="
