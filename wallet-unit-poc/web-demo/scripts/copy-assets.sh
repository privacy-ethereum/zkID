#!/bin/bash
# Copy required assets into the web-demo public/ and src/ directories.
# Run from the web-demo directory: bash scripts/copy-assets.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
WEB_DEMO_DIR="$(dirname "$SCRIPT_DIR")"
SDK_DIR="$WEB_DEMO_DIR/../openac-sdk"
KEYS_DIR="$WEB_DEMO_DIR/../ecdsa-spartan2/keys"

echo "=== zkID Web Demo: Asset Setup ==="

# 1. Copy WASM JS glue + type files to src/wasm/ (Vite bundles them)
#    Copy WASM binary to public/ (served as a static file, fetched at runtime)
#    Copy snippets/ to src/wasm/snippets/ so Vite resolves the rayon worker
#    helper via the relative new URL('./snippets/...', import.meta.url) pattern.
echo "[1/5] Copying openac WASM module..."
mkdir -p "$WEB_DEMO_DIR/src/wasm"
cp "$SDK_DIR/wasm/pkg/openac_wasm.js"        "$WEB_DEMO_DIR/src/wasm/"
cp "$SDK_DIR/wasm/pkg/openac_wasm.d.ts"      "$WEB_DEMO_DIR/src/wasm/"
cp "$SDK_DIR/wasm/pkg/openac_wasm_bg.wasm.d.ts" "$WEB_DEMO_DIR/src/wasm/"
cp "$SDK_DIR/wasm/pkg/openac_wasm_bg.wasm"   "$WEB_DEMO_DIR/public/"

if [ -d "$SDK_DIR/wasm/pkg/snippets" ]; then
  rm -rf "$WEB_DEMO_DIR/src/wasm/snippets"
  cp -r "$SDK_DIR/wasm/pkg/snippets" "$WEB_DEMO_DIR/src/wasm/snippets"
  echo "  Copied snippets/ (rayon worker helpers)"
fi

# The bundler-mode workerHelpers.js does `import('../../..')` expecting to land
# at the package root (pkg/ in a normal npm install).  Copied into src/wasm/,
# that path resolves to the bare directory src/wasm/ — Vite needs an index.js
# there to know which file to load.
cat > "$WEB_DEMO_DIR/src/wasm/index.js" <<'EOF'
// Entry point for the wasm-bindgen-rayon bundler-mode worker helper.
// workerHelpers.js does `import('../../..')` which resolves to this directory;
// Vite picks up index.js and re-exports the real WASM glue module.
export * from './openac_wasm.js';
export { default } from './openac_wasm.js';
EOF
echo "  Created src/wasm/index.js (barrel for workerHelpers.js '../../..' import)"

# 2. Copy circom circuit WASM files to public/ (must match key size!)
CIRCOM_DIR="$WEB_DEMO_DIR/../circom/build"
echo "[2/5] Copying circuit WASM files..."
if [ -f "$CIRCOM_DIR/jwt_1k/jwt_1k_js/jwt_1k.wasm" ]; then
  cp "$CIRCOM_DIR/jwt_1k/jwt_1k_js/jwt_1k.wasm" "$WEB_DEMO_DIR/public/jwt.wasm"
  echo "  Copied jwt_1k.wasm → public/jwt.wasm"
else
  echo "  WARNING: jwt_1k.wasm not found — run 'yarn compile:all' in the circom directory first"
fi

if [ -f "$CIRCOM_DIR/show/show_js/show.wasm" ]; then
  cp "$CIRCOM_DIR/show/show_js/show.wasm" "$WEB_DEMO_DIR/public/show.wasm"
  echo "  Copied show.wasm"
else
  echo "  WARNING: show.wasm not found — run 'yarn compile:all' in the circom directory first"
fi

# 3. Copy witness_calculator.js to src/assets/ and patch CJS→ESM export
echo "[3/5] Copying witness calculator (CJS→ESM patch)..."
mkdir -p "$WEB_DEMO_DIR/src/assets"
cp "$SDK_DIR/assets/witness_calculator.js" "$WEB_DEMO_DIR/src/assets/"
# Vite only does CJS→ESM for node_modules, not src/ files.
# Patch the CJS module.exports to an ESM default export.
sed -i.bak 's/^module\.exports = async function builder/export default async function builder/' \
  "$WEB_DEMO_DIR/src/assets/witness_calculator.js"
rm -f "$WEB_DEMO_DIR/src/assets/witness_calculator.js.bak"

# 4. Symlink keys directory (local dev only — keys are not committed)
echo "[4/5] Symlinking keys directory..."
if [ -L "$WEB_DEMO_DIR/public/keys" ]; then
  rm "$WEB_DEMO_DIR/public/keys"
fi
if [ -d "$WEB_DEMO_DIR/public/keys" ]; then
  rm -rf "$WEB_DEMO_DIR/public/keys"
fi
if [ -d "$KEYS_DIR" ]; then
  ln -s "$KEYS_DIR" "$WEB_DEMO_DIR/public/keys"
  echo "  Linked public/keys → $KEYS_DIR"
else
  echo "  WARNING: keys directory not found at $KEYS_DIR — skipping symlink (run 'cargo run -- setup' in ecdsa-spartan2 first)"
fi

echo ""
echo "=== Done! ==="
echo "Verify with: ls -la public/ && ls src/wasm/ && ls src/wasm/snippets/ 2>/dev/null && ls src/assets/"
echo "Run with:    npm run dev"
