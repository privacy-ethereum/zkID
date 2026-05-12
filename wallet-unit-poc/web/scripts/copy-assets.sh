#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WEB_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
REPO_ROOT="$(cd "${WEB_DIR}/../.." && pwd)"
WASM_PKG="${REPO_ROOT}/wallet-unit-poc/spartan2-wasm/pkg"
CIRCOM_BUILD="${REPO_ROOT}/wallet-unit-poc/circom/build"

mkdir -p "${WEB_DIR}/src/wasm" "${WEB_DIR}/public/assets"

# 1. spartan2-wasm output
if [ -d "${WASM_PKG}" ]; then
  cp "${WASM_PKG}"/spartan2_wasm.js "${WEB_DIR}/src/wasm/"
  cp "${WASM_PKG}"/spartan2_wasm.d.ts "${WEB_DIR}/src/wasm/"
  cp "${WASM_PKG}"/spartan2_wasm_bg.wasm.d.ts "${WEB_DIR}/src/wasm/"
  [ -d "${WASM_PKG}/snippets" ] && { rm -rf "${WEB_DIR}/src/wasm/snippets"; cp -R "${WASM_PKG}/snippets" "${WEB_DIR}/src/wasm/snippets"; }
  printf '{ "type": "module" }\n' > "${WEB_DIR}/src/wasm/package.json"
  printf 'export { default } from "./spartan2_wasm.js";\nexport * from "./spartan2_wasm.js";\n' > "${WEB_DIR}/src/wasm/index.js"
  cp "${WASM_PKG}"/spartan2_wasm_bg.wasm "${WEB_DIR}/src/wasm/"
fi

# 2. Circom witness calculators (one per circuit). witness_calculator.js is
#    identical across circomkit outputs for the same circom version — copy once.
for circuit in certChainRS2048 certChainRS4096 userSigRS2048; do
  SRC="${CIRCOM_BUILD}/${circuit}/${circuit}_js"
  if [ -d "${SRC}" ]; then
    cp "${SRC}/${circuit}.wasm" "${WEB_DIR}/public/assets/"
    [ -f "${WEB_DIR}/public/assets/witness_calculator.js" ] || \
      cp "${SRC}/witness_calculator.js" "${WEB_DIR}/public/assets/"
  fi
done
