// Entry point for the wasm-bindgen-rayon bundler-mode worker helper.
// workerHelpers.js does `import('../../..')` which resolves to this directory;
// Vite picks up index.js and re-exports the real WASM glue module.
export * from './openac_wasm.js';
export { default } from './openac_wasm.js';
