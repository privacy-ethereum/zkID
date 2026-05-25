import path from "path";
import { defineConfig } from "vite";

export default defineConfig({
  // BigInt support requires ES2020+
  build: {
    target: "es2020",
  },
  optimizeDeps: {
    esbuildOptions: {
      target: "es2020",
    },
  },
  resolve: {
    // openac-sdk lives next to web-demo (not inside it), so node resolution
    // won't find web-demo's node_modules when walking up from openac-sdk/src/.
    // Force all @noble/* imports (from any file) to use web-demo's copies.
    alias: [
      {
        find: /^@noble\/(.*)/,
        replacement: path.resolve(__dirname, "node_modules/@noble/$1"),
      },
    ],
  },
  server: {
    headers: {
      // Required for SharedArrayBuffer (rayon thread pool) and WASM
      "Cross-Origin-Opener-Policy": "same-origin",
      "Cross-Origin-Embedder-Policy": "require-corp",
    },
    // Allow serving files from parent directories (openac-sdk source)
    fs: {
      allow: [".."],
    },
  },
});
