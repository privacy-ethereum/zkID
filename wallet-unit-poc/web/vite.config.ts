/// <reference types="vitest" />
import { resolve } from "node:path";

import {
  defineConfig,
  loadEnv,
  type Connect,
  type PluginOption,
  type PreviewServer,
  type ViteDevServer,
} from "vite";

const RELEASE_BASE = "https://github.com/zkmopro/zkID/releases/download/latest";
const SMT_SNAPSHOT_RELEASE_BASE =
  "https://github.com/privacy-ethereum/moica-revocation-smt/releases/download/snapshot-latest";

// COOP is scoped per URL so that the sign route keeps `window.opener` alive
// for the HiPKI popup while the proving route runs in a cross-origin-isolated
// context (required by `wasm-bindgen-rayon` for SharedArrayBuffer).
function coopPerPathMiddleware(): Connect.NextHandleFunction {
  return (req, res, next) => {
    const url = req.url ?? "";
    const isProve = url === "/prove" || url.startsWith("/prove.html") ||
      url.startsWith("/prove/") || url.startsWith("/prove?");
    res.setHeader("Cross-Origin-Embedder-Policy", "require-corp");
    res.setHeader(
      "Cross-Origin-Opener-Policy",
      isProve ? "same-origin" : "same-origin-allow-popups",
    );
    next();
  };
}

function coopPerPath(): PluginOption {
  return {
    name: "zkid-coop-per-path",
    configureServer(server: ViteDevServer) {
      server.middlewares.use(coopPerPathMiddleware());
    },
    configurePreviewServer(server: PreviewServer) {
      server.middlewares.use(coopPerPathMiddleware());
    },
  };
}

// sirv (preview's static handler) auto-applies Content-Encoding: gzip to *.gz,
// which trips the worker's own DecompressionStream pipeline. Strip the request
// Accept-Encoding and the response Content-Encoding for /keys/* and
// /smt-snapshot/* so preview matches prod (where assets are passed through
// verbatim by the deployer's CDN).
function stripAssetEncodingMiddleware(): Connect.NextHandleFunction {
  return (req, res, next) => {
    const url = req.url ?? "";
    if (url.startsWith("/keys/") || url.startsWith("/smt-snapshot/")) {
      delete (req.headers as Record<string, unknown>)["accept-encoding"];
      const origWriteHead = res.writeHead.bind(res);
      type WriteHeadArgs =
        | [statusCode: number, headers?: object]
        | [statusCode: number, statusMessage?: string, headers?: object];
      res.writeHead = (...args: WriteHeadArgs) => {
        const last = args[args.length - 1];
        if (last && typeof last === "object" && !Array.isArray(last)) {
          for (const k of Object.keys(last)) {
            if (k.toLowerCase() === "content-encoding") {
              delete (last as Record<string, unknown>)[k];
            }
          }
        }
        res.removeHeader("content-encoding");
        return origWriteHead(...(args as Parameters<typeof origWriteHead>));
      };
      res.removeHeader("content-encoding");
    }
    next();
  };
}

function stripAssetEncoding(): PluginOption {
  return {
    name: "zkid-preview-strip-asset-encoding",
    configurePreviewServer(server: PreviewServer) {
      server.middlewares.use(stripAssetEncodingMiddleware());
    },
  };
}

export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, process.cwd(), "");
  const SMT_SNAPSHOT_TARGET =
    env.VITE_SMT_SNAPSHOT_PROXY_TARGET ?? SMT_SNAPSHOT_RELEASE_BASE;

  return {
    plugins: [coopPerPath(), stripAssetEncoding()],
    build: {
      target: "es2020",
      rollupOptions: {
        input: {
          main: resolve(__dirname, "index.html"),
          prove: resolve(__dirname, "prove.html"),
        },
      },
    },
    worker: { format: "es" },
    optimizeDeps: { esbuildOptions: { target: "es2020" } },
    test: {
      exclude: ["node_modules/**", "dist/**", "e2e/**"],
    },
    server: {
      fs: { allow: [".."] },
      proxy: {
        "/keys": {
          target: RELEASE_BASE,
          changeOrigin: true,
          followRedirects: true,
          rewrite: (p) => p.replace(/^\/keys/, ""),
        },
        // SMT snapshot assets (smt.wasm, wasm_exec.js, per-issuer *.bin.gz)
        // come from the moica-revocation-smt `snapshot-latest` release. Same
        // shape as /keys: same-origin in dev via this proxy, same-origin in
        // prod via a deployer-configured reverse proxy. We never rely on
        // GitHub Release CORS headers.
        "/smt-snapshot": {
          target: SMT_SNAPSHOT_TARGET,
          changeOrigin: true,
          followRedirects: true,
          rewrite: (p) => p.replace(/^\/smt-snapshot/, ""),
        },
      },
    },
    // preview is static-only; an inherited proxy would shadow the dist files.
    preview: { proxy: {} },
  };
});
