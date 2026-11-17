// Bundle worker.mjs for Cloudflare Workers with esbuild.
// Usage: npm run build   → dist/worker.js
// The snarkjs browser ESM build is bundled (platform: browser); the circuit
// artifacts are NOT bundled — the Worker fetches them at runtime.

import { build } from "esbuild";

await build({
  entryPoints: ["worker.mjs"],
  bundle: true,
  platform: "browser",
  format: "esm",
  outfile: "dist/worker.js",
  minify: true,
  logLevel: "info",
  // Cloudflare Workers exposes a global Blob but NOT URL.createObjectURL,
  // and ffjavascript's threadman calls URL.createObjectURL(blob) at module
  // scope when (process.browser && globalThis.Blob). Hiding Blob makes it
  // take its data-URL fallback instead (a plain string; never used — the
  // Workers runtime has no Worker constructor, so buildThreadManager runs
  // single-threaded anyway). Without this the deploy is rejected with
  // HTTP 400 / code 10021 "URL.createObjectURL() is not implemented".
  banner: {
    js: "globalThis.Blob = undefined;",
  },
});
