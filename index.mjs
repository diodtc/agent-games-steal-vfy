// Node entry point (local dev / testing).
// Usage: npm start  (reads env from process.env; see .env.example)

import { serve } from "@hono/node-server";
import { readFile } from "node:fs/promises";
import { setRuntimeEnv } from "./src/config.mjs";
import { createApp } from "./src/app.mjs";

setRuntimeEnv(process.env);

let artifactsCache = null;
async function loadArtifacts() {
  if (artifactsCache) return artifactsCache;
  const wasm = await readFile(new URL("./circuits/vfy-policy.wasm", import.meta.url));
  const zkey = await readFile(new URL("./circuits/vfy-policy_final.zkey", import.meta.url));
  artifactsCache = { wasm, zkey };
  return artifactsCache;
}

const app = createApp({ loadArtifacts });
const port = Number(process.env.PORT || 8787);
serve({ fetch: app.fetch, port }, (info) => {
  console.log(`agent-games-steal-vfy listening on http://localhost:${info.port}/agent`);
});
