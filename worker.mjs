// Cloudflare Workers entry point.
// The vfy-policy circuit artifacts (~3.0 MB wasm + ~810 KB zkey) are NOT
// bundled — they are fetched at runtime from the official Agent Games site
// on first use and cached in the isolate. Secrets come from Worker secrets
// (AGENT_GAMES_HMAC_SECRET, KURIER_API_KEY, STEAL_VFY_SALT,
// STEAL_VFY_COMMITMENT), never from the bundle.

import { setRuntimeEnv } from "./src/config.mjs";
import { createApp } from "./src/app.mjs";

const CIRCUIT_URLS = {
  wasm: "https://agentgames.zkverify.io/circuits/vfy-policy.wasm",
  zkey: "https://agentgames.zkverify.io/circuits/vfy-policy_final.zkey",
};

let artifactsCache = null;
async function loadArtifacts() {
  if (artifactsCache) return artifactsCache;
  const [wasmRes, zkeyRes] = await Promise.all([
    fetch(CIRCUIT_URLS.wasm),
    fetch(CIRCUIT_URLS.zkey),
  ]);
  if (!wasmRes.ok) throw new Error(`wasm fetch failed: HTTP ${wasmRes.status}`);
  if (!zkeyRes.ok) throw new Error(`zkey fetch failed: HTTP ${zkeyRes.status}`);
  artifactsCache = {
    wasm: await wasmRes.arrayBuffer(),
    zkey: await zkeyRes.arrayBuffer(),
  };
  return artifactsCache;
}

const app = createApp({ loadArtifacts });

export default {
  async fetch(request, env, ctx) {
    setRuntimeEnv(env);
    return app.fetch(request, env, ctx);
  },
};
