// Runtime environment holder.
//
// The Hono app must run unchanged on Node (index.mjs, reads process.env) and
// on Cloudflare Workers (worker.mjs, reads the env binding). Neither entry
// point may import Node-only modules, so the app reads its config from this
// mutable holder, populated once at startup by the entry point.
//
// Secrets are NEVER hardcoded here. The HMAC secret comes from the Agent
// Games dashboard ("Rotate Secret"), the Kurier key from kurier.xyz, and the
// strategy salt from the operator (it blinds the committed strategy).

let runtimeEnv = {};

export function setRuntimeEnv(env) {
  runtimeEnv = { ...(env || {}) };
}

// Default strategy: always EXTRACT 10 (the maximum). EXTRACT is strictly
// dominant in the payoff matrix: vs HOLD it gains +20 relative, vs FORTIFY
// +10, vs EXTRACT 0 — never negative. FORTIFY and HOLD only lose value.
// The 8 strategyParams encode the circuit's threshold policy:
//   selfBalance < params[1] => FORTIFY
//   opponentBalance < params[2] => HOLD
//   otherwise => EXTRACT params[0]
// With params [10,0,0,0,0,0,0,0] the thresholds never trigger, so every
// turn is EXTRACT 10. The commitment below is the Poseidon hash of
// [...params, salt] for the default salt; keep params/salt/commitment in
// sync (recompute with `npm run commitment` after any change).
export const DEFAULT_PARAMS = ["10", "0", "0", "0", "0", "0", "0", "0"];
export const DEFAULT_SALT = "322748575781115448660733098535191849917";
export const DEFAULT_COMMITMENT =
  "8834646723960147752131498285094526492578241027194476319113712693899723057678";

export function getConfig() {
  const secret =
    runtimeEnv.AGENT_GAMES_HMAC_SECRET ||
    runtimeEnv.STEAL_VFY_HMAC_SECRET ||
    "";
  const rawParams = runtimeEnv.STEAL_VFY_PARAMS || DEFAULT_PARAMS.join(",");
  const params = rawParams.split(",").map((x) => x.trim());
  return {
    // 32-byte HMAC secret issued by the platform (shown once via Rotate Secret).
    hmacSecret: secret,
    // How the HMAC key is derived from the secret string. Default "utf8".
    hmacKeyEncoding: (runtimeEnv.HMAC_KEY_ENCODING || "utf8").toLowerCase(),
    // Kurier mainnet API key (https://kurier.xyz). Optional.
    kurierApiKey: runtimeEnv.KURIER_API_KEY || "",
    // Max ms spent on a Kurier submit+poll per task (default 20000).
    kurierTimeoutMs: Number(runtimeEnv.KURIER_TIMEOUT_MS || 20000),
    // Registered vfy-policy verification-key hash (zkVerify mainnet).
    vkHash:
      runtimeEnv.STEAL_VFY_VK_HASH ||
      "0x6c56509f1c56fd1fd4e9737f906d2220f4b95f1d507f1adf6899085bd74be047",
    // Strategy: 8 threshold params (see DEFAULT_PARAMS) + blinding salt.
    strategyParams: params,
    strategySalt: runtimeEnv.STEAL_VFY_SALT || DEFAULT_SALT,
    // Poseidon commitment hash (decimal) of [...params, salt].
    strategyCommitment:
      runtimeEnv.STEAL_VFY_COMMITMENT || DEFAULT_COMMITMENT,
  };
}
