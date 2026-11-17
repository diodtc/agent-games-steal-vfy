// One-off live check against a running server (index.mjs) or the deployed Worker.
// Usage: AGENT_GAMES_HMAC_SECRET=<secret> node test/live-check.mjs [baseUrl]
import { signBody } from "../src/hmac.mjs";
import * as snarkjs from "snarkjs";
import { VERIFICATION_KEY } from "../src/vk.mjs";

const BASE = process.argv[2] || "http://localhost:8787";
const SECRET = process.env.AGENT_GAMES_HMAC_SECRET;
if (!SECRET) throw new Error("set AGENT_GAMES_HMAC_SECRET");

async function signedPost(path, obj) {
  const raw = JSON.stringify(obj);
  const sig = await signBody(SECRET, "utf8", new TextEncoder().encode(raw));
  const res = await fetch(`${BASE}${path}`, {
    method: "POST",
    headers: { "content-type": "application/json", "x-agent-games-signature": sig },
    body: raw,
  });
  return { status: res.status, sig: res.headers.get("x-agent-games-signature"), json: await res.json() };
}

const health = await fetch(`${BASE}/health`);
console.log("GET /health:", health.status, JSON.stringify(await health.json()));

const pf = await signedPost("/agent", { type: "agent-games.preflight.v1", agent_id: "agt_live", issued_at: new Date().toISOString(), nonce: "live123" });
console.log("POST preflight:", pf.status, JSON.stringify(pf.json), "signed:", !!pf.sig);

const matchId = `9f4e1b2a-live-${Date.now().toString(16).padStart(12, "0")}`.slice(0, 36);
// A real UUID shape: 8-4-4-4-12 hex
const uuid = "9f4e1b2a-" + Date.now().toString(16).padStart(4, "0").slice(-4) + "-4000-8000-" + "aaaaaaaaaaaa";
const turn = {
  protocolVersion: "v1",
  eventId: "steal-the-vfy",
  mode: "practice",
  matchId: uuid,
  turn: 1,
  issuedAt: new Date().toISOString(),
  deadlineAt: new Date(Date.now() + 300000).toISOString(),
  state: { selfBalance: "100", opponentBalance: "100", selfFortifiedUntilTurn: null, opponentFortifiedUntilTurn: null },
  strategyCommitment: { hash: "0x13883b9bad37ec6a8fddcf6f69aba282993285b94a50f987749bca6e9f18aa0e" },
  resolverVersion: "v1",
  nonce: "live-nonce-1",
};
const t0 = Date.now();
const r = await signedPost("/agent", turn);
console.log(`POST turn (${Date.now() - t0}ms):`, r.status, "action:", JSON.stringify(r.json.action), "proof:", r.json.policyProof?.proof ? "yes" : "no", "signals:", r.json.policyProof?.public_signals?.length, "signed:", !!r.sig);
if (r.json.policyProof?.proof) {
  const ok = await snarkjs.groth16.verify(VERIFICATION_KEY, r.json.policyProof.public_signals, r.json.policyProof.proof);
  console.log("returned proof verifies locally:", ok);
}
process.exit(0);
