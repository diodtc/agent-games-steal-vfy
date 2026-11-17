// Test suite for the Steal the VFY agent.
// Usage: npm test
// Covers: strategy matrix (threshold policy + boundaries + malformed input),
// HMAC sign/verify, local Groth16 proving (correct move proves / wrong move
// does not prove / wrong commitment does not prove / signal layout),
// publicInputsHash (keccak256 of the 8 ABI-packed fields), and the HTTP
// endpoint end-to-end (preflight, auth failures, turn EXTRACT with proof,
// idempotency, action.amount omission, health endpoints).
// Kurier is NOT exercised here (no API key) — the HTTP tests assert the
// response is still complete (proof present, proofReference absent) without it.

import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import * as snarkjs from "snarkjs";
import { setRuntimeEnv, getConfig, DEFAULT_PARAMS, DEFAULT_SALT, DEFAULT_COMMITMENT } from "../src/config.mjs";
import { signBody, verifySignature } from "../src/hmac.mjs";
import { decideMove, matchIdToBigInt, ACTION_CODE } from "../src/strategy.mjs";
import { generateProof, buildCircuitInput } from "../src/prover.mjs";
import { computePublicInputsHash } from "../src/app.mjs";
import { VERIFICATION_KEY } from "../src/vk.mjs";
import { createApp } from "../src/app.mjs";
import { createStore } from "../src/store.mjs";

const TEST_SECRET = "test-secret-32-bytes-placeholder-0123456789";
const MATCH_ID = "9f4e1b2a-1111-2222-3333-444455556666";
let passed = 0;
function ok(name, cond) {
  assert.ok(cond, name);
  passed++;
  console.log(`  ok ${name}`);
}

let artifactsCache = null;
async function loadArtifacts() {
  if (artifactsCache) return artifactsCache;
  const wasm = await readFile(new URL("../circuits/vfy-policy.wasm", import.meta.url));
  const zkey = await readFile(new URL("../circuits/vfy-policy_final.zkey", import.meta.url));
  artifactsCache = { wasm, zkey };
  return artifactsCache;
}

function baseEnvelope(over = {}) {
  return {
    protocolVersion: "v1",
    eventId: "steal-the-vfy",
    mode: "competition",
    matchId: MATCH_ID,
    turn: 3,
    issuedAt: "2026-11-16T15:00:00.000Z",
    deadlineAt: "2026-11-16T15:05:00.000Z",
    state: { selfBalance: "95", opponentBalance: "105", selfFortifiedUntilTurn: null, opponentFortifiedUntilTurn: null },
    strategyCommitment: { hash: "0x13883b9bad37ec6a8fddcf6f69aba282993285b94a50f987749bca6e9f18aa0e" },
    resolverVersion: "v1",
    nonce: "3c2f1a",
    ...over,
  };
}

// ------------------------------------------------------------------ strategy
console.log("\n[1] strategy (decideMove)");
{
  const def = DEFAULT_PARAMS;
  let m = decideMove({ selfBalance: "100", opponentBalance: "100" }, def);
  ok("default params, 100/100 → EXTRACT 10", m.type === "EXTRACT" && m.amountNum === 10 && m.actionCode === 2);
  m = decideMove({ selfBalance: "1", opponentBalance: "100" }, def);
  ok("default params, self=1 → still EXTRACT 10 (threshold 0 never triggers)", m.type === "EXTRACT" && m.amountNum === 10);
  m = decideMove({ selfBalance: "100", opponentBalance: "0" }, def);
  ok("default params, opp=0 → still EXTRACT 10", m.type === "EXTRACT" && m.amountNum === 10);
  m = decideMove({ selfBalance: "0", opponentBalance: "0" }, def);
  ok("default params, 0/0 → EXTRACT 10", m.type === "EXTRACT" && m.amountNum === 10);

  const ref = ["8", "18", "8", "0", "0", "0", "0", "0"];
  m = decideMove({ selfBalance: "10", opponentBalance: "100" }, ref);
  ok("ref params, self=10 < 18 → FORTIFY", m.type === "FORTIFY" && m.amountNum === 0 && m.actionCode === 1);
  m = decideMove({ selfBalance: "18", opponentBalance: "100" }, ref);
  ok("ref params, self=18 == threshold → not fortify, EXTRACT 8 (boundary)", m.type === "EXTRACT" && m.amountNum === 8);
  m = decideMove({ selfBalance: "50", opponentBalance: "5" }, ref);
  ok("ref params, opp=5 < 8 → HOLD", m.type === "HOLD" && m.amountNum === 0 && m.actionCode === 0);
  m = decideMove({ selfBalance: "50", opponentBalance: "8" }, ref);
  ok("ref params, opp=8 == threshold → not hold, EXTRACT 8 (boundary)", m.type === "EXTRACT" && m.amountNum === 8);
  m = decideMove({ selfBalance: "50", opponentBalance: "100" }, ref);
  ok("ref params, 50/100 → EXTRACT 8", m.type === "EXTRACT" && m.amountNum === 8);

  assert.throws(() => decideMove(null, def), /missing game state/);
  ok("null state throws", true);
  assert.throws(() => decideMove({ selfBalance: "50", opponentBalance: "100" }, ["0", "0", "0", "0", "0", "0", "0", "0"]), /invalid extract amount/);
  ok("extract amount 0 throws", true);
  assert.throws(() => decideMove({ selfBalance: "50", opponentBalance: "100" }, ["11", "0", "0", "0", "0", "0", "0", "0"]), /invalid extract amount/);
  ok("extract amount 11 throws", true);

  ok("matchIdToBigInt strips dashes", matchIdToBigInt(MATCH_ID) === BigInt("0x9f4e1b2a111122223333444455556666"));
  assert.throws(() => matchIdToBigInt("not-a-uuid!!"), /invalid matchId/);
  ok("matchIdToBigInt rejects garbage", true);
}

// --------------------------------------------------------------------- hmac
console.log("\n[2] hmac");
{
  const body = new TextEncoder().encode('{"type":"agent-games.preflight.v1"}');
  const sig = await signBody(TEST_SECRET, "utf8", body);
  ok("sign produces 64-char lowercase hex", /^[0-9a-f]{64}$/.test(sig));
  ok("verify accepts own signature", await verifySignature(TEST_SECRET, "utf8", sig, body));
  ok("verify accepts sha256= prefix", await verifySignature(TEST_SECRET, "utf8", "sha256=" + sig, body));
  const b64 = Buffer.from(sig, "hex").toString("base64");
  ok("verify accepts base64", await verifySignature(TEST_SECRET, "utf8", b64, body));
  ok("verify rejects tampered body", !(await verifySignature(TEST_SECRET, "utf8", sig, new TextEncoder().encode('{"type":"x"}'))));
  ok("verify rejects wrong secret", !(await verifySignature("wrong-secret", "utf8", sig, body)));
}

// ------------------------------------------------------------------- prover
console.log("\n[3] prover (local Groth16)");
{
  setRuntimeEnv({});
  const cfg = getConfig();
  ok("default config params are 10,0,0,...", cfg.strategyParams.join(",") === "10,0,0,0,0,0,0,0");
  ok("default config salt matches", cfg.strategySalt === DEFAULT_SALT);
  ok("default config commitment matches", cfg.strategyCommitment === DEFAULT_COMMITMENT);

  const env = baseEnvelope();
  const move = decideMove(env.state, cfg.strategyParams);
  const t0 = Date.now();
  const p1 = await generateProof(env, move, cfg, loadArtifacts);
  console.log(`  (first prove took ${Date.now() - t0}ms)`);
  ok("correct EXTRACT 10 proves", p1 !== null);
  ok("proof verifies locally", await snarkjs.groth16.verify(VERIFICATION_KEY, p1.publicSignals, p1.proof));
  ok("public signals: 9 elements", p1.publicSignals.length === 9);
  ok("commitment signal [1] == configured commitment", p1.publicSignals[1] === DEFAULT_COMMITMENT);
  ok("turn signal [3] == 3", p1.publicSignals[3] === "3");
  ok("selfBalance signal [4] == 95", p1.publicSignals[4] === "95");
  ok("opponentBalance signal [5] == 105", p1.publicSignals[5] === "105");
  ok("action signal [6] == 2 (EXTRACT)", p1.publicSignals[6] === "2");
  ok("amount signal [7] == 10", p1.publicSignals[7] === "10");
  ok("circuitVersion signal [8] == 1", p1.publicSignals[8] === "1");

  // A wrong move must NOT prove (circuit enforces the strategy).
  const badMove = { type: "HOLD", amountNum: 0, actionCode: 0 };
  const bad = await generateProof(env, badMove, cfg, loadArtifacts);
  ok("wrong HOLD of an EXTRACT turn does NOT prove (proof null)", bad === null);

  const badAmt = { type: "EXTRACT", amountNum: 5, actionCode: 2 };
  const bad2 = await generateProof(env, badAmt, cfg, loadArtifacts);
  ok("wrong EXTRACT amount (5 vs 10) does NOT prove", bad2 === null);

  // Wrong commitment must NOT prove.
  const envBadCommit = baseEnvelope({ strategyCommitment: { hash: "0x0000000000000000000000000000000000000000000000000000000000001234" } });
  const bad3 = await generateProof(envBadCommit, move, cfg, loadArtifacts);
  ok("wrong frozen commitment does NOT prove", bad3 === null);

  // No frozen commitment in envelope → falls back to configured one.
  const envNoCommit = baseEnvelope();
  delete envNoCommit.strategyCommitment;
  const p2 = await generateProof(envNoCommit, move, cfg, loadArtifacts);
  ok("no frozen commitment → configured commitment proves", p2 !== null);
  ok("fallback proof verifies locally", await snarkjs.groth16.verify(VERIFICATION_KEY, p2.publicSignals, p2.proof));
}

// ------------------------------------------------------- publicInputsHash
console.log("\n[4] publicInputsHash");
{
  setRuntimeEnv({});
  const cfg = getConfig();
  const env = baseEnvelope();
  const move = decideMove(env.state, cfg.strategyParams);
  const hash = computePublicInputsHash(env, move, DEFAULT_COMMITMENT);
  ok("hash is 0x + 64 hex chars", /^0x[0-9a-f]{64}$/.test(hash));
  // Cross-check against viem's keccak256(concat(numberToHex(...))) — the
  // exact snippet from the /build page.
  const { concat, keccak256, numberToHex } = await import("viem");
  const expected = keccak256(concat([
    numberToHex(BigInt(DEFAULT_COMMITMENT), { size: 32 }),
    numberToHex(BigInt("0x" + MATCH_ID.replace(/-/g, "")), { size: 32 }),
    numberToHex(3n, { size: 32 }),
    numberToHex(95n, { size: 32 }),
    numberToHex(105n, { size: 32 }),
    numberToHex(2n, { size: 32 }),
    numberToHex(10n, { size: 32 }),
    numberToHex(1n, { size: 32 }),
  ]));
  ok("hash matches the /build page viem snippet", hash === expected);
  const hash2 = computePublicInputsHash(env, { type: "HOLD", amountNum: 0, actionCode: 0 }, DEFAULT_COMMITMENT);
  ok("different action → different hash", hash2 !== hash);
}

// ---------------------------------------------------------------------- http
console.log("\n[5] http endpoint (Hono app.request, dummy secret, no Kurier key)");
{
  setRuntimeEnv({ AGENT_GAMES_HMAC_SECRET: TEST_SECRET });
  const store = createStore();
  const app = createApp({ loadArtifacts, store });

  async function post(obj, { sign = true, secret = TEST_SECRET } = {}) {
    const raw = JSON.stringify(obj);
    const headers = { "content-type": "application/json" };
    if (sign) headers["x-agent-games-signature"] = await signBody(secret, "utf8", new TextEncoder().encode(raw));
    return app.request("http://localhost/agent", { method: "POST", headers, body: raw });
  }

  // preflight
  let res = await post({ type: "agent-games.preflight.v1", agent_id: "agt_test", issued_at: new Date().toISOString(), nonce: "abc123" });
  ok("preflight → 200", res.status === 200);
  let json = await res.json();
  ok("preflight body {ok:true, protocolVersion:v1}", json.ok === true && json.protocolVersion === "v1");
  ok("preflight response is HMAC-signed", typeof res.headers.get("x-agent-games-signature") === "string" && res.headers.get("x-agent-games-signature").length === 64);

  // unsigned / wrong signature
  res = await post({ type: "agent-games.preflight.v1" }, { sign: false });
  ok("unsigned request → 401", res.status === 401);
  res = await post({ type: "agent-games.preflight.v1" }, { secret: "wrong-secret" });
  ok("wrong-signature request → 401", res.status === 401);

  // unknown type
  res = await post({ type: "agent-games.unknown.v1" });
  ok("unknown type → 400", res.status === 400);

  // valid turn → EXTRACT 10 with a real proof
  res = await post(baseEnvelope());
  ok("valid turn → 200", res.status === 200);
  json = await res.json();
  ok("turn echoes matchId", json.matchId === MATCH_ID);
  ok("turn echoes turn", json.turn === 3);
  ok("turn action is EXTRACT 10", json.action?.type === "EXTRACT" && json.action?.amount === 10);
  ok("policyProof.circuitVersion is v1", json.policyProof?.circuitVersion === "v1");
  ok("policyProof.proof present", json.policyProof?.proof && typeof json.policyProof.proof === "object");
  ok("policyProof.public_signals present (9)", Array.isArray(json.policyProof?.public_signals) && json.policyProof.public_signals.length === 9);
  ok("returned proof verifies locally", await snarkjs.groth16.verify(VERIFICATION_KEY, json.policyProof.public_signals, json.policyProof.proof));
  ok("policyProof.publicInputsHash present (0x+64hex)", /^0x[0-9a-f]{64}$/.test(json.policyProof?.publicInputsHash ?? ""));
  ok("idempotencyKey present", typeof json.idempotencyKey === "string" && json.idempotencyKey.length > 0);
  ok("agentTimestamp present", typeof json.agentTimestamp === "string");
  ok("no proofReference without Kurier key", !("proofReference" in (json.policyProof ?? {})));

  // idempotency: same match+turn returns the cached response verbatim
  res = await post(baseEnvelope());
  const json2 = await res.json();
  ok("re-delivery → identical cached response", JSON.stringify(json2) === JSON.stringify(json));

  // a different turn is a new decision (not the cached one)
  res = await post(baseEnvelope({ turn: 4 }));
  const json3 = await res.json();
  ok("different turn → new response with turn 4", json3.turn === 4 && JSON.stringify(json3) !== JSON.stringify(json));

  // missing matchId → 400
  const badEnv = baseEnvelope();
  delete badEnv.matchId;
  res = await post(badEnv);
  ok("missing matchId → 400", res.status === 400);

  // health endpoints
  res = await app.request("http://localhost/health");
  ok("GET /health → 200", res.status === 200);
  const h = await res.json();
  ok("health body names the service", h.service === "agent-games-steal-vfy" && h.ok === true);
  res = await app.request("http://localhost/agent");
  ok("GET /agent → 200 (health)", res.status === 200);
}

console.log(`\n${passed} assertions passed.`);
// NOTE: snarkjs 0.7.5's fullProve leaves a live handle (worker thread) that
// keeps the Node event loop open, so a passing run would otherwise hang.
// The server (index.mjs) is long-lived by design; only the test harness
// needs an explicit exit.
process.exit(0);
