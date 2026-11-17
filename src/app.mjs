// Hono app: Steal the VFY agent for zkVerify Agent Games.
//
// Routes:
//   GET  /            health / service info (unsigned)
//   GET  /health      health (unsigned)
//   GET  /agent       health (unsigned; the dashboard health check hits the
//                    registered URL — the handler itself is POST-only)
//   POST /agent       the agent endpoint: preflight + steal-the-vfy turns
//
// POST /agent protocol (verified against live /build, 2026-11-16):
//   - Request must carry `x-agent-games-signature`: HMAC-SHA-256 over the
//     RAW request body, keyed by the platform-issued secret.
//   - Response is signed the same way over the RAW response body.
//   - Preflight: {"type":"agent-games.preflight.v1",...}
//     → {"ok":true,"protocolVersion":"v1"}.
//   - Turn: {"protocolVersion":"v1","eventId":"steal-the-vfy",
//     "matchId","turn","state":{selfBalance,opponentBalance,...},
//     "strategyCommitment":{hash},...}
//     → {"matchId","turn","action","policyProof","agentTimestamp",
//     "idempotencyKey"}. The action carries `amount` ONLY for EXTRACT
//     (HOLD/FORTIFY must omit it entirely). policyProof carries
//     circuitVersion "v1" plus the Groth16 proof and public_signals INSIDE
//     policyProof (top-level proof is ignored by the platform), plus the
//     optional publicInputsHash audit pointer.
//   - Turn IDs are idempotency keys: a re-delivery of the same matchId+turn
//     returns the cached response verbatim, never re-decides or re-proves.

import { Hono } from "hono";
import { getConfig } from "./config.mjs";
import { signBody, verifySignature } from "./hmac.mjs";
import { decideMove, matchIdToBigInt, ACTION_CODE } from "./strategy.mjs";
import { generateProof } from "./prover.mjs";
import { submitProofToKurier } from "./kurier.mjs";
import { createStore } from "./store.mjs";
import sha3 from "js-sha3";
// js-sha3 ships CJS/UMD only; the ESM default import is the module object.
const { keccak256 } = sha3;

const te = new TextEncoder();
const td = new TextDecoder();
const FIELD_PRIME = BigInt(
  "21888242871839275222246405745257275088548364400416034343698204186575808495617"
);

function to32BytesBE(n) {
  const v = BigInt(n) % FIELD_PRIME;
  const out = new Uint8Array(32);
  let x = v;
  for (let i = 31; i >= 0; i--) {
    out[i] = Number(x & 0xffn);
    x >>= 8n;
  }
  return out;
}

// publicInputsHash: keccak256 of ABI-packed fields, each 32 bytes
// big-endian (per the /build page's TypeScript snippet).
//   commitment, matchId, turn, selfBalance, opponentBalance,
//   action (HOLD 0 / FORTIFY 1 / EXTRACT 2), amount, circuitVersion (1)
export function computePublicInputsHash(envelope, move, commitmentDecimal) {
  const state = envelope.state || {};
  const parts = [
    to32BytesBE(commitmentDecimal),
    to32BytesBE(matchIdToBigInt(envelope.matchId)),
    to32BytesBE(envelope.turn),
    to32BytesBE(state.selfBalance),
    to32BytesBE(state.opponentBalance),
    to32BytesBE(move.actionCode),
    to32BytesBE(move.amountNum),
    to32BytesBE(1n),
  ];
  const packed = new Uint8Array(32 * parts.length);
  parts.forEach((p, i) => packed.set(p, i * 32));
  return "0x" + keccak256(packed);
}

export function createApp({ loadArtifacts, store = createStore() }) {
  const app = new Hono();

  const health = {
    ok: true,
    service: "agent-games-steal-vfy",
    version: "1.0.0",
    protocol: "agent-games v1",
    event: "steal-the-vfy",
    endpoints: { agent: "POST /agent" },
  };

  app.get("/", (c) => c.json(health));
  app.get("/health", (c) => c.json(health));
  app.get("/agent", (c) => c.json(health));

  // Sign a JSON body and return it as a signed response.
  async function respondSigned(c, obj, status = 200) {
    const cfg = getConfig();
    const body = JSON.stringify(obj);
    const headers = { "content-type": "application/json" };
    if (cfg.hmacSecret) {
      headers["x-agent-games-signature"] = await signBody(
        cfg.hmacSecret,
        cfg.hmacKeyEncoding,
        te.encode(body)
      );
    }
    return c.text(body, status, headers);
  }

  app.post("/agent", async (c) => {
    const cfg = getConfig();
    const raw = new Uint8Array(await c.req.arrayBuffer());

    if (!cfg.hmacSecret) {
      console.error("[agent] HMAC secret not configured — refusing request");
      return respondSigned(c, { error: "hmac secret not configured" }, 500);
    }

    const signature = c.req.header("x-agent-games-signature");
    const valid = await verifySignature(
      cfg.hmacSecret,
      cfg.hmacKeyEncoding,
      signature,
      raw
    );
    if (!valid) {
      return respondSigned(c, { error: "invalid signature" }, 401);
    }

    let body;
    try {
      body = JSON.parse(td.decode(raw));
    } catch {
      return respondSigned(c, { error: "invalid JSON" }, 400);
    }
    if (!body || typeof body !== "object") {
      return respondSigned(c, { error: "request body must be a JSON object" }, 400);
    }

    // ---- Preflight ------------------------------------------------------
    if (body.type === "agent-games.preflight.v1") {
      console.log("[agent] preflight ok");
      return respondSigned(c, { ok: true, protocolVersion: "v1" });
    }

    // ---- Steal the VFY turn ---------------------------------------------
    if (body.eventId === "steal-the-vfy") {
      const matchId = body.matchId;
      const turn = body.turn;
      if (typeof matchId !== "string" || matchId === "") {
        return respondSigned(c, { error: "missing matchId" }, 400);
      }
      if (typeof turn !== "number" && typeof turn !== "string") {
        return respondSigned(c, { error: "missing turn" }, 400);
      }

      // Idempotency: re-delivery of the same match+turn returns the cached
      // response verbatim, never re-decides or re-proves.
      const cacheKey = `vfy:${matchId}:${turn}`;
      const cached = store.getResponse(cacheKey);
      if (cached) {
        console.log(`[agent] turn ${matchId}#${turn} replayed from cache`);
        return respondSigned(c, cached);
      }

      const practice =
        body.mode === "practice" || body.environment === "practice";

      // Decide the move from the committed threshold strategy.
      let move;
      try {
        move = decideMove(body.state || {}, cfg.strategyParams);
      } catch (err) {
        console.warn(`[agent] decideMove failed: ${err.message}`);
        // Fail closed: HOLD with no proof is scored as HOLD (no -2 for a
        // missing proof is worse than a wrong move, but a wrong move cannot
        // prove; HOLD at least keeps the turn answered).
        move = { type: "HOLD", amountNum: 0, actionCode: ACTION_CODE.HOLD };
      }

      // Prove the move follows the committed strategy.
      const proofResult = await generateProof(body, move, cfg, loadArtifacts);

      // Kurier is best-effort: proofReference only when it finalizes.
      let proofReference = null;
      if (proofResult && cfg.kurierApiKey) {
        const k = await submitProofToKurier({
          apiKey: cfg.kurierApiKey,
          proof: proofResult.proof,
          publicSignals: proofResult.publicSignals,
          timeoutMs: cfg.kurierTimeoutMs,
        });
        if (k.ok && k.txHash) {
          proofReference = k.txHash;
        } else {
          console.warn(`[agent] kurier skipped/failed: ${k.error}`);
        }
      }

      // Commitment decimal for the audit hash (frozen hash wins when present).
      let commitmentDecimal = cfg.strategyCommitment;
      const frozen = body.strategyCommitment?.hash;
      if (typeof frozen === "string" && frozen !== "") {
        commitmentDecimal = BigInt(frozen).toString();
      }
      const publicInputsHash = computePublicInputsHash(body, move, commitmentDecimal);

      // action.amount is included ONLY for EXTRACT; HOLD/FORTIFY omit it.
      const action =
        move.type === "EXTRACT"
          ? { type: "EXTRACT", amount: move.amountNum }
          : { type: move.type };

      const response = {
        matchId,
        turn,
        action,
        policyProof: {
          circuitVersion: "v1",
          proof: proofResult ? proofResult.proof : null,
          public_signals: proofResult ? proofResult.publicSignals : null,
          publicInputsHash,
        },
        agentTimestamp: new Date().toISOString(),
        idempotencyKey: crypto.randomUUID(),
      };
      if (proofReference) response.policyProof.proofReference = proofReference;

      store.setResponse(cacheKey, response);
      console.log(
        `[agent] turn ${matchId}#${turn} ${practice ? "[practice] " : ""}` +
          `${move.type}${move.type === "EXTRACT" ? " " + move.amountNum : ""} ` +
          `proof=${proofResult ? "yes" : "no"}`
      );
      return respondSigned(c, response);
    }

    return respondSigned(c, { error: `unknown request type: ${body.type ?? body.eventId ?? null}` }, 400);
  });

  return app;
}
