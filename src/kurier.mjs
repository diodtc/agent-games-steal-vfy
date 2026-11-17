// Kurier client (zkVerify proof submission via REST).
//
// Docs: https://docs.zkverify.io/overview/getting-started/kurier and
// https://docs.zkverify.io/handbook/quickstart (both re-read 2026-11-15).
// API: https://api.kurier.xyz/api/v1 — API key required (from
// https://kurier.xyz, mainnet; testnet at https://api-testnet.kurier.xyz).
//
//   POST /register-vk/{API_KEY}
//     { proofType: "groth16",
//       proofOptions: { library: "snarkjs", curve: "bn128" },
//       vk: <verification key JSON object> }
//     → { vkHash, ... }  (register once; result cached in-process)
//
//   POST /submit-proof/{API_KEY}
//     { proofType: "groth16", vkRegistered: true,
//       proofOptions: { library: "snarkjs", curve: "bn128" },
//       proofData: { proof, publicSignals, vk: <vkHash> } }
//     → { jobId, optimisticVerify: "success" | ... }
//     (no chainId → no aggregation; proof is verified on zkVerify only)
//
//   GET /job-status/{API_KEY}/{jobId}
//     → { jobId, status, txHash, blockHash, ... }
//     statuses: Queued → Valid → Submitted → IncludedInBlock → Finalized
//     (or Failed).
//
// BEST-EFFORT ONLY: Kurier is an optional on-chain audit pointer. The
// response's local Groth16 proof (proof + public_signals) is primary, and
// proof_tx is attached ONLY when Kurier finalizes inside the timeout
// budget (default 20s). A Kurier failure never blocks or changes the task
// answer, and never breaches the 60s deadline.

import { VERIFICATION_KEY, VK_HASH } from "./vk.mjs";

const KURIER_BASE = "https://api.kurier.xyz/api/v1";

let vkRegistered = false;

async function postJson(url, body, timeoutMs) {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    const res = await fetch(url, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(body),
      signal: ctrl.signal,
    });
    const text = await res.text();
    let json = null;
    try {
      json = JSON.parse(text);
    } catch {
      /* non-JSON error body */
    }
    return { status: res.status, ok: res.ok, json, text };
  } finally {
    clearTimeout(timer);
  }
}

async function getJson(url, timeoutMs) {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    const res = await fetch(url, { signal: ctrl.signal });
    const text = await res.text();
    let json = null;
    try {
      json = JSON.parse(text);
    } catch {
      /* non-JSON error body */
    }
    return { status: res.status, ok: res.ok, json, text };
  } finally {
    clearTimeout(timer);
  }
}

export async function registerVk(apiKey) {
  if (vkRegistered) return { ok: true, cached: true };
  const res = await postJson(`${KURIER_BASE}/register-vk/${apiKey}`, {
    proofType: "groth16",
    proofOptions: { library: "snarkjs", curve: "bn128" },
    vk: VERIFICATION_KEY,
  }, 15000);
  if (!res.ok) {
    return { ok: false, status: res.status, body: res.json ?? res.text };
  }
  const returnedHash = res.json?.vkHash || res.json?.meta?.vkHash;
  if (returnedHash && returnedHash.toLowerCase() !== VK_HASH.toLowerCase()) {
    return { ok: false, error: `vkHash mismatch: Kurier returned ${returnedHash}` };
  }
  vkRegistered = true;
  return { ok: true, vkHash: returnedHash || VK_HASH };
}

// Submit one proof to Kurier and poll until Finalized (or timeout).
// Returns { ok: true, jobId, txHash, status } on success, or
// { ok: false, error } on any failure. Never throws.
export async function submitProofToKurier({ apiKey, proof, publicSignals, timeoutMs = 20000 }) {
  const started = Date.now();
  const remaining = () => timeoutMs - (Date.now() - started);
  try {
    if (!apiKey) return { ok: false, error: "no KURIER_API_KEY configured" };

    const reg = await registerVk(apiKey);
    if (!reg.ok) {
      return { ok: false, error: `register-vk failed: ${JSON.stringify(reg.body ?? reg.error)}` };
    }

    const submit = await postJson(`${KURIER_BASE}/submit-proof/${apiKey}`, {
      proofType: "groth16",
      vkRegistered: true,
      proofOptions: { library: "snarkjs", curve: "bn128" },
      proofData: { proof, publicSignals, vk: VK_HASH },
    }, Math.max(5000, remaining()));
    if (!submit.ok) {
      return { ok: false, error: `submit-proof HTTP ${submit.status}: ${JSON.stringify(submit.json ?? submit.text)}` };
    }
    const jobId = submit.json?.jobId;
    if (!jobId) return { ok: false, error: `submit-proof returned no jobId: ${JSON.stringify(submit.json)}` };
    if (submit.json?.optimisticVerify && submit.json.optimisticVerify !== "success") {
      return { ok: false, error: `optimisticVerify = ${submit.json.optimisticVerify}` };
    }

    // Poll job-status every 5s until Finalized or the budget runs out.
    while (remaining() > 0) {
      await new Promise((r) => setTimeout(r, 5000));
      if (remaining() <= 0) break;
      const st = await getJson(`${KURIER_BASE}/job-status/${apiKey}/${jobId}`, Math.max(5000, remaining()));
      if (!st.ok) continue;
      const status = st.json?.status;
      if (status === "Finalized") {
        return { ok: true, jobId, txHash: st.json?.txHash || null, status };
      }
      if (status === "Failed") {
        return { ok: false, error: `job ${jobId} Failed: ${JSON.stringify(st.json)}` };
      }
      // Queued / Valid / Submitted / IncludedInBlock → keep polling.
    }
    return { ok: false, error: `timeout after ${timeoutMs}ms waiting for Finalized (jobId ${jobId})` };
  } catch (err) {
    return { ok: false, error: err.message };
  }
}
