# Steal the VFY agent — zkVerify Agent Games

HMAC-signed Hono endpoint that plays 20-turn **Steal the VFY** matches with
a Poseidon-committed threshold strategy and proves every move with a local
Groth16 proof (the official vfy-policy circuit), with an optional on-chain
audit pointer via Kurier.

- **Live endpoint:** `https://agent-games-steal-vfy.dtccrypto.workers.dev/agent`
- **Health:** `GET https://agent-games-steal-vfy.dtccrypto.workers.dev/health`
- **Owner:** @Nentoczc (GitHub diodtc) — Steal the VFY, Swiss R4–R7 + Top 16
  knockout, 13–17 Nov 2026. Entry is mid-tournament (joins from the next
  Swiss round); global registration closes 21 Nov 2026, 22:00 UTC.
- **Strategy:** always EXTRACT 10 (see "Strategy" below).
- **Commitment (hex, register in dashboard):**
  `0x13883b9bad37ec6a8fddcf6f69aba282993285b94a50f987749bca6e9f18aa0e`
- **Commitment (decimal):**
  `8834646723960147752131498285094526492578241027194476319113712693899723057678`

> **Status 2026-11-16 ~16:05 UTC:** deployed and serving GETs; signed
> preflight verified live (HTTP 200, signed). A live practice turn returns
> the correct action (EXTRACT 10) and publicInputsHash, but the Groth16
> proof is **null in the Worker** — the in-Worker prove fails (most likely
> the Workers CPU/memory limit; see "Known limits"). The proof works
> locally (65/65 tests, live Node server). **Do not enter a scored round
> until a practice turn returns a real proof from the live Worker** — the
> likely fix is upgrading the Cloudflare Workers plan to Paid ($5/mo).

## How a turn is handled

```
POST /agent  (x-agent-games-signature: HMAC-SHA-256 over raw body)
  1. verify HMAC → 401 if bad (every response is also HMAC-signed)
  2. preflight {"type":"agent-games.preflight.v1",...}
       → {"ok":true,"protocolVersion":"v1"}
  3. turn {"protocolVersion":"v1","eventId":"steal-the-vfy",
     "matchId","turn","state":{selfBalance,opponentBalance,...},
     "strategyCommitment":{hash},...}
       → decide move → Groth16 proof → optional Kurier proofReference
       → {"matchId","turn","action","policyProof","agentTimestamp",
          "idempotencyKey"}
```

**Strategy** (`src/strategy.mjs`, pure function) — the circuit enforces this
threshold policy; a move that does not follow it cannot prove:

| condition | move |
|---|---|
| `selfBalance < params[1]` | FORTIFY |
| `opponentBalance < params[2]` | HOLD |
| otherwise | EXTRACT `params[0]` |

Default params `[10,0,0,0,0,0,0,0]` mean "always EXTRACT 10": the
thresholds (0) never trigger because balances are never negative. EXTRACT
is strictly dominant in the payoff matrix — vs HOLD it gains +20 relative,
vs FORTIFY +10, vs EXTRACT 0, never negative — so always extracting the
maximum wins against any opponent that ever HOLDs or FORTIFies, and draws
against an always-extracting opponent.

**Game numbers** (official event page): HOLD free, no transfer. FORTIFY
costs 2 VFY, blocks up to 6 VFY of incoming extraction. EXTRACT N free,
steals up to N VFY (max 10) from the opponent's exposed balance; a
fortified opponent reduces the gain by 6. Both start at 100 VFY; 20 turns;
highest balance wins.

**Prover** (`src/prover.mjs`, snarkjs 0.7.5) — every move is proven with
the vfy-policy circuit. A locally generated proof is verified against the
embedded verification key before it is returned; if proving fails for any
reason the answer still goes out with `proof: null` (the move is scored,
the proof bonus is lost — never a timeout).

**Kurier** (`src/kurier.mjs`, best-effort) — with `KURIER_API_KEY` set, the
proof is submitted to `https://api.kurier.xyz/api/v1` and `proofReference`
is attached only when Kurier finalizes in budget. Without a key the agent
still answers every turn.

**Idempotency** (`src/store.mjs`, in-memory) — `vfy:${matchId}:${turn}` is
the key: a re-delivery returns the cached response verbatim, never
re-decides or re-proves. The store is per-isolate — a Worker restart or a
second isolate starts empty. For 20 turns/match this is acceptable for v1.

## Response-shape notes (verified against the live /build page)

- `action.amount` is included ONLY for EXTRACT. HOLD and FORTIFY omit it
  entirely (the schema rejects the field even when it is 0).
- `policyProof` carries `circuitVersion: "v1"` plus the Groth16 `proof`
  and `public_signals` INSIDE `policyProof` (a top-level proof is ignored
  by the platform — the #1 cause of lost turns).
- `publicInputsHash` is keccak256 of the 8 ABI-packed fields (commitment,
  matchId, turn, selfBalance, opponentBalance, action, amount,
  circuitVersion 1), each 32 bytes big-endian — verified byte-identical
  against the /build page's viem snippet in the test suite.
- `idempotencyKey` is a fresh UUID per response (re-deliveries return the
  cached response, so the key is stable per turn).

## Circuit (verified, not assumed)

- Artifacts: `circuits/vfy-policy.wasm` (2,991,212 B),
  `circuits/vfy-policy_final.zkey` (810,586 B), downloaded from the official
  site; `vk_hash 0x6c56509f1c56fd1fd4e9737f906d2220f4b95f1d507f1adf6899085bd74be047`.
- `snarkjs zkey export verificationkey` confirms Groth16, bn128, nPublic 9.
- Circuit inputs (17: 8 public + 9 private): `commitment, matchId,
  turnNumber, selfBalance, opponentBalance, action (0/1/2), amount,
  circuitVersion` (public); `salt, strategyParams[0..7]` (private).
- Public signals (9, verified empirically): `[0]` circuit output — a
  circuit-defined field element (do not assert its value; its semantics are
  unpublished); `[1]` commitment, `[2]` matchId, `[3]` turnNumber,
  `[4]` selfBalance, `[5]` opponentBalance, `[6]` action, `[7]` amount,
  `[8]` circuitVersion (1).
- Commitment: Poseidon hash of `[...strategyParams, salt]` (9 field
  elements), via circomlibjs `buildPoseidon()`. Verified: the circuit
  asserts when the commitment does not match the params+salt, when the
  move does not follow the thresholds, and when the amount is wrong.
- Encodings: commitment as decimal (Poseidon output, already < p); matchId
  as decimal of the UUID hex (dashes removed); numbers as decimals; salt as
  decimal; strategyParams as 8 decimal strings.
- Prove times (this VM): ~700–800ms per proof — well inside the 5-minute
  turn deadline (the platform waits ~30s per push).

## Tests — what was run and what passed

`npm test` — **65/65 assertions pass**:

- Strategy: default params always EXTRACT 10 (including 0/0 balances);
  reference params `[8,18,8,...]` fortify below 18, hold below 8, extract 8;
  boundaries (balance == threshold does not trigger); invalid extract
  amount (0, 11) throws; bad matchId throws.
- HMAC: sign/verify round-trip, `sha256=` prefix, base64, tampered body
  rejected, wrong secret rejected, hex key encoding.
- Prover: correct EXTRACT 10 proves and verifies locally (9 signals,
  layout verified element by element); wrong HOLD, wrong amount, and wrong
  frozen commitment all do NOT prove (proof null); no frozen commitment in
  the envelope falls back to the configured one and proves.
- publicInputsHash: matches the /build page's viem snippet byte-for-byte;
  a different action gives a different hash.
- HTTP (in-process): preflight 200 + signed, unsigned → 401, wrong
  signature → 401, unknown type → 400, valid turn → EXTRACT 10 with a proof
  that verifies locally, re-delivery → identical cached response,
  different turn → new response, missing matchId → 400, GET /health and
  GET /agent → 200.
- Live Node server (`npm start` + `test/live-check.mjs`): GET /health 200,
  POST preflight 200 signed, POST practice turn 200 in ~0.7–1.5s, EXTRACT 10,
  proof present (9 signals), response signature valid, returned proof
  verifies locally.

## Deploy

```sh
npm run build   # → dist/worker.js (349 KB; circuit artifacts NOT bundled)
python3 scripts/deploy-curl.py deploy --name agent-games-steal-vfy \
  --account-id ad9484366a20a9e7a341965f516b0f0a \
  --script-path dist/worker.js
python3 scripts/deploy-curl.py enable-subdomain --name agent-games-steal-vfy \
  --account-id ad9484366a20a9e7a341965f516b0f0a
# Secrets (Worker secrets; values are sent in the request body only):
python3 scripts/deploy-curl.py put-secret --name agent-games-steal-vfy \
  --account-id ad9484366a20a9e7a341965f516b0f0a \
  --secret-name AGENT_GAMES_HMAC_SECRET --secret-value <from dashboard>
python3 scripts/deploy-curl.py put-secret --name agent-games-steal-vfy \
  --account-id ad9484366a20a9e7a341965f516b0f0a \
  --secret-name STEAL_VFY_SALT --secret-value <salt>
python3 scripts/deploy-curl.py put-secret --name agent-games-steal-vfy \
  --account-id ad9484366a20a9e7a341965f516b0f0a \
  --secret-name STEAL_VFY_COMMITMENT --secret-value <commitment decimal>
```

Use `scripts/deploy-curl.py`, not the Python urllib helper: urllib stalls
in this VM's proxy CONNECT phase. The deploy is idempotent — re-running
overwrites the script. Secrets apply immediately; a redeploy is not needed
after setting them.

Deploy quirks: the same esbuild `banner` fix as the gatekeeper
(`globalThis.Blob = undefined;`) is applied — without it the deploy is
rejected with HTTP 400 / code 10021.

## Dashboard registration (user steps)

1. Open https://agentgames.zkverify.io/dashboard/agents (logged in as
   @Nentoczc) → register a new agent for **Steal the VFY** with endpoint
   `https://agent-games-steal-vfy.dtccrypto.workers.dev/agent`
   (full handler path `/agent`; root POST returns 404 by design).
2. The dashboard shows a 32-byte HMAC secret once ("Rotate Secret").
   **Send it to Muse only via a secure route — never in chat.** Muse sets
   it as the Worker secret `AGENT_GAMES_HMAC_SECRET` (replacing the dummy
   currently set). Secrets apply immediately; no redeploy needed.
3. Register the strategy commitment (hex) in the dashboard
   (My Agents → Edit agent → strategy commitment):
   `0x13883b9bad37ec6a8fddcf6f69aba282993285b94a50f987749bca6e9f18aa0e`
   This MUST match the agent's params+salt (Poseidon hash). Do this
   BEFORE the next Swiss round pairs, or the platform cannot pair the agent.
4. Run the dashboard **preflight** — it must return
   `{ok:true, protocolVersion:"v1"}`. (Verified live from this VM with the
   dummy secret; re-verify after the real secret is set.)
5. Run **≥1 practice turn** (same format, no score). Check the response
   carries a proof that verifies and the action is EXTRACT 10. **If the
   practice turn returns proof:null, do NOT enter a scored round** — see
   "Known limits" (likely the Workers plan CPU limit; upgrade to Paid).
6. Join the next Swiss round (R5) from the dashboard once preflight +
   practice pass with a real proof.

## Secrets

| Secret | From | Status |
|---|---|---|
| `AGENT_GAMES_HMAC_SECRET` | Agent Games dashboard → "Rotate Secret" (shown once, after the endpoint is registered) | **NOT SET — a dummy is in place.** Currently set on the Worker: `DUMMY-PLACEHOLDER-REPLACE-ME-0123456789abcdef`. The Worker verifies signatures against this dummy, so requests signed with the platform's real secret will get 401 until the Worker secret is replaced with the real one. **Replace after registration.** Send the real secret only via a secure route, never in chat. |
| `STEAL_VFY_SALT` | Generated for this agent (random 128-bit) | **Set** on the Worker. Value: `322748575781115448660733098535191849917`. Keep it private — it blinds the committed strategy. |
| `STEAL_VFY_COMMITMENT` | Poseidon hash of [...params, salt] | **Set** on the Worker (decimal). Also registered in the dashboard as hex (see above). |
| `KURIER_API_KEY` | https://kurier.xyz (free signup, mainnet) | **Not set — optional.** Without it the agent still answers every turn with a local Groth16 proof; only the `proofReference` audit pointer is missing. |

No other secret is needed. Never commit `.env`; `.gitignore` covers
`node_modules/`, `.env`, `dist/`, `*.log`.

## Known limits / what is untested

1. **Live practice turn returns proof:null in the Worker.** The turn
   endpoint works (correct EXTRACT 10 action, correct publicInputsHash,
   signed, 200 in ~14s), but `generateProof` fails inside the Worker and
   the response carries `proof: null, public_signals: null`. The same
   proof works locally (65/65 tests + live Node server). Most likely
   cause: the Cloudflare Workers plan CPU/memory limit — proving needs
   ~700–800ms CPU and the vfy-policy artifacts are ~3.8 MB, vs Workers
   Free's 10ms CPU per invocation. **Fix: upgrade to Workers Paid ($5/mo,
   30s CPU by default) and re-run a practice turn.** If it still returns
   proof:null on Paid, the cause is elsewhere (artifact fetch or snarkjs
   in-Worker) and needs Worker-log investigation. **Do not enter a scored
   round until a practice turn returns a real proof.**
2. **Live POST paths from this VM are flaky.** POSTs from this VM to
   `*.workers.dev` stall via Node fetch (the gatekeeper had the same
   issue); curl POSTs work. Preflight was verified live via curl.
   Verify preflight + practice from the dashboard (the user's
   browser/machine) after the real secret is set.
3. **Kurier untested end-to-end** (no API key). Same payloads as the
   gatekeeper (copied verbatim from the official Kurier docs).
4. **In-Worker artifact fetch untested live (proof path).** On first use
   per isolate the Worker fetches the wasm+zkey (~3.8 MB) from
   agentgames.zkverify.io and caches them. If that fetch fails, turns
   answer with `proof: null`. The fetch path is the same code as the local
   file path, but the network hop from Workers to the Agent Games site has
   not been independently verified (the 14s turn response suggests the
   fetch does run, but the prove then fails).
5. **In-memory idempotency is per-isolate.** A Worker restart or a second
   isolate starts with an empty turn cache. For 20 turns/match this is
   acceptable; a replay across isolates could in theory re-decide a turn
   (same deterministic result — the strategy is deterministic, so the
   re-decision is identical; only the idempotencyKey would differ).

## Local development

```sh
cp .env.example .env   # fill AGENT_GAMES_HMAC_SECRET (dummy value is fine)
npm install
npm test               # 65 assertions
npm run commitment     # prints the Poseidon commitment (hex + decimal)
npm start              # http://localhost:8787/agent
AGENT_GAMES_HMAC_SECRET=<dummy> node test/live-check.mjs http://localhost:8787
```

## Files

```
worker.mjs                  Cloudflare Workers entry (fetches circuit artifacts
                            from agentgames.zkverify.io at runtime, caches them)
index.mjs                   Node entry (local dev; reads ./circuits/ from disk)
src/app.mjs                 Hono app: HMAC gate, preflight, steal-the-vfy turn handler
src/config.mjs              env holder (Node process.env / Workers binding)
src/hmac.mjs                HMAC-SHA-256 sign/verify (WebCrypto only)
src/strategy.mjs            threshold policy (decideMove) + matchId encoding
src/prover.mjs              snarkjs Groth16 proving + local verification
src/vk.mjs                  embedded vfy-policy verification key
src/kurier.mjs              Kurier REST client (register-vk/submit-proof/job-status)
src/store.mjs               idempotency store (matchId+turn key)
scripts/build.mjs           esbuild bundle → dist/worker.js (349 KB)
scripts/deploy-curl.py      deploy via curl (verify/deploy/get-script/
                            enable-subdomain/subdomain/put-secret)
scripts/commitment.mjs      compute the Poseidon commitment (hex + decimal)
test/run-tests.mjs          test suite (npm test) — 65 assertions
test/live-check.mjs         live check vs a running server (preflight + turn)
circuits/                   vfy-policy.wasm, vfy-policy_final.zkey,
                            verification_key.json (official artifacts)
.env.example                env template (never commit a real .env)
```
