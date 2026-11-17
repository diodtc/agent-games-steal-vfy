// Local Groth16 proving for the vfy-policy circuit (snarkjs).
//
// Circuit (https://agentgames.zkverify.io/api/circuit-info):
//   vk_hash 0x6c56509f1c56fd1fd4e9737f906d2220f4b95f1d507f1adf6899085bd74be047
//   Groth16, curve bn128, nPublic 9 (8 public inputs + 1 output).
//
// Circuit inputs (17: 8 public + 9 private), in witness order:
//   commitment, matchId, turnNumber, selfBalance, opponentBalance,
//   action (0=HOLD, 1=FORTIFY, 2=EXTRACT), amount, circuitVersion (public),
//   salt, strategyParams[0..7] (private).
// Public signals returned by snarkjs, in order (verified empirically,
// 2026-11-16):
//   [0]  circuit output — a circuit-defined field element (do not assert
//        its value; its semantics are unpublished)
//   [1]  commitment (Poseidon hash of [...strategyParams, salt], mod p)
//   [2]  matchId (UUID hex, dashes removed, as integer)
//   [3]  turnNumber, [4] selfBalance, [5] opponentBalance
//   [6]  action, [7] amount, [8] circuitVersion (1)
//
// The circuit enforces the threshold policy (see src/strategy.mjs): a move
// that does not follow the committed strategyParams cannot prove (the
// witness calculator asserts). A failed prove therefore means the move
// disagrees with the strategy — the caller must fall back to proof: null
// (the turn is still answered; only the proof bonus is lost).
//
// Encodings (verified empirically):
//   - commitment: decimal string of the Poseidon hash (already < p).
//   - matchId: decimal of the UUID hex (dashes removed).
//   - numbers: decimal strings.
//   - salt: decimal string of the blinding salt.
//   - strategyParams: array of 8 decimal strings.
//
// Prove times measured locally: ~700–800ms per proof — well inside the
// 5-minute turn deadline.
//
// Artifact loading is INJECTED by the entry point (loadArtifacts): Node
// reads ./circuits/*.wasm|*.zkey from disk; Workers fetches them from
// agentgames.zkverify.io at runtime (snarkjs accepts ArrayBuffers).

import * as snarkjs from "snarkjs";
import { VERIFICATION_KEY } from "./vk.mjs";
import { matchIdToBigInt } from "./strategy.mjs";

// Build the circuit input object for one turn + move. Throws when any
// required field is missing or unparseable (caller then returns proof: null).
export function buildCircuitInput(envelope, move, cfg) {
  const state = envelope.state || {};
  // Prefer the platform's frozen commitment hash when present (it is what
  // the platform verifies against); fall back to the locally configured one.
  let commitment = cfg.strategyCommitment;
  const frozen = envelope.strategyCommitment?.hash;
  if (typeof frozen === "string" && frozen !== "") {
    commitment = BigInt(frozen).toString();
    if (commitment !== cfg.strategyCommitment) {
      console.warn(
        "[prover] envelope commitment differs from configured commitment — " +
          "the registered strategy may not match this agent's params/salt"
      );
    }
  }
  return {
    commitment,
    matchId: matchIdToBigInt(envelope.matchId).toString(),
    turnNumber: String(envelope.turn),
    selfBalance: String(state.selfBalance),
    opponentBalance: String(state.opponentBalance),
    action: String(move.actionCode),
    amount: String(move.amountNum),
    circuitVersion: "1",
    salt: String(cfg.strategySalt),
    strategyParams: cfg.strategyParams.map(String),
  };
}

// Generate a Groth16 proof for one turn and locally verify it against the
// embedded verification key. Returns { proof, publicSignals } or null when
// proving is impossible (bad input / strategy mismatch) or local
// verification fails. A null is the correct fallback: the turn answer still
// goes out (the move itself is scored); only the proof bonus is lost.
export async function generateProof(envelope, move, cfg, loadArtifacts) {
  let circuitInput;
  try {
    circuitInput = buildCircuitInput(envelope, move, cfg);
  } catch (err) {
    console.warn(`[prover] cannot build circuit input: ${err.message}`);
    return null;
  }
  let artifacts;
  try {
    artifacts = await loadArtifacts();
  } catch (err) {
    console.warn(`[prover] artifact load failed: ${err.message}`);
    return null;
  }
  try {
    const { proof, publicSignals } = await snarkjs.groth16.fullProve(
      circuitInput,
      artifacts.wasm,
      artifacts.zkey
    );
    const ok = await snarkjs.groth16.verify(VERIFICATION_KEY, publicSignals, proof);
    if (!ok) {
      console.warn("[prover] local verification FAILED");
      return null;
    }
    return { proof, publicSignals };
  } catch (err) {
    console.warn(`[prover] fullProve failed: ${err.message.split("\n")[0]}`);
    return null;
  }
}
