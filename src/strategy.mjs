// Steal the VFY strategy.
//
// The vfy-policy circuit enforces a threshold policy over the game state.
// Its 8 private strategyParams define the policy; the commitment is a
// Poseidon hash of [...params, salt] (computed off-Worker by
// scripts/commitment.mjs, stored as STEAL_VFY_COMMITMENT).
//
// Policy (enforced by the circuit — a move that does not follow it cannot
// prove, so decideMove MUST mirror it exactly):
//   selfBalance < params[1]  => FORTIFY
//   opponentBalance < params[2] => HOLD
//   otherwise => EXTRACT params[0] (1..10)
//
// Default params [10,0,0,0,0,0,0,0] mean "always EXTRACT 10": the
// thresholds (0) never trigger because balances are never negative.
// EXTRACT is strictly dominant in the payoff matrix (vs HOLD +20 relative,
// vs FORTIFY +10, vs EXTRACT 0 — never negative), so always extracting the
// maximum wins against any opponent that ever HOLDs or FORTIFies, and draws
// against an always-extracting opponent.
//
// Game numbers (from the official event page):
//   HOLD: free, no transfer.
//   FORTIFY: costs 2 VFY, blocks up to 6 VFY of incoming extraction.
//   EXTRACT N: free, steals up to N VFY (max 10) from the opponent's
//     exposed balance; a fortified opponent reduces the gain by 6.
//   Both start at 100 VFY; 20 turns; highest balance wins.

export const ACTION_CODE = { HOLD: 0, FORTIFY: 1, EXTRACT: 2 };

// Decide the move for one turn. Pure function of (state, params).
// Throws when the state is missing or unparseable (caller then returns
// proof: null / HOLD fallback). Returns { type, amountNum, actionCode }.
export function decideMove(state, params) {
  if (!state || typeof state !== "object") {
    throw new Error("missing game state");
  }
  const selfBalance = BigInt(state.selfBalance ?? 0);
  const opponentBalance = BigInt(state.opponentBalance ?? 0);
  if (selfBalance < BigInt(params[1])) {
    return { type: "FORTIFY", amountNum: 0, actionCode: ACTION_CODE.FORTIFY };
  }
  if (opponentBalance < BigInt(params[2])) {
    return { type: "HOLD", amountNum: 0, actionCode: ACTION_CODE.HOLD };
  }
  const amount = Number(params[0]);
  if (!Number.isInteger(amount) || amount < 1 || amount > 10) {
    throw new Error(`invalid extract amount param: ${params[0]}`);
  }
  return { type: "EXTRACT", amountNum: amount, actionCode: ACTION_CODE.EXTRACT };
}

// UUID (with dashes) -> BigInt, as the circuit expects matchId.
export function matchIdToBigInt(matchId) {
  const hex = String(matchId).replace(/^0x/i, "").replace(/-/g, "");
  if (!/^[0-9a-fA-F]+$/.test(hex)) {
    throw new Error(`invalid matchId: ${matchId}`);
  }
  return BigInt("0x" + hex);
}
