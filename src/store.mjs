// Idempotency store (in-memory, v1).
//
// Task IDs are idempotency keys: a re-delivered task must return the exact
// cached response, never re-evaluate or re-prove. The seen proof_tx set is
// the PROOF_REUSED detector: a proof_tx is marked as used ONLY when the
// task was APPROVEd (a rejected task's proof was never accepted), and only
// in competition mode (practice dispatches must not poison later rounds).

export function createStore() {
  const responses = new Map(); // task_id -> response object
  const seenProofTx = new Set(); // proof_tx strings accepted in competition

  return {
    getResponse(taskId) {
      return responses.get(taskId) ?? null;
    },
    setResponse(taskId, response) {
      responses.set(taskId, response);
    },
    isProofReused(proofTx) {
      if (typeof proofTx !== "string" || proofTx === "") return false;
      return seenProofTx.has(proofTx);
    },
    markProofUsed(proofTx) {
      if (typeof proofTx === "string" && proofTx !== "") seenProofTx.add(proofTx);
    },
    size() {
      return { tasks: responses.size, proofs: seenProofTx.size };
    },
  };
}
