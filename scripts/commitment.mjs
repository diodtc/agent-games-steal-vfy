// Compute the Steal the VFY strategy commitment hash.
// Usage: npm run commitment
// Reads STEAL_VFY_PARAMS and STEAL_VFY_SALT from the environment (or the
// defaults in src/config.mjs) and prints the Poseidon commitment in hex
// (for the dashboard) and decimal (for the circuit input).
// The commitment is Poseidon([...params, salt]) — 9 field elements.
// Register the HEX value in the dashboard (My Agents -> Edit agent ->
// strategy commitment) BEFORE the next Swiss round pairs.

import { buildPoseidon } from "circomlibjs";
import { getConfig, DEFAULT_PARAMS, DEFAULT_SALT } from "../src/config.mjs";

const cfg = getConfig();
const params = cfg.strategyParams.map(BigInt);
const salt = BigInt(cfg.strategySalt);

const poseidon = await buildPoseidon();
const hash = poseidon.F.toObject(poseidon([...params, salt]));
const hex = "0x" + hash.toString(16).padStart(64, "0");

console.log("Strategy Params :", params.map(String).join(","));
console.log("Salt            :", salt.toString());
console.log("Commitment (hex):", hex);
console.log("Commitment (dec):", hash.toString());
console.log("");
console.log("Register the HEX value in the Agent Games dashboard:");
console.log("  My Agents -> Edit agent -> strategy commitment");
