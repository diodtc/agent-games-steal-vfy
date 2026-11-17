// HMAC-SHA-256 signing / verification for the Agent Games protocol.
//
// The platform signs every request with the `x-agent-games-signature`
// header, computed over the RAW request body. Every response must be signed
// the same way over the RAW response body. Verification runs BEFORE parsing
// any JSON.
//
// Uses only WebCrypto (global `crypto.subtle`), so this module runs
// unchanged on Node and on Cloudflare Workers. No Node-only imports.
//
// Two details the live /build page does NOT pin down, and how this module
// handles them (see README "Unresolved protocol details"):
//  1. Signature encoding: the signer emits lowercase hex, no prefix. The
//     verifier ALSO accepts a "sha256=" prefix and base64, so either
//     platform choice verifies.
//  2. Key derivation: the HMAC key is derived from the secret string per
//     HMAC_KEY_ENCODING (utf8 | hex | base64, default utf8). The verifier
//     tries every applicable derivation; the signer uses the configured one.

const te = new TextEncoder();

export function toHex(bytes) {
  return [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");
}

function fromHex(str) {
  if (typeof str !== "string" || str.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(str)) return null;
  const out = new Uint8Array(str.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(str.slice(i * 2, i * 2 + 2), 16);
  return out;
}

function fromBase64(str) {
  try {
    const bin = atob(str);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  } catch {
    return null;
  }
}

// Decode a presented signature value into raw bytes. Accepts bare hex,
// "sha256=<hex>", and base64. Returns null when undecodable.
export function decodeSignature(value) {
  if (typeof value !== "string") return null;
  let v = value.trim();
  if (/^sha256=/i.test(v)) v = v.slice(7);
  if (/^[0-9a-fA-F]+$/.test(v) && v.length % 2 === 0) return fromHex(v);
  return fromBase64(v);
}

// Derive HMAC key bytes from the secret string under one encoding.
export function deriveKeyBytes(secret, encoding) {
  if (encoding === "hex") {
    const b = fromHex(secret.trim());
    if (b && b.length > 0) return b;
  }
  if (encoding === "base64") {
    const b = fromBase64(secret.trim());
    if (b && b.length > 0) return b;
  }
  return te.encode(secret); // utf8 (default, and fallback)
}

async function hmacSignBytes(keyBytes, dataBytes) {
  const key = await crypto.subtle.importKey(
    "raw",
    keyBytes,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const sig = await crypto.subtle.sign("HMAC", key, dataBytes);
  return new Uint8Array(sig);
}

// Sign raw bytes; returns lowercase hex (no prefix).
export async function signBody(secret, encoding, dataBytes) {
  const sig = await hmacSignBytes(deriveKeyBytes(secret, encoding), dataBytes);
  return toHex(sig);
}

// Constant-time byte comparison (no Node-only APIs).
function timingEqual(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

// Verify a presented signature against raw body bytes. Tries every
// applicable key derivation (configured encoding first, then utf8/hex/
// base64) so the endpoint is robust to how the platform derived its key.
// Returns true on the first match.
export async function verifySignature(secret, configuredEncoding, headerValue, dataBytes) {
  const presented = decodeSignature(headerValue);
  if (!presented || presented.length === 0) return false;
  const encodings = [...new Set([configuredEncoding, "utf8", "hex", "base64"])];
  for (const enc of encodings) {
    const expected = await hmacSignBytes(deriveKeyBytes(secret, enc), dataBytes);
    if (timingEqual(presented, expected)) return true;
  }
  return false;
}
