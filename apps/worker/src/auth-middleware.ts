import { ed25519 } from "@noble/curves/ed25519";
import type { Env } from "./types";

const MAX_CLOCK_SKEW_MS = 5 * 60 * 1000;
const MAX_SIGNED_BODY_BYTES = 16_384;
const IDENTITY_PATTERN = /^[a-z0-9._:-]{1,64}$/;
const REQUEST_ID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const PUBLIC_KEY_PATTERN = /^(?:[0-9a-fA-F]{2}){32}$/;
const SIGNATURE_PATTERN = /^(?:[0-9a-fA-F]{2}){64}$/;

function jsonError(error: string, status: number): Response {
  return Response.json({ error }, { status });
}

function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

async function readBoundedBody(request: Request): Promise<Uint8Array | Response> {
  if (!request.body) return new Uint8Array();
  const declaredLength = Number(request.headers.get("Content-Length") ?? 0);
  if (Number.isFinite(declaredLength) && declaredLength > MAX_SIGNED_BODY_BYTES) {
    return jsonError("Signed request body is too large", 413);
  }

  const reader = request.body.getReader();
  const chunks: Uint8Array[] = [];
  let length = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      length += value.byteLength;
      if (length > MAX_SIGNED_BODY_BYTES) {
        await reader.cancel();
        return jsonError("Signed request body is too large", 413);
      }
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }

  const body = new Uint8Array(length);
  let offset = 0;
  for (const chunk of chunks) {
    body.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return body;
}

/**
 * Validates signed requests to the storefront/manifold route families.
 * Sign the UTF-8 bytes of:
 * BEEMAX-SOVEREIGN-V1\nMETHOD\npathname\ntimestamp\nidentity\nreqId\nsha256(body)-hex
 * Headers: X-QAL-Identity, X-QAL-Timestamp (milliseconds),
 * X-QAL-Request-Id (UUID), and X-QAL-Signature (hex Ed25519 signature).
 */
export async function verifySovereignRequest(
  request: Request,
  env: Env,
): Promise<Response | null> {
  const rawIdentity = request.headers.get("X-QAL-Identity") ?? "";
  const identity = rawIdentity.trim().toLowerCase();
  const timestamp = request.headers.get("X-QAL-Timestamp") ?? "";
  const requestId = request.headers.get("X-QAL-Request-Id") ?? "";
  const signatureHex = request.headers.get("X-QAL-Signature") ?? "";

  if (!IDENTITY_PATTERN.test(identity) || identity === "anonymous") {
    return jsonError("Invalid sovereign identity", 401);
  }
  if (!/^\d{1,16}$/.test(timestamp)) {
    return jsonError("Invalid or missing request timestamp", 401);
  }
  const requestTime = Number(timestamp);
  if (!Number.isSafeInteger(requestTime) || Math.abs(Date.now() - requestTime) > MAX_CLOCK_SKEW_MS) {
    return jsonError("Request timestamp expired", 401);
  }
  if (!REQUEST_ID_PATTERN.test(requestId)) {
    return jsonError("Invalid or missing request ID", 400);
  }
  if (!SIGNATURE_PATTERN.test(signatureHex)) {
    return jsonError("Invalid or missing Ed25519 signature", 401);
  }

  const body = await readBoundedBody(request.clone());
  if (body instanceof Response) return body;

  try {
    const identityRecord = await env.DB.prepare(
      "SELECT public_key FROM sovereign_identities WHERE identity = ? AND status = 'ACTIVE'",
    ).bind(identity).first<{ public_key: string }>();
    if (!identityRecord || !PUBLIC_KEY_PATTERN.test(identityRecord.public_key)) {
      return jsonError("Sovereign identity is not registered or active", 401);
    }

    const bodyDigest = new Uint8Array(await crypto.subtle.digest("SHA-256", body));
    const canonical = [
      "BEEMAX-SOVEREIGN-V1",
      request.method.toUpperCase(),
      new URL(request.url).pathname,
      timestamp,
      identity,
      requestId,
      bytesToHex(bodyDigest),
    ].join("\n");
    const valid = ed25519.verify(
      hexToBytes(signatureHex),
      new TextEncoder().encode(canonical),
      hexToBytes(identityRecord.public_key),
    );
    if (!valid) return jsonError("Sovereign request signature is invalid", 401);

    // Expired nonce rows can be discarded safely: their associated signatures
    // are outside the accepted timestamp window. The INSERT's unique key is the
    // atomic one-time check; simultaneous replays cannot both succeed.
    const now = Date.now();
    await env.DB.prepare("DELETE FROM sovereign_nonces WHERE created_at <= ?")
      .bind(now - MAX_CLOCK_SKEW_MS * 2)
      .run();
    const nonce = await env.DB.prepare(
      "INSERT INTO sovereign_nonces(req_id, identity, created_at) VALUES (?, ?, ?) ON CONFLICT(req_id) DO NOTHING",
    ).bind(requestId, identity, now).run();
    if (nonce.meta.changes !== 1) return jsonError("Sovereign request has already been used", 409);

    return null;
  } catch (error) {
    console.error("[sovereign-auth] request verification failed", error);
    return jsonError("Sovereign verification service unavailable", 503);
  }
}
