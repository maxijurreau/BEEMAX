import { ed25519 } from "@noble/curves/ed25519";
import type { Env } from "../types.js";

export interface SovereignAccessResult {
  authorized: boolean;
  tier: string;
  identity: string;
}

const MAX_CLOCK_SKEW_MS = 5 * 60 * 1000;
const IDENTITY_PATTERN = /^[a-z0-9._:-]+$/;
const HEX_PATTERN = /^(?:[0-9a-fA-F]{2})+$/;

function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

export async function verifySovereignAccess(
  request: Request,
  env: Env,
): Promise<SovereignAccessResult> {
  const signatureHex = request.headers.get("X-QAL-Signature");
  const timestamp = request.headers.get("X-QAL-Timestamp");
  const rawIdentity = request.headers.get("X-QAL-Identity");
  const identity = rawIdentity ? rawIdentity.trim().toLowerCase() : "";

  // Reject ambiguous or malformed identities before doing crypto or querying D1.
  if (!identity || identity === "anonymous" || identity.length > 64 || !IDENTITY_PATTERN.test(identity)) {
    return { authorized: false, tier: "invalid_identity", identity: "anonymous" };
  }
  if (!signatureHex || !timestamp) {
    return { authorized: false, tier: "missing_headers", identity };
  }
  if (!/^\d{1,16}$/.test(timestamp)) {
    return { authorized: false, tier: "expired_timestamp", identity };
  }

  const requestTime = Number(timestamp);
  if (!Number.isSafeInteger(requestTime) || Math.abs(Date.now() - requestTime) > MAX_CLOCK_SKEW_MS) {
    return { authorized: false, tier: "expired_timestamp", identity };
  }

  const publicKeyHex = env.SOVEREIGN_PUBLIC_KEY;
  const ledger = env.SOVEREIGN_LEDGER;
  if (!publicKeyHex || !ledger || !/^(?:[0-9a-fA-F]{2}){32}$/.test(publicKeyHex)) {
    return { authorized: false, tier: "unconfigured_environment", identity };
  }
  if (!/^(?:[0-9a-fA-F]{2}){64}$/.test(signatureHex)) {
    return { authorized: false, tier: "invalid_signature", identity };
  }

  try {
    // The client must sign this canonicalized identity with the exact request path and timestamp.
    const payload = `${new URL(request.url).pathname}:${timestamp}:${identity}`;
    const isValid = ed25519.verify(
      hexToBytes(signatureHex),
      new TextEncoder().encode(payload),
      hexToBytes(publicKeyHex),
    );
    if (!isValid) return { authorized: false, tier: "invalid_signature", identity };

    const license = await ledger.prepare(
      "SELECT tier, expires_at FROM sovereign_licenses WHERE identity = ? AND status = 'active'",
    ).bind(identity).first<{ tier: string; expires_at: number | null }>();

    if (!license) return { authorized: false, tier: "unlicensed", identity };

    // NULL and the legacy zero sentinel both represent a lifetime license.
    const isLifetime = license.expires_at === null || license.expires_at === 0;
    if (!isLifetime && license.expires_at! <= Date.now()) {
      return { authorized: false, tier: "license_expired", identity };
    }

    return { authorized: true, tier: license.tier, identity };
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    console.error("[sovereignAuth] Verification failure:", message);
    return { authorized: false, tier: "verification_error", identity };
  }
}
