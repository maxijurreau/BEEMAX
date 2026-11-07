import { ed25519 } from "@noble/curves/ed25519";
import type { Env } from "../types.js";

export interface AccessContext {
  authorized: boolean;
  tier: string;
  identity: string;
}

const MAX_CLOCK_SKEW_MS = 5 * 60 * 1000;

/** Verifies an Ed25519 QAL request and checks the identity's D1 license. */
export async function verifySovereignAccess(
  request: Request,
  env: Env,
): Promise<AccessContext> {
  const signatureHex = request.headers.get("X-QAL-Signature");
  const timestamp = request.headers.get("X-QAL-Timestamp");
  const identity = request.headers.get("X-QAL-Identity") || "anonymous";

  if (!signatureHex || !timestamp) {
    return { authorized: false, tier: "missing_headers", identity };
  }
  if (identity.length > 200 || !/^\d{1,16}$/.test(timestamp)) {
    return { authorized: false, tier: "invalid_headers", identity };
  }

  const requestTime = Number(timestamp);
  if (!Number.isSafeInteger(requestTime) || Math.abs(Date.now() - requestTime) > MAX_CLOCK_SKEW_MS) {
    return { authorized: false, tier: "expired_timestamp", identity };
  }

  const publicKeyHex = env.SOVEREIGN_PUBLIC_KEY;
  if (!publicKeyHex || !/^(?:[0-9a-fA-F]{2}){32}$/.test(publicKeyHex)) {
    return { authorized: false, tier: "unconfigured_environment", identity };
  }
  if (!/^(?:[0-9a-fA-F]{2}){64}$/.test(signatureHex)) {
    return { authorized: false, tier: "invalid_signature", identity };
  }

  try {
    const payload = `${new URL(request.url).pathname}:${timestamp}:${identity}`;
    const isValid = ed25519.verify(
      hexToBytes(signatureHex),
      new TextEncoder().encode(payload),
      hexToBytes(publicKeyHex),
    );
    if (!isValid) return { authorized: false, tier: "invalid_signature", identity };

    const ledger = env.SOVEREIGN_LEDGER ?? env.DB;
    const license = await ledger.prepare(
      "SELECT tier, expires_at FROM sovereign_licenses WHERE identity = ? AND status = 'active'",
    ).bind(identity).first<{ tier: string; expires_at: number | null }>();

    if (!license) return { authorized: false, tier: "unlicensed", identity };
    if (license.expires_at !== null && license.expires_at <= Date.now()) {
      return { authorized: false, tier: "license_expired", identity };
    }

    return { authorized: true, tier: license.tier, identity };
  } catch {
    return { authorized: false, tier: "error", identity };
  }
}

function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}
