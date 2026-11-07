import { describe, it, expect, beforeEach, vi } from "vitest";
import { ed25519 } from "@noble/curves/ed25519";
import { bytesToHex } from "@noble/curves/utils";
import { verifySovereignAccess } from "../src/middleware/sovereignAuth.js";
import type { Env } from "../src/types.js";

describe("sovereignAuth Middleware", () => {
  const privateKeyBytes = ed25519.utils.randomPrivateKey();
  const publicKeyHex = bytesToHex(ed25519.getPublicKey(privateKeyBytes));
  const testIdentity = "maxjurreau-3";
  let mockLicenseRecord: { tier: string; expires_at: number | null } | null = null;

  const mockPrepare = vi.fn().mockImplementation((_query: string) => ({
    bind: vi.fn().mockImplementation((..._params: unknown[]) => ({
      first: vi.fn().mockImplementation(async () => mockLicenseRecord),
    })),
  }));
  const mockDb = { prepare: mockPrepare } as unknown as D1Database;
  const mockEnv: Env = {
    DB: mockDb,
    SOVEREIGN_LEDGER: mockDb,
    SOVEREIGN_PUBLIC_KEY: publicKeyHex,
  };

  beforeEach(() => {
    vi.clearAllMocks();
    mockLicenseRecord = null;
  });

  function createSignedHeaders(url: string, timestamp: string, identity: string, signingKey = privateKeyBytes) {
    const payload = `${new URL(url).pathname}:${timestamp}:${identity}`;
    const signature = ed25519.sign(new TextEncoder().encode(payload), signingKey);
    return {
      "X-QAL-Signature": bytesToHex(signature),
      "X-QAL-Timestamp": timestamp,
      "X-QAL-Identity": identity,
    };
  }

  it("rejects requests missing X-QAL headers", async () => {
    const result = await verifySovereignAccess(
      new Request("https://beemax.internal/api/manifold/compute"), mockEnv,
    );
    expect(result.authorized).toBe(false);
    expect(result.tier).toBe("missing_headers");
  });

  it("rejects timestamps outside the five-minute replay window", async () => {
    const timestamp = String(Date.now() - 300001);
    const url = "https://beemax.internal/api/manifold/compute";
    const request = new Request(url, { headers: createSignedHeaders(url, timestamp, testIdentity) });
    const result = await verifySovereignAccess(request, mockEnv);
    expect(result.authorized).toBe(false);
    expect(result.tier).toBe("expired_timestamp");
  });

  it("rejects an unconfigured public key", async () => {
    const url = "https://beemax.internal/api/manifold/compute";
    const timestamp = String(Date.now());
    const request = new Request(url, { headers: createSignedHeaders(url, timestamp, testIdentity) });
    const result = await verifySovereignAccess(request, { ...mockEnv, SOVEREIGN_PUBLIC_KEY: undefined });
    expect(result.authorized).toBe(false);
    expect(result.tier).toBe("unconfigured_environment");
  });

  it("rejects an invalid Ed25519 signature", async () => {
    const url = "https://beemax.internal/api/manifold/compute";
    const timestamp = String(Date.now());
    const wrongKey = ed25519.utils.randomPrivateKey();
    const request = new Request(url, { headers: createSignedHeaders(url, timestamp, testIdentity, wrongKey) });
    const result = await verifySovereignAccess(request, mockEnv);
    expect(result.authorized).toBe(false);
    expect(result.tier).toBe("invalid_signature");
  });

  it("rejects a valid signature when no D1 license exists", async () => {
    const url = "https://beemax.internal/api/manifold/compute";
    const timestamp = String(Date.now());
    const request = new Request(url, { headers: createSignedHeaders(url, timestamp, testIdentity) });
    const result = await verifySovereignAccess(request, mockEnv);
    expect(mockPrepare).toHaveBeenCalled();
    expect(result.authorized).toBe(false);
    expect(result.tier).toBe("unlicensed");
  });

  it("rejects an expired D1 license", async () => {
    mockLicenseRecord = { tier: "standard", expires_at: Date.now() - 1000 };
    const url = "https://beemax.internal/api/manifold/compute";
    const timestamp = String(Date.now());
    const request = new Request(url, { headers: createSignedHeaders(url, timestamp, testIdentity) });
    const result = await verifySovereignAccess(request, mockEnv);
    expect(result.authorized).toBe(false);
    expect(result.tier).toBe("license_expired");
  });

  it("authorizes a valid signature and active timed license", async () => {
    mockLicenseRecord = { tier: "sovereign", expires_at: Date.now() + 86400000 };
    const url = "https://beemax.internal/api/manifold/compute";
    const timestamp = String(Date.now());
    const request = new Request(url, { headers: createSignedHeaders(url, timestamp, testIdentity) });
    const result = await verifySovereignAccess(request, mockEnv);
    expect(result).toEqual({ authorized: true, tier: "sovereign", identity: testIdentity });
  });

  it("authorizes a lifetime license with a null expiry", async () => {
    mockLicenseRecord = { tier: "enterprise", expires_at: null };
    const url = "https://beemax.internal/api/storefront/download";
    const timestamp = String(Date.now());
    const request = new Request(url, { headers: createSignedHeaders(url, timestamp, testIdentity) });
    const result = await verifySovereignAccess(request, mockEnv);
    expect(result).toEqual({ authorized: true, tier: "enterprise", identity: testIdentity });
  });
});
