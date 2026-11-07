export type HealthStatus = "HEALTHY" | "DEGRADED" | "UNREACHABLE";

export interface HealthAttestationResponse {
  nodeId: string;
  status: HealthStatus;
  wiringStatus: {
    processManager: boolean;
    simulationEngine: boolean;
  };
  authoritativeAttestation: {
    d1HeartbeatPersisted: boolean;
    durableObjectLeaseValid: boolean;
    qalSignatureVerified: boolean;
    latencyMs: number;
  };
  timestamp: number;
}

interface HealthProbeComponent {
  status?: () => unknown;
  verifyReplay?: () => boolean;
}

interface HealthNamespace {
  idFromName(name: string): DurableObjectId;
  get(id: DurableObjectId): { fetch(request: Request): Promise<Response> };
}

export interface HealthAttestationEnv {
  DB: D1Database;
  PORTAL_KERNEL: HealthNamespace;
  /** PEM-encoded SubjectPublicKeyInfo RSA public key; never a private key. */
  QAL_PUBLIC_KEY_PEM: string;
  PROCESS_MANAGER?: HealthProbeComponent;
  SIMULATION_ENGINE?: HealthProbeComponent;
  ENVIRONMENT?: string;
}

const NODE_ID = "planetary-edge-node-01";
const FRESHNESS_WINDOW_MS = 60_000;

function componentReady(component: HealthProbeComponent | undefined): boolean {
  if (!component) return false;
  try {
    if (component.verifyReplay) return component.verifyReplay();
    if (component.status) {
      const status = component.status();
      return status === "running" || status === "READY" || status === "RUNNING" || status === true;
    }
  } catch {
    return false;
  }
  return false;
}

function pemToBytes(pem: string): Uint8Array {
  const encoded = pem.replace(/-----BEGIN PUBLIC KEY-----|-----END PUBLIC KEY-----|\s/g, "");
  const binary = atob(encoded);
  return Uint8Array.from(binary, (character) => character.charCodeAt(0));
}

/** Verifies an RSA PKCS#1 v1.5 SHA-256 signature over the canonical health claim. */
async function verifyRSASSA(
  data: string,
  base64Signature: string,
  pemPublicKey: string,
): Promise<boolean> {
  try {
    const key = await crypto.subtle.importKey(
      "spki",
      pemToBytes(pemPublicKey),
      { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
      false,
      ["verify"],
    );
    const signature = Uint8Array.from(atob(base64Signature), (character) => character.charCodeAt(0));
    return await crypto.subtle.verify(
      "RSASSA-PKCS1-v1_5",
      key,
      signature,
      new TextEncoder().encode(data),
    );
  } catch {
    return false;
  }
}

/**
 * GET /health and /healthz return a quick wiring diagnostic by default.
 * `?level=authoritative` additionally requires a fresh, request-bound QAL
 * signature, persists its heartbeat, and validates the Durable Object lease.
 */
export async function handleAuthoritativeHealthCheck(
  request: Request,
  env: HealthAttestationEnv,
): Promise<Response> {
  if (request.method !== "GET") {
    return Response.json({ error: "Method not allowed" }, { status: 405 });
  }

  const startTime = performance.now();
  const now = Date.now();
  const url = new URL(request.url);
  const wiringStatus = {
    processManager: componentReady(env.PROCESS_MANAGER),
    simulationEngine: componentReady(env.SIMULATION_ENGINE),
  };

  if (url.searchParams.get("level") !== "authoritative") {
    const diagnosticHealthy = wiringStatus.processManager && wiringStatus.simulationEngine;
    return Response.json(
      {
        status: diagnosticHealthy ? "HEALTHY" : "DEGRADED",
        tier: "DIAGNOSTIC_WIRING",
        wiringStatus,
        timestamp: now,
      },
      {
        status: diagnosticHealthy ? 200 : 503,
        headers: { "Cache-Control": "no-store" },
      },
    );
  }

  let d1HeartbeatPersisted = false;
  let durableObjectLeaseValid = false;
  let qalSignatureVerified = false;
  const incomingSignature = request.headers.get("X-QAL-Attestation-Sig");
  const signedAtHeader = request.headers.get("X-QAL-Attestation-Timestamp");
  const signedAt = signedAtHeader === null ? Number.NaN : Number(signedAtHeader);

  if (
    incomingSignature &&
    Number.isSafeInteger(signedAt) &&
    Math.abs(now - signedAt) <= FRESHNESS_WINDOW_MS
  ) {
    const canonicalClaim = `nodeId=${NODE_ID}&timestamp=${signedAt}`;
    qalSignatureVerified = await verifyRSASSA(
      canonicalClaim,
      incomingSignature,
      env.QAL_PUBLIC_KEY_PEM,
    );
  }

  if (qalSignatureVerified) {
    try {
      const result = await env.DB.prepare(`
        INSERT INTO node_heartbeats
          (node_id, worker_environment, status, active_isolates, qal_signature, last_tick_timestamp)
        VALUES (?, ?, 'HEALTHY', 1, ?, ?)
        ON CONFLICT(node_id) DO UPDATE SET
          worker_environment = excluded.worker_environment,
          status = excluded.status,
          active_isolates = excluded.active_isolates,
          qal_signature = excluded.qal_signature,
          last_tick_timestamp = excluded.last_tick_timestamp
      `)
        .bind(
          NODE_ID,
          env.ENVIRONMENT ?? "unknown",
          incomingSignature,
          signedAt,
        )
        .run();
      d1HeartbeatPersisted = result.success;
    } catch {
      d1HeartbeatPersisted = false;
    }
  }

  try {
    const kernel = env.PORTAL_KERNEL.get(env.PORTAL_KERNEL.idFromName("global-health-anchor"));
    const leaseResponse = await kernel.fetch(new Request("https://portal-kernel/ping"));
    durableObjectLeaseValid = leaseResponse.ok;
  } catch {
    durableObjectLeaseValid = false;
  }

  const latencyMs = performance.now() - startTime;
  const isFullyHealthy = d1HeartbeatPersisted && durableObjectLeaseValid && qalSignatureVerified;
  const responsePayload: HealthAttestationResponse = {
    nodeId: NODE_ID,
    status: isFullyHealthy ? "HEALTHY" : "DEGRADED",
    wiringStatus,
    authoritativeAttestation: {
      d1HeartbeatPersisted,
      durableObjectLeaseValid,
      qalSignatureVerified,
      latencyMs,
    },
    timestamp: now,
  };

  // Store every authoritative probe outcome. A failed audit write is itself a
  // failure of authoritative readiness, not a successful attestation.
  let auditPersisted = false;
  try {
    const result = await env.DB.prepare(`
      INSERT INTO attestation_logs (node_id, probe_type, latency_ms, verified, timestamp)
      VALUES (?, 'AUTHORITATIVE_LEASE', ?, ?, ?)
    `)
      .bind(NODE_ID, latencyMs, isFullyHealthy ? 1 : 0, now)
      .run();
    auditPersisted = result.success;
  } catch {
    auditPersisted = false;
  }

  if (!auditPersisted) responsePayload.status = "DEGRADED";
  return Response.json(responsePayload, {
    status: responsePayload.status === "HEALTHY" ? 200 : 503,
    headers: { "Cache-Control": "no-store" },
  });
}
