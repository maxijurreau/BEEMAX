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
  /** Base64-encoded DER SubjectPublicKeyInfo for the active QAL RSA key. */
  QAL_PUBLIC_KEY: string;
  /** Active isolate signature over `${nodeId}:${timestamp}` (base64). */
  QAL_SIGNATURE?: string;
  PROCESS_MANAGER?: HealthProbeComponent;
  SIMULATION_ENGINE?: HealthProbeComponent;
  ENVIRONMENT?: string;
}

const NODE_ID = "planetary-edge-node-01";
const MAX_SIGNATURE_AGE_MS = 60_000;

function base64ToBytes(value: string): Uint8Array {
  const normalized = value.replace(/-/g, "+").replace(/_/g, "/");
  const binary = atob(normalized);
  return Uint8Array.from(binary, (character) => character.charCodeAt(0));
}

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

async function verifyQalSignature(
  publicKey: string,
  signature: string | undefined,
  nodeId: string,
  timestamp: number,
  now: number,
): Promise<boolean> {
  if (!signature || Math.abs(now - timestamp) > MAX_SIGNATURE_AGE_MS) return false;
  try {
    const key = await crypto.subtle.importKey(
      "spki",
      base64ToBytes(publicKey),
      { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
      false,
      ["verify"],
    );
    return await crypto.subtle.verify(
      "RSASSA-PKCS1-v1_5",
      key,
      base64ToBytes(signature),
      new TextEncoder().encode(`${nodeId}:${timestamp}`),
    );
  } catch {
    return false;
  }
}

/**
 * GET /health and /healthz return a quick wiring diagnostic by default.
 * `?level=authoritative` additionally persists a signed heartbeat and probes
 * the configured Durable Object lease. QAL verification fails closed unless a
 * valid, fresh signature and a provisioned RSA public key are supplied.
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
    const healthy = wiringStatus.processManager && wiringStatus.simulationEngine;
    return Response.json(
      {
        status: healthy ? "HEALTHY" : "DEGRADED",
        tier: "DIAGNOSTIC_WIRING",
        wiringStatus,
        timestamp: now,
      },
      { status: healthy ? 200 : 503, headers: { "Cache-Control": "no-store" } },
    );
  }

  const signature = request.headers.get("X-QAL-Signature") ?? env.QAL_SIGNATURE;
  const signedAtHeader = request.headers.get("X-QAL-Timestamp");
  const signedAt = signedAtHeader === null ? now : Number(signedAtHeader);
  const qalSignatureVerified = Number.isSafeInteger(signedAt)
    && await verifyQalSignature(env.QAL_PUBLIC_KEY, signature, NODE_ID, signedAt, now);

  let d1HeartbeatPersisted = false;
  let durableObjectLeaseValid = false;
  let status: HealthStatus = "DEGRADED";

  try {
    const nodeStatus: HealthStatus = qalSignatureVerified ? "HEALTHY" : "DEGRADED";
    const result = await env.DB.prepare(`
      INSERT INTO node_heartbeats
        (node_id, worker_environment, status, active_isolates, qal_signature, last_tick_timestamp)
      VALUES (?, ?, ?, 1, ?, ?)
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
        nodeStatus,
        qalSignatureVerified ? signature : "",
        signedAt,
      )
      .run();
    d1HeartbeatPersisted = result.success;
  } catch {
    d1HeartbeatPersisted = false;
  }

  try {
    const kernel = env.PORTAL_KERNEL.get(env.PORTAL_KERNEL.idFromName("global-health-anchor"));
    const leaseResponse = await kernel.fetch(new Request("https://portal-kernel/ping"));
    durableObjectLeaseValid = leaseResponse.ok;
  } catch {
    durableObjectLeaseValid = false;
  }

  const isFullyHealthy = d1HeartbeatPersisted && durableObjectLeaseValid && qalSignatureVerified;
  status = isFullyHealthy ? "HEALTHY" : "DEGRADED";
  const latencyMs = performance.now() - startTime;

  try {
    await env.DB.prepare(`
      INSERT INTO attestation_logs (node_id, probe_type, latency_ms, verified, timestamp)
      VALUES (?, 'AUTHORITATIVE_LEASE', ?, ?, ?)
    `)
      .bind(NODE_ID, latencyMs, isFullyHealthy ? 1 : 0, now)
      .run();
  } catch {
    // The health result remains degraded if required evidence could not be logged.
    status = "DEGRADED";
  }

  const responsePayload: HealthAttestationResponse = {
    nodeId: NODE_ID,
    status,
    wiringStatus,
    authoritativeAttestation: {
      d1HeartbeatPersisted,
      durableObjectLeaseValid,
      qalSignatureVerified,
      latencyMs,
    },
    timestamp: now,
  };

  const healthy = status === "HEALTHY";
  return Response.json(responsePayload, {
    status: healthy ? 200 : 503,
    headers: { "Cache-Control": "no-store" },
  });
}
