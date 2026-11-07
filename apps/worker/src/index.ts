import { captureIntelligence } from "./universe-api.js";
import { reconcileCompensation } from "./execution.js";
import { protectPortal, auditAccess } from "./access.js";
import { verifySovereignAccess } from "./middleware/sovereignAuth.js";
import kernel from "./kernel.js";
import { routeApi } from "./routes/api.js";
import { telemetryStatsApi } from "./routes/telemetry.js";
import { bemaxApi, compatibilityApi } from "./bemax.js";
import { createEdgeRuntime } from "./runtime.js";
import { streamTokenApi } from "./stream.js";
import type { Env } from "./types.js";
export { ProductFactoryActor } from "./factory.js";
export { MicrokernelProcessActor } from "./kernel.js";
export { InstantSpaceDurableObject } from "./InstantSpaceDurableObject.js";

export default {
  async scheduled(_event: ScheduledController, env: Env, ctx: ExecutionContext) {
    ctx.waitUntil(captureIntelligence(env));
    ctx.waitUntil(reconcileCompensation(env));
    ctx.waitUntil((async () => {
      if (!env.FACTORY_ACTOR) return;
      const ideas = await env.DB.prepare(
        `SELECT p.id FROM products p WHERE (p.stage IN ('Idea','Discovery','Validation') OR
        (p.stage='Build' AND EXISTS (SELECT 1 FROM factory_runs r WHERE r.product_id=p.id AND r.status IN ('running','blocked'))))
        AND length(trim(p.description)) >= 20 AND length(trim(p.name)) >= 2
        AND NOT EXISTS (SELECT 1 FROM workflow_events e WHERE e.product_id=p.id)
        ORDER BY p.updated_at,p.id LIMIT 50`,
      ).all<{ id: string }>();
      await Promise.all(ideas.results.map(async ({ id }) => {
        const response = await env.FACTORY_ACTOR!.get(env.FACTORY_ACTOR!.idFromName(id))
          .fetch("https://factory.internal/run", { method: "POST", body: JSON.stringify({ productId: id }) });
        if (!response.ok) throw new Error(`ICVS reconciliation failed: ${response.status}`);
      }));
    })());
  },
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    const path = new URL(request.url).pathname;
    const origin = request.headers.get("Origin");
    const allowed = (env.ALLOWED_ORIGINS ?? "").split(",").map((value) => value.trim());
    const headers = new Headers({ Vary: "Origin", "Cache-Control": "no-store" });
    if (origin && allowed.includes(origin)) {
      headers.set("Access-Control-Allow-Origin", origin);
      headers.set("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
      headers.set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-QAL-Signature, X-QAL-Timestamp, X-QAL-Identity");
    }
    if (origin && !allowed.includes(origin))
      return Response.json({ error: "Origin not allowed" }, { status: 403, headers });
    if (request.method === "OPTIONS") return new Response(null, { status: 204, headers });

    if (path === "/api/space/ws") {
      if (request.method !== "GET") return new Response("Method not allowed", { status: 405, headers });
      if (!env.INSTANT_SPACE) return Response.json({ error: "Spatial sync unavailable" }, { status: 503, headers });
      if (request.headers.get("Upgrade")?.toLowerCase() !== "websocket")
        return new Response("Expected Upgrade: websocket", { status: 426, headers });
      const objectId = env.INSTANT_SPACE.idFromName("portal-os1-spatial-space");
      return env.INSTANT_SPACE.get(objectId).fetch(request);
    }

    if ((path === "/healthz" || path === "/health") && request.method === "GET") {
      const runtime = createEdgeRuntime(env);
      return Response.json({
        status: runtime.adapters.list().every((adapter) => adapter.state === "CONNECTED") ? "CONNECTED" : "DEGRADED",
        substrate: "Portal-OS1 Edge Runtime",
        identityAnchor: "bba28add4f99bd9aae158f173168145d",
        adapters: runtime.adapters.list().map(({ kind, id, state, identityAnchor }) => ({ kind, id, state, identityAnchor })),
        simulation: { id: "portal-edge-health", version: "1.0.0", stepMs: 1000, replay: runtime.simulation.verifyReplay() },
      }, { headers });
    }

    try {
      const access = await protectPortal(request, env);
      if (access instanceof Response) {
        ctx.waitUntil(auditAccess(env, request, null, access.status));
        headers.forEach((value, key) => access.headers.set(key, value));
        return access;
      }

      const sovereignRoute = path.startsWith("/api/manifold/") || path.startsWith("/api/storefront/");
      if (sovereignRoute) {
        const sovereignAccess = await verifySovereignAccess(request, env);
        if (!sovereignAccess.authorized) {
          const response = Response.json({
            error: "Sovereign Access Denied",
            reason: sovereignAccess.tier,
            protocol: "BEEMAX-V1",
          }, { status: 402, headers });
          ctx.waitUntil(auditAccess(env, request, null, response.status));
          return response;
        }
      }

      const telemetry = await telemetryStatsApi(request, env);
      if (telemetry) {
        ctx.waitUntil(auditAccess(env, request, access, telemetry.status));
        headers.forEach((value, key) => telemetry.headers.set(key, value));
        return telemetry;
      }

      if (path === "/api/stream/token") {
        if (request.method !== "GET") {
          const response = Response.json({ error: "Method not allowed" }, { status: 405, headers });
          ctx.waitUntil(auditAccess(env, request, access, response.status));
          return response;
        }
        if (access.role === "Automation") {
          const response = Response.json({ error: "Staff sign-in required" }, { status: 403, headers });
          ctx.waitUntil(auditAccess(env, request, null, response.status));
          return response;
        }
        const response = await streamTokenApi(env);
        headers.forEach((value, key) => response.headers.set(value, key));
        ctx.waitUntil(auditAccess(env, request, access, response.status));
        return response;
      }

      if (path === "/sim/tick" && request.method === "POST") {
        const declaredLength = Number(request.headers.get("Content-Length") ?? 0);
        if (declaredLength > 65_536) return Response.json({ success: false, error: "Payload too large" }, { status: 413, headers });
        const body: unknown = await request.json();
        if (!body || typeof body !== "object" || Array.isArray(body))
          return Response.json({ success: false, error: "Expected a JSON object state" }, { status: 400, headers });
        const tick = createEdgeRuntime(env).simulation.executeTick(body as Record<string, unknown>);
        ctx.waitUntil(auditAccess(env, request, access, 200));
        return Response.json({ success: true, tick }, { headers });
      }
      if (path === "/sim/provenance" && request.method === "GET") {
        return Response.json({ provenance: createEdgeRuntime(env).simulation.getReplayProvenance() }, { headers });
      }

      const compat = path.startsWith("/api/bemax") || path.startsWith("/api/providers") || path.startsWith("/api/governor") || path.startsWith("/api/uss")
        ? await compatibilityApi(request, env) : null;
      const upstream = path === "/api/session" ? Response.json(access)
        : compat ?? (path.startsWith("/api/bemax")
          ? (await bemaxApi(request, env)) ?? (await routeApi(request, env))
          : !path.startsWith("/api/") || path.startsWith("/api/kernel/")
            ? await kernel.fetch(request, env, ctx) : await routeApi(request, env));
      if (request.method !== "GET") ctx.waitUntil(auditAccess(env, request, access, upstream.status));
      const response = new Response(upstream.body, upstream);
      response.headers.delete("Access-Control-Allow-Origin");
      headers.forEach((value, key) => response.headers.set(key, value));
      return response;
    } catch (error) {
      const err = error instanceof Error ? error : new Error(String(error));
      console.error("[portal-os1] worker request failure", {
        method: request.method, url: request.url, bindingNames: Object.keys(env ?? {}),
        message: err.message, stack: err.stack ?? "",
        sql: typeof (error as any)?.cause === "object" && "sql" in ((error as any).cause ?? {}) ? String((error as any).cause.sql) : undefined,
      });
      return Response.json({ error: "Portal data is unavailable" }, { status: 500, headers });
    }
  },
} satisfies ExportedHandler<Env>;
