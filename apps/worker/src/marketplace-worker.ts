import type { Env } from "./types";
import { marketplaceApi, reconcilePayments } from "./marketplace";
import { handleWardrobeCheckout } from "./wardrobe-checkout";
import { verifySovereignRequest } from "./auth-middleware";
import {
  grantFromRequest,
  resolveMarketplaceDownloadGrant,
} from "./marketplace-downloads";
export { InstantSpaceDurableObject } from "./InstantSpaceDurableObject";
export { MicrokernelProcessActor } from "./kernel";
export { ProductFactoryActor } from "./factory";

function allowedOrigins(env: Env) {
  return new Set(
    (env.MARKETPLACE_ORIGIN ?? "")
      .split(",")
      .map((origin) => origin.trim())
      .filter(Boolean),
  );
}

export default {
  async scheduled(
    _event: ScheduledController,
    env: Env,
    ctx: ExecutionContext,
  ) {
    ctx.waitUntil(reconcilePayments(env));
  },
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    const origin = request.headers.get("Origin");
    const allowed = allowedOrigins(env);
    const headers = new Headers({
      "Cache-Control": "no-store",
      Vary: "Origin",
      "X-Content-Type-Options": "nosniff",
    });
    if (origin && allowed.has(origin)) {
      headers.set("Access-Control-Allow-Origin", origin);
      headers.set("Access-Control-Allow-Credentials", "true");
      headers.set("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
      headers.set(
        "Access-Control-Allow-Headers",
        "Content-Type, X-QAL-Identity, X-QAL-Timestamp, X-QAL-Request-Id, X-QAL-Signature",
      );
    }
    if (
      (origin && !allowed.has(origin)) ||
      (request.method === "POST" && (!origin || !allowed.has(origin)))
    )
      return Response.json(
        { error: "Origin not allowed. Add this exact Pages origin to MARKETPLACE_ORIGIN." },
        { status: 403, headers },
      );
    if (request.method === "OPTIONS")
      return new Response(null, { status: 204, headers });
    if (!url.pathname.startsWith("/api/"))
      return Response.json({ error: "Not found" }, { status: 404, headers });

    try {
      if (url.pathname === "/api/health" && request.method === "GET") {
        return Response.json({ status: "ONLINE", node: "JFK-EDGE" }, { headers });
      }

      const protectedRoute =
        url.pathname.startsWith("/api/storefront/") ||
        url.pathname.startsWith("/api/manifold/");
      if (protectedRoute) {
        const authError = await verifySovereignRequest(request, env);
        if (authError) {
          headers.forEach((value, key) => authError.headers.set(key, value));
          return authError;
        }
      }

      let response: Response;
      if (url.pathname === "/api/wardrobe/checkout") {
        response = await handleWardrobeCheckout(request, env);
      } else if (url.pathname === "/api/manifold/hud" && request.method === "GET") {
        response = Response.json({
          status: "SECURE",
          telemetry: "Marketplace edge request authenticated.",
        });
      } else if (
        url.pathname === "/api/storefront/acquire" &&
        request.method === "POST"
      ) {
        // Forward acquisition to the existing order flow, which still requires
        // the customer session and performs payment/order checks server-side.
        const orderUrl = new URL("/api/orders", url);
        response = await marketplaceApi(new Request(orderUrl, request), env);
      } else if (url.pathname === "/api/downloads/resolve") {
        response = await resolveMarketplaceDownloadGrant(request, env);
      } else if (
        url.pathname === "/api/downloads" &&
        request.method === "POST" &&
        env.DOWNLOADS_SECRET
      ) {
        response = await grantFromRequest(request, env);
      } else if (
        url.pathname === "/api/downloads/grant" &&
        request.method === "POST"
      ) {
        response = await grantFromRequest(request, env);
      } else {
        response = await marketplaceApi(request, env);
      }
      headers.forEach((value, key) => response.headers.set(key, value));
      return response;
    } catch (error) {
      const malformed =
        error instanceof SyntaxError ||
        (error instanceof Error &&
          ["Expected a JSON object", "Request is too large", "Signed request body is too large"].includes(
            error.message,
          ));
      return Response.json(
        {
          error: malformed
            ? "Invalid request body"
            : "Marketplace service is temporarily unavailable",
        },
        { status: malformed ? 400 : 503, headers },
      );
    }
  },
} satisfies ExportedHandler<Env>;
