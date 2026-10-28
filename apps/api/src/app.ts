import { createTokenVerifier } from "@restow-backup/cicd-updater/auth";
import { Hono } from "hono";
import { createMiddleware } from "hono/factory";
import { secureHeaders } from "hono/secure-headers";
import { auth } from "./auth.ts";
import { pool } from "./db.ts";
import { env } from "./env.ts";
import { requestBodyLimit } from "./lib/body-limit.ts";
import { type AppEnv, requireActor } from "./lib/context.ts";
import { handleError, ProblemError } from "./lib/problem.ts";
import { accountRoutes } from "./routes/account.ts";
import { aiRoutes } from "./routes/ai.ts";
import { auditRoutes } from "./routes/audit.ts";
import { directoryRoutes } from "./routes/directory.ts";
import { findingRoutes } from "./routes/findings.ts";
import { fixRoutes } from "./routes/fixes.ts";
import { gateCiRoutes } from "./routes/gate-ci.ts";
import { gateRoutes } from "./routes/gates.ts";
import { invitationRoutes } from "./routes/invitations.ts";
import { meRoutes } from "./routes/me.ts";
import { notificationRoutes } from "./routes/notifications.ts";
import { organizationRoutes } from "./routes/organization.ts";
import { overviewRoutes } from "./routes/overview.ts";
import { packageRoutes } from "./routes/packages.ts";
import { repositoryRoutes } from "./routes/repositories.ts";
import { scanRoutes } from "./routes/scans.ts";
import { searchRoutes } from "./routes/search.ts";
import { setupRoutes } from "./routes/setup.ts";
import { signInOptionsRoutes } from "./routes/sign-in-options.ts";
import { systemRoutes } from "./routes/system.ts";
import { teamRoutes } from "./routes/team.ts";
import { maintenanceRoutes, updateRoutes } from "./routes/updates.ts";
import { userNotificationRoutes } from "./routes/user-notifications.ts";
import { APP_VERSION } from "./version.ts";

const publicOrigin = new URL(env.PUBLIC_URL).origin;

/** Recognises the update sidecar by its shared token (ADR 0007). */
const updaterToken = createTokenVerifier({ tokenFile: env.UPDATER_TOKEN_FILE });

/**
 * CSRF defence for cookie-authenticated requests: every state-changing request
 * must come from our own origin. Browsers always send Origin on such requests.
 */
const sameOrigin = createMiddleware(async (c, next) => {
  if (!["GET", "HEAD", "OPTIONS"].includes(c.req.method)) {
    const origin = c.req.header("origin");
    if (origin !== publicOrigin) throw new ProblemError(403, "cross-origin", "Cross-origin request refused");
  }
  await next();
});

export const app = new Hono()
  .onError(handleError)
  .use(
    "*",
    secureHeaders({
      contentSecurityPolicy: { defaultSrc: ["'none'"], frameAncestors: ["'none'"] },
      crossOriginResourcePolicy: "same-origin",
      referrerPolicy: "no-referrer",
      strictTransportSecurity: "max-age=63072000; includeSubDomains",
    }),
  )
  .use("*", requestBodyLimit)
  .get("/api/health", (c) => c.json({ ok: true }))
  /**
   * Readiness for the container health check and the update sidecar: 200 once the
   * database answers, 503 before. The version only for the sidecar's token: a public
   * version number would tell an attacker which known vulnerability is still open.
   */
  .get("/api/healthz", async (c) => {
    const ready = await pool.query("select 1").then(
      () => true,
      () => false,
    );
    const version = (await updaterToken.isUpdater(c.req.header("authorization")))
      ? { version: APP_VERSION }
      : {};
    return c.json({ status: ready ? "ok" : "starting", ...version }, ready ? 200 : 503, {
      "cache-control": "no-store",
    });
  })
  .use("/api/auth/*", sameOrigin)
  .on(["GET", "POST"], "/api/auth/*", (c) => auth.handler(c.req.raw))
  /**
   * The gate API for CI (ADR 0008): bearer gate token only, no cookies, so it is
   * registered before the same-origin check and the session middleware and answers
   * on its own.
   */
  .route("/api/v1/gate", gateCiRoutes)
  .use("/api/v1/*", sameOrigin)
  .route("/api/v1/setup", setupRoutes)
  // The sign-in page asks what it may offer (the directory) before anyone is signed in (ADR 0020).
  .route("/api/v1/sign-in-options", signInOptionsRoutes)
  // Accepting an invitation happens before the person has an account (ADR 0009).
  .route("/api/v1/invitations", invitationRoutes);

const v1 = new Hono<AppEnv>()
  .use("*", requireActor)
  .route("/me", meRoutes)
  .route("/me", userNotificationRoutes)
  .route("/account", accountRoutes)
  .route("/overview", overviewRoutes)
  .route("/repositories", repositoryRoutes)
  .route("/scans", scanRoutes)
  .route("/search", searchRoutes)
  .route("/findings", findingRoutes)
  .route("/fixes", fixRoutes)
  .route("/ai", aiRoutes)
  .route("/gates", gateRoutes)
  .route("/packages", packageRoutes)
  .route("/organization", organizationRoutes)
  .route("/audit-log", auditRoutes)
  .route("/system", systemRoutes)
  .route("/team", teamRoutes)
  .route("/directory", directoryRoutes)
  .route("/notifications", notificationRoutes)
  .route("/maintenance", maintenanceRoutes)
  .route("/updates", updateRoutes);

app.route("/api/v1", v1);
app.notFound((c) => c.json({ type: "about:blank", title: "Not found", status: 404 }, 404));
