import {
  DEFAULT_LEAD_TIMES,
  maintenanceViewOf,
  type StateView,
  UpdaterProblemError,
  UpdaterUnavailableError,
} from "@restow-backup/cicd-updater";
import { isPlainVersion } from "@restow-backup/cicd-updater/semver";
import { type Context, Hono } from "hono";
import type { ContentfulStatusCode } from "hono/utils/http-status";
import { z } from "zod";
import { audit } from "../lib/audit.ts";
import { type Actor, type AppEnv, isAdmin } from "../lib/context.ts";
import { forbidden, ProblemError } from "../lib/problem.ts";
import { updater } from "../updater/client.ts";

/**
 * In-app updates through the optional cicd-updater sidecar (ADR 0007).
 *
 * The sidecar trusts whoever holds its token, so this file decides who may act:
 * owners and admins only, and scheduling also needs a sign-in (password and TOTP) from
 * the last ten minutes. Accepted actions are journaled by the sidecar itself and copied
 * into the audit log exactly once (updater/journal.ts); this file audits only what was
 * denied or refused, which the sidecar never sees.
 */

/** How recent the sign-in must be to schedule an update. */
export const STEP_UP_MAX_AGE_SECONDS = 10 * 60;
const RUN_ID = /^[A-Za-z0-9_-]{1,64}$/;

const scheduleBody = z.object({
  version: z.string().max(64).refine(isPlainVersion, "Not a release version"),
  /** Seconds from now; the sidecar enforces its own maximum. */
  leadSeconds: z
    .number()
    .int()
    .min(0)
    .max(7 * 24 * 3600),
  /** The release document the admin was shown: what they saw is what gets installed. */
  releaseSha256: z.string().regex(/^[0-9a-f]{64}$/),
});

type Request = "schedule" | "cancel" | "acknowledge";

/** What the sidecar records as the requester: our user id and the email an auditor recognises. */
const requestedBy = (actor: Actor) => ({ id: actor.userId.slice(0, 200), label: actor.email.slice(0, 200) });

async function auditAttempt(
  actor: Actor,
  request: Request,
  outcome: "denied" | "refused" | "failed",
  code: string,
  target: string | null,
) {
  await audit(actor, "update.request_refused", target ? { type: "update", id: target } : undefined, {
    request,
    outcome,
    code,
  });
}

function requireUpdateAdmin(actor: Actor): void {
  if (!isAdmin(actor)) throw forbidden("Only owners and admins manage updates");
}

/** Sidecar answers keep their status and code, so the web app can explain them. */
function toProblem(error: unknown): unknown {
  if (error instanceof UpdaterProblemError) {
    const { blockers, reasons, errors, feedError } = error.problem as typeof error.problem & {
      feedError?: string;
    };
    return new ProblemError(
      error.status as ContentfulStatusCode,
      `updater/${error.code}`,
      error.problem.title,
      undefined,
      { blockers, reasons, errors, feedError },
    );
  }
  if (error instanceof UpdaterUnavailableError) {
    return new ProblemError(
      503,
      "updater/updater_unavailable",
      "The update service does not answer",
      undefined,
      {
        reason: error.reason,
      },
    );
  }
  return error;
}

/** Runs an update action; denied, refused or failed attempts go into the audit log. */
async function act(
  c: Context<AppEnv>,
  request: Request,
  target: string | null,
  options: { stepUp: boolean },
  run: (actor: Actor) => Promise<StateView>,
  status: ContentfulStatusCode,
) {
  const actor = c.get("actor");
  if (!isAdmin(actor)) {
    await auditAttempt(actor, request, "denied", "forbidden", target);
    throw forbidden("Only owners and admins manage updates");
  }
  if (options.stepUp && Date.now() - actor.strongAuthAt.getTime() > STEP_UP_MAX_AGE_SECONDS * 1000) {
    await auditAttempt(actor, request, "denied", "step_up_required", target);
    throw new ProblemError(403, "step-up-required", "Sign in again to confirm it is you", undefined, {
      maxAgeSeconds: STEP_UP_MAX_AGE_SECONDS,
    });
  }
  try {
    return c.json(await run(actor), status, { "cache-control": "no-store" });
  } catch (error) {
    if (error instanceof UpdaterProblemError)
      await auditAttempt(actor, request, "refused", error.code, target);
    else if (error instanceof UpdaterUnavailableError) {
      await auditAttempt(actor, request, "failed", "updater_unavailable", target);
    }
    throw toProblem(error);
  }
}

/** The maintenance banner, for every signed-in user. Never the full state: that is for admins. */
export const maintenanceRoutes = new Hono<AppEnv>().get("/", async (c) =>
  c.json(maintenanceViewOf(await updater.state().catch(() => null)), 200, { "cache-control": "no-store" }),
);

export const updateRoutes = new Hono<AppEnv>()
  // Actions take JSON only: a cross-site form cannot send it without a CORS preflight.
  // The same-origin check in app.ts applies as well.
  .use("*", async (c, next) => {
    if (c.req.method === "POST" && !/^application\/json\b/i.test(c.req.header("content-type") ?? "")) {
      throw new ProblemError(415, "unsupported-media-type", "Send the request as JSON");
    }
    await next();
  })
  .get("/", async (c) => {
    requireUpdateAdmin(c.get("actor"));
    const state = await updater.state({ fresh: true }).catch((error) => {
      throw toProblem(error);
    });
    return c.json(
      { state, leadTimes: DEFAULT_LEAD_TIMES, stepUpMaxAgeSeconds: STEP_UP_MAX_AGE_SECONDS },
      200,
      { "cache-control": "no-store" },
    );
  })
  .get("/releases", async (c) => {
    requireUpdateAdmin(c.get("actor"));
    // Slow: the sidecar asks the release host (up to two minutes).
    const releases = await updater.releases({ refresh: c.req.query("refresh") === "1" }).catch((error) => {
      throw toProblem(error);
    });
    return c.json(releases, 200, { "cache-control": "no-store" });
  })
  .post("/", async (c) => {
    // Validated after the permission check, so a viewer's attempt is audited as denied.
    const raw: unknown = await c.req.json().catch(() => null);
    const target =
      typeof (raw as { version?: unknown })?.version === "string"
        ? (raw as { version: string }).version.slice(0, 64)
        : null;
    return act(
      c,
      "schedule",
      target,
      { stepUp: true },
      (actor) => {
        const input = scheduleBody.parse(raw);
        return updater.schedule({
          version: input.version,
          leadSeconds: input.leadSeconds,
          requestedBy: requestedBy(actor),
          expect: { releaseSha256: input.releaseSha256 },
        });
      },
      202,
    );
  })
  .post("/:runId/cancel", async (c) => {
    const runId = c.req.param("runId");
    return act(
      c,
      "cancel",
      runId.slice(0, 64),
      { stepUp: false },
      (actor) => {
        if (!RUN_ID.test(runId)) throw new ProblemError(404, "not-found", "Run not found");
        return updater.cancel(runId, requestedBy(actor));
      },
      200,
    );
  })
  .post("/:runId/acknowledge", async (c) => {
    const runId = c.req.param("runId");
    return act(
      c,
      "acknowledge",
      runId.slice(0, 64),
      { stepUp: false },
      (actor) => {
        if (!RUN_ID.test(runId)) throw new ProblemError(404, "not-found", "Run not found");
        return updater.acknowledge(runId, requestedBy(actor));
      },
      200,
    );
  });
