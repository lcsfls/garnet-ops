import { Hono } from "hono";
import { env } from "../env.ts";
import { type AppEnv, requireRole } from "../lib/context.ts";
import { buildSystemStatus, type UpdaterFacts } from "../lib/system-status.ts";
import { updater } from "../updater/client.ts";
import { APP_VERSION } from "../version.ts";

/** What the update sidecar says, if one is set up and answers. Never throws: a sidecar that is down is a fact, not an error. */
async function updaterFacts(): Promise<UpdaterFacts> {
  const configured = Boolean(env.UPDATER_URL);
  if (!configured) return { configured, phase: null, latestAvailable: null };
  const state = await updater.state().catch(() => null);
  return {
    configured,
    phase: state?.phase ?? null,
    latestAvailable: state?.updater.latestAvailable ?? null,
  };
}

export const systemRoutes = new Hono<AppEnv>()
  /** Facts about this installation that every signed-in user may see. */
  .get("/", (c) => c.json({ version: APP_VERSION }))
  /**
   * Is everything current and running? One read-only view for owners and admins (ADR 0024):
   * scanners, the vulnerability database, the integrations, the worker and its queues,
   * the database and the app. Numbers, states and short codes only; nothing here runs a binary
   * or contacts an integration, it reads what the worker has reported.
   */
  .get("/status", async (c) => {
    requireRole(c.get("actor"), "admin");
    const status = await buildSystemStatus(c.get("actor").organizationId, await updaterFacts());
    return c.json(status, 200, { "cache-control": "no-store" });
  });
