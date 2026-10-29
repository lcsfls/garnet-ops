import { isTimeZone, schema } from "@garnetops/db";
import { and, desc, eq, sql } from "drizzle-orm";
import { Hono } from "hono";
import { z } from "zod";
import { db } from "../db.ts";
import { audit } from "../lib/audit.ts";
import { type AppEnv, requireRole } from "../lib/context.ts";
import { MODULES, modulesOf } from "../lib/modules.ts";
import { notFound, ProblemError } from "../lib/problem.ts";

const o = schema.organization;
const moduleBody = z.object({ enabled: z.boolean() });

const scheduleBody = z.object({
  enabled: z.boolean(),
  /** Local wall-clock time, "HH:MM" (24 h). */
  localTime: z.string().regex(/^([01]\d|2[0-3]):[0-5]\d$/, "Use a time between 00:00 and 23:59"),
  timeZone: z.string().max(64).refine(isTimeZone, "Unknown time zone"),
});

async function scheduleOf(organizationId: string) {
  const [row] = await db
    .select({ enabled: o.scanScheduleEnabled, localTime: o.scanLocalTime, timeZone: o.scanTimeZone })
    .from(o)
    .where(eq(o.id, organizationId))
    .limit(1);
  return row;
}

export const organizationRoutes = new Hono<AppEnv>()
  .get("/", async (c) => {
    const { organizationId } = c.get("actor");
    const [org] = await db
      .select({ id: o.id, name: o.name })
      .from(o)
      .where(eq(o.id, organizationId))
      .limit(1);
    if (!org) throw notFound("Organisation");
    const lastRuns = await db
      .select({
        localDate: schema.scanScheduleRun.localDate,
        queuedScans: schema.scanScheduleRun.queuedScans,
        createdAt: schema.scanScheduleRun.createdAt,
      })
      .from(schema.scanScheduleRun)
      .where(eq(schema.scanScheduleRun.organizationId, organizationId))
      .orderBy(desc(schema.scanScheduleRun.localDate))
      .limit(7);
    return c.json({ ...org, scanSchedule: await scheduleOf(organizationId), lastRuns });
  })
  .put("/scan-schedule", async (c) => {
    const actor = c.get("actor");
    requireRole(actor, "admin");
    const input = scheduleBody.parse(await c.req.json());

    // The runtime and PostgreSQL ship separate zone data; a zone only one of them knows
    // would make the nightly run skip this organisation silently (ADR 0005).
    const known = await db.execute(
      sql`select 1 from pg_timezone_names where name = ${input.timeZone} limit 1`,
    );
    if (known.rows.length === 0) {
      throw new ProblemError(422, "unsupported-time-zone", "The database does not know this time zone");
    }

    const before = await scheduleOf(actor.organizationId);
    const localTime = `${input.localTime}:00`;
    await db
      .update(o)
      .set({ scanScheduleEnabled: input.enabled, scanLocalTime: localTime, scanTimeZone: input.timeZone })
      .where(eq(o.id, actor.organizationId));
    await audit(
      actor,
      "organization.scan_schedule_changed",
      { type: "organization", id: actor.organizationId },
      { before, after: { enabled: input.enabled, localTime, timeZone: input.timeZone } },
    );
    return c.json({ scanSchedule: await scheduleOf(actor.organizationId) });
  })
  /** The modules an organisation switches on (ADR 0033). */
  .get("/modules", async (c) => c.json(await modulesOf(c.get("actor").organizationId)))
  .put("/modules/:name", async (c) => {
    const actor = c.get("actor");
    requireRole(actor, "admin");
    const name = MODULES.find((m) => m === c.req.param("name"));
    if (!name) throw notFound("Module");
    const input = moduleBody.parse(await c.req.json());
    if ((await modulesOf(actor.organizationId))[name] === input.enabled) {
      return c.json(await modulesOf(actor.organizationId));
    }
    const now = new Date();
    const s = schema.exposureSettings;
    const a = schema.exposureAsset;
    await db.transaction(async (tx) => {
      const set = { enabled: input.enabled, enabledBy: actor.userId, enabledAt: now, updatedAt: now };
      await tx
        .insert(s)
        .values({ organizationId: actor.organizationId, ...set })
        .onConflictDoUpdate({ target: s.organizationId, set });
      // Switching off also switches stage 2 off and voids its acknowledgements: switching on again starts from a safe state.
      if (!input.enabled) {
        await tx
          .update(a)
          .set({
            stage2Enabled: false,
            stage2AcknowledgedBy: null,
            stage2AcknowledgedAt: null,
            updatedAt: now,
          })
          .where(and(eq(a.organizationId, actor.organizationId), eq(a.stage2Enabled, true)));
        await tx
          .update(schema.exposureRun)
          .set({ state: "failed", error: "moduleOff", finishedAt: now })
          .where(
            and(
              eq(schema.exposureRun.organizationId, actor.organizationId),
              eq(schema.exposureRun.state, "queued"),
            ),
          );
      }
    });
    await audit(
      actor,
      input.enabled ? "organization.module_enabled" : "organization.module_disabled",
      { type: "organization", id: actor.organizationId },
      { module: name },
    );
    return c.json(await modulesOf(actor.organizationId));
  });
