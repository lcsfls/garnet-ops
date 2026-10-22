import { schema } from "@garnetops/db";
import { eq } from "drizzle-orm";
import { Hono } from "hono";
import { db } from "../db.ts";
import type { AppEnv } from "../lib/context.ts";

export const meRoutes = new Hono<AppEnv>().get("/", async (c) => {
  const actor = c.get("actor");
  const [preferences] = await db
    .select({ locale: schema.user.locale, timeZone: schema.user.timeZone })
    .from(schema.user)
    .where(eq(schema.user.id, actor.userId))
    .limit(1);
  const [org] = await db
    .select({
      id: schema.organization.id,
      name: schema.organization.name,
      scanSchedule: {
        enabled: schema.organization.scanScheduleEnabled,
        localTime: schema.organization.scanLocalTime,
        timeZone: schema.organization.scanTimeZone,
      },
    })
    .from(schema.organization)
    .where(eq(schema.organization.id, actor.organizationId))
    .limit(1);
  return c.json({
    user: {
      id: actor.userId,
      name: actor.name,
      email: actor.email,
      // Null: follow this browser (ADR 0017).
      locale: preferences?.locale ?? null,
      timeZone: preferences?.timeZone ?? null,
    },
    organization: org,
    role: actor.role,
  });
});
