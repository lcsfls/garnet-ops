/**
 * "Getting started" on the overview: how far this organisation is with its setup, read from what is actually there, so the
 * checklist ticks itself off and never needs to be maintained. Owners and admins only; counts, no names or addresses.
 */
import { vulnDbReportSchema } from "@garnetops/core/system-status";
import { schema } from "@garnetops/db";
import { and, count, eq, isNull, type SQL } from "drizzle-orm";
import type { PgTable } from "drizzle-orm/pg-core";
import { Hono } from "hono";
import { db } from "../db.ts";
import { type AppEnv, requireRole } from "../lib/context.ts";

export const SETUP_STEPS = [
  "forge",
  "repositories",
  "scanOnPush",
  "notifications",
  "vulnDb",
  "ciGate",
] as const;
export type SetupStep = (typeof SETUP_STEPS)[number];

export const setupProgressRoutes = new Hono<AppEnv>().get("/", async (c) => {
  const actor = c.get("actor");
  requireRole(actor, "admin");
  const org = actor.organizationId;
  const one = async (table: PgTable, where: SQL | undefined) =>
    Number((await db.select({ n: count() }).from(table).where(where))[0]?.n ?? 0);

  const [forge, repositories, webhooks, channels, gateTokens, vulndb] = await Promise.all([
    one(schema.forgeConnection, eq(schema.forgeConnection.organizationId, org)),
    one(
      schema.repository,
      and(eq(schema.repository.organizationId, org), isNull(schema.repository.inactiveAt)),
    ),
    one(schema.repositoryWebhook, eq(schema.repositoryWebhook.organizationId, org)),
    one(schema.notificationChannel, eq(schema.notificationChannel.organizationId, org)),
    one(schema.gateToken, and(eq(schema.gateToken.organizationId, org), isNull(schema.gateToken.revokedAt))),
    db
      .select({ data: schema.systemReport.data })
      .from(schema.systemReport)
      .where(eq(schema.systemReport.key, "vulndb")),
  ]);
  const report = vulnDbReportSchema.safeParse(vulndb[0]?.data);
  const steps: { id: SetupStep; done: boolean; count?: number; total?: number }[] = [
    { id: "forge", done: forge > 0, count: forge },
    { id: "repositories", done: repositories > 0, count: repositories },
    { id: "scanOnPush", done: webhooks > 0, count: webhooks, total: repositories },
    { id: "notifications", done: channels > 0, count: channels },
    { id: "vulnDb", done: report.success && report.data.valid },
    { id: "ciGate", done: gateTokens > 0, count: gateTokens },
  ];
  c.header("cache-control", "no-store");
  return c.json({ steps, done: steps.filter((s) => s.done).length, total: steps.length });
});
