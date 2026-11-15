/**
 * Deprecated and yanked packages (ADR 0051): the module's settings (own registries, names that never leave), a repository's
 * deprecated and yanked packages, and "check now". The registries are asked by the worker only.
 */
import {
  cleanRegistryUrl,
  DEFAULT_REGISTRIES,
  DEPRECATION_ECOSYSTEMS,
  DEPRECATION_LIMITS,
  type DeprecationEcosystem,
  excludedEntryProblem,
} from "@garnetops/core/deprecated";
import { deprecationView, packageStatusMatch, repositoryVisibleTo, schema } from "@garnetops/db";
import { and, eq, sql } from "drizzle-orm";
import { Hono } from "hono";
import { z } from "zod";
import { boss, db, QUEUES } from "../db.ts";
import { audit } from "../lib/audit.ts";
import { type AppEnv, requireRole } from "../lib/context.ts";
import { requireModule } from "../lib/modules.ts";
import { notFound } from "../lib/problem.ts";
import { rateLimit } from "../lib/rate-limit.ts";
import { requireRecentSignIn } from "../lib/step-up.ts";

const d = schema.deprecationSettings;

const registry = z
  .string()
  .nullish()
  .transform((v, ctx) => {
    if (!v?.trim()) return null;
    const clean = cleanRegistryUrl(v);
    if ("problem" in clean) {
      ctx.addIssue({
        code: "custom",
        message: "An https:// address without user, password, query or fragment",
      });
      return z.NEVER;
    }
    return clean.url;
  });

const settingsBody = z.object({
  registries: z.object({ npm: registry, pypi: registry, crates: registry }),
  excluded: z
    .array(z.string().trim())
    .max(DEPRECATION_LIMITS.maxExcluded)
    .transform((list) => [...new Set(list.filter(Boolean))])
    .refine((list) => list.every((e) => excludedEntryProblem(e) === null), {
      message: "An npm scope (@acme) or a name pattern (acme-*) that does not match everything",
    }),
});

async function settingsOf(organizationId: string) {
  const [row] = await db.select().from(d).where(eq(d.organizationId, organizationId)).limit(1);
  return {
    enabled: row?.enabled === true,
    registries: Object.fromEntries(
      DEPRECATION_ECOSYSTEMS.map((e) => [e, row?.registries?.[e] ?? null]),
    ) as Record<DeprecationEcosystem, string | null>,
    defaults: DEFAULT_REGISTRIES,
    excluded: row?.excluded ?? [],
    lastRun: row?.lastRun ?? null,
  };
}

export const deprecatedRoutes = new Hono<AppEnv>()
  /** The settings, for everyone in the organisation: which registries are asked and which names never leave. */
  .get("/settings", async (c) => c.json(await settingsOf(c.get("actor").organizationId)))
  /** Admins, with a recent sign-in: these decide what leaves the network. */
  .put("/settings", async (c) => {
    const actor = c.get("actor");
    requireRole(actor, "admin");
    requireRecentSignIn(actor);
    const input = settingsBody.parse(await c.req.json());
    const before = await settingsOf(actor.organizationId);
    const now = new Date();
    await db.transaction(async (tx) => {
      await tx
        .insert(d)
        .values({
          organizationId: actor.organizationId,
          registries: input.registries,
          excluded: input.excluded,
        })
        .onConflictDoUpdate({
          target: d.organizationId,
          set: { registries: input.registries, excluded: input.excluded, updatedAt: now },
        });
      // Another registry may answer differently: what the old own registry said is forgotten.
      if (DEPRECATION_ECOSYSTEMS.some((e) => before.registries[e] !== input.registries[e])) {
        await tx.delete(schema.packageStatus).where(eq(schema.packageStatus.scope, actor.organizationId));
      }
    });
    await audit(
      actor,
      "deprecated.settings_changed",
      { type: "organization", id: actor.organizationId },
      {
        registries: Object.fromEntries(
          DEPRECATION_ECOSYSTEMS.map((e) => [
            e,
            input.registries[e] ? new URL(input.registries[e] as string).host : null,
          ]),
        ),
        excluded: input.excluded,
      },
    );
    return c.json(await settingsOf(actor.organizationId));
  })
  /** Ask the registries now (members and above, once every ten minutes per organisation). */
  .post("/check", requireModule("deprecated"), async (c) => {
    const actor = c.get("actor");
    requireRole(actor, "member");
    await rateLimit(`deprecated:check:${actor.organizationId}`, 1, 10 * 60_000);
    await boss.send(
      QUEUES.deprecatedCheck,
      { organizationId: actor.organizationId },
      { retryLimit: 0, expireInSeconds: 1800, singletonKey: actor.organizationId },
    );
    return c.json({ queued: true }, 202);
  })
  /** A repository's deprecated and yanked packages, with the registry's message. */
  .get("/repositories/:id", requireModule("deprecated"), async (c) => {
    const actor = c.get("actor");
    const [repo] = await db
      .select({ id: schema.repository.id })
      .from(schema.repository)
      .where(and(eq(schema.repository.id, c.req.param("id")), repositoryVisibleTo(actor)))
      .limit(1);
    if (!repo) throw notFound("Repository");
    const view = await deprecationView(db, actor.organizationId);
    const p = schema.repositoryPackage;
    const s = schema.packageStatus;
    const rows = await db
      .select({
        name: p.name,
        version: p.version,
        type: p.type,
        state: s.state,
        message: s.message,
        checkedAt: s.checkedAt,
      })
      .from(p)
      .innerJoin(s, packageStatusMatch(view, { type: p.type, name: p.name, version: p.version }))
      .where(and(eq(p.repositoryId, repo.id), sql`${s.state} in ('deprecated', 'yanked')`))
      .orderBy(p.name, p.version)
      .limit(500);
    const [settings] = await db
      .select({ lastRun: d.lastRun })
      .from(d)
      .where(eq(d.organizationId, actor.organizationId));
    return c.json({ items: rows, lastRun: settings?.lastRun ?? null });
  });
