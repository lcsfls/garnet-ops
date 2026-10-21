import { newId } from "@garnetops/core";
import { GATE_DEFAULTS, GATE_MODES, GATE_RULES, type GateRule } from "@garnetops/core/gates";
import { pageSizeSchema } from "@garnetops/core/pagination";
import { schema } from "@garnetops/db";
import { and, count, desc, eq, isNull } from "drizzle-orm";
import { Hono } from "hono";
import { z } from "zod";
import { db } from "../db.ts";
import { audit } from "../lib/audit.ts";
import { type AppEnv, requireRole } from "../lib/context.ts";
import { newGateToken } from "../lib/gate-token.ts";
import { type KeysetSpec, keysetQuery, parseDate, parseText, toPage } from "../lib/paginate.ts";
import { notFound } from "../lib/problem.ts";

const run = schema.gateRun;

const ruleBody = z.object({
  mode: z.enum(GATE_MODES),
  /** Only for "license-denied": SPDX ids, e.g. ["AGPL-3.0-only", "SSPL-1.0"]. */
  deniedLicenses: z
    .array(
      z
        .string()
        .trim()
        .min(1)
        .max(100)
        .regex(/^[A-Za-z0-9.+-]+$/, "Use SPDX licence ids"),
    )
    .max(100)
    .optional(),
});

const runsQuery = z.object({
  cursor: z.string().optional(),
  pageSize: pageSizeSchema,
  repositoryId: z.string().max(40).optional(),
});

type RunRow = { id: string; createdAt: Date } & Record<string, unknown>;
const runSpec: KeysetSpec<RunRow> = {
  keys: [run.createdAt, run.id],
  direction: "desc",
  keyOf: (row) => [row.createdAt, row.id],
  parse: [parseDate, parseText],
};

const tokenBody = z.object({ label: z.string().trim().min(1).max(80) });

async function ownRepository(organizationId: string, id: string) {
  const [row] = await db
    .select({ id: schema.repository.id, name: schema.repository.name })
    .from(schema.repository)
    .where(and(eq(schema.repository.id, id), eq(schema.repository.organizationId, organizationId)))
    .limit(1);
  if (!row) throw notFound("Repository");
  return row;
}

/** Quality gates in the app (ADR 0008): rules, runs and the CI tokens per repository. */
export const gateRoutes = new Hono<AppEnv>()
  /** The rules with their mode for this organisation; missing rows are the documented defaults. */
  .get("/rules", async (c) => {
    const actor = c.get("actor");
    const rows = await db
      .select()
      .from(schema.gateRule)
      .where(eq(schema.gateRule.organizationId, actor.organizationId));
    const stored = new Map(rows.map((r) => [r.rule, r]));
    return c.json(
      GATE_RULES.map((rule) => {
        const row = stored.get(rule);
        return {
          rule,
          mode: row?.mode ?? GATE_DEFAULTS[rule],
          defaultMode: GATE_DEFAULTS[rule],
          deniedLicenses:
            rule === "license-denied"
              ? ((row?.config?.deniedLicenses as string[] | undefined) ?? [])
              : undefined,
          updatedAt: row?.updatedAt ?? null,
        };
      }),
    );
  })
  /** Changing a rule affects the next run only; earlier runs keep their result. */
  .put("/rules/:rule", async (c) => {
    const actor = c.get("actor");
    requireRole(actor, "admin");
    const rule = z.enum(GATE_RULES).parse(c.req.param("rule")) as GateRule;
    const input = ruleBody.parse(await c.req.json());
    const [before] = await db
      .select()
      .from(schema.gateRule)
      .where(and(eq(schema.gateRule.organizationId, actor.organizationId), eq(schema.gateRule.rule, rule)));
    const config =
      rule === "license-denied"
        ? {
            deniedLicenses: [
              ...new Set(input.deniedLicenses ?? (before?.config?.deniedLicenses as string[]) ?? []),
            ],
          }
        : null;
    await db
      .insert(schema.gateRule)
      .values({
        organizationId: actor.organizationId,
        rule,
        mode: input.mode,
        config,
        updatedBy: actor.userId,
      })
      .onConflictDoUpdate({
        target: [schema.gateRule.organizationId, schema.gateRule.rule],
        set: { mode: input.mode, config, updatedBy: actor.userId, updatedAt: new Date() },
      });
    await audit(
      actor,
      "gate.rule_changed",
      { type: "gate_rule", id: rule },
      {
        before: before?.mode ?? GATE_DEFAULTS[rule],
        after: input.mode,
        ...(config ? { deniedLicenses: config.deniedLicenses } : {}),
      },
    );
    return c.body(null, 204);
  })
  .get("/runs", async (c) => {
    const actor = c.get("actor");
    const input = runsQuery.parse(c.req.query());
    const where = and(
      eq(run.organizationId, actor.organizationId),
      input.repositoryId ? eq(run.repositoryId, input.repositoryId) : undefined,
    );
    const q = keysetQuery(runSpec, input.cursor, input.pageSize);
    const [rows, totalRow] = await Promise.all([
      db
        .select({
          id: run.id,
          createdAt: run.createdAt,
          result: run.result,
          matches: run.matches,
          repositoryId: run.repositoryId,
          repositoryName: schema.repository.name,
          scanId: run.scanId,
          trigger: schema.scan.trigger,
          ref: schema.scan.ref,
          branch: schema.scan.branch,
          commitSha: schema.scan.commitSha,
          startedAt: schema.scan.startedAt,
          finishedAt: schema.scan.finishedAt,
        })
        .from(run)
        .innerJoin(schema.repository, eq(schema.repository.id, run.repositoryId))
        .innerJoin(schema.scan, eq(schema.scan.id, run.scanId))
        .where(and(where, q.where))
        .orderBy(...q.orderBy)
        .limit(q.limit),
      db.select({ n: count() }).from(run).where(where),
    ]);
    return c.json(
      toPage(runSpec, q, rows, totalRow[0]?.n ?? 0, input.pageSize, Boolean(input.cursor), (r) => r),
    );
  })
  /** The latest gate result per repository, for the repositories list. */
  .get("/latest", async (c) => {
    const actor = c.get("actor");
    const rows = await db
      .selectDistinctOn([run.repositoryId], {
        repositoryId: run.repositoryId,
        result: run.result,
        createdAt: run.createdAt,
      })
      .from(run)
      .innerJoin(schema.scan, eq(schema.scan.id, run.scanId))
      // The repository's own state: scans of its configured branch, not pull request checks.
      .where(and(eq(run.organizationId, actor.organizationId), isNull(schema.scan.ref)))
      .orderBy(run.repositoryId, desc(run.createdAt));
    return c.json(rows);
  })
  .get("/repositories/:id/tokens", async (c) => {
    const actor = c.get("actor");
    requireRole(actor, "admin");
    const repo = await ownRepository(actor.organizationId, c.req.param("id"));
    const rows = await db
      .select({
        id: schema.gateToken.id,
        label: schema.gateToken.label,
        prefix: schema.gateToken.prefix,
        createdAt: schema.gateToken.createdAt,
        lastUsedAt: schema.gateToken.lastUsedAt,
        createdBy: schema.user.name,
      })
      .from(schema.gateToken)
      .leftJoin(schema.user, eq(schema.user.id, schema.gateToken.createdBy))
      .where(and(eq(schema.gateToken.repositoryId, repo.id), isNull(schema.gateToken.revokedAt)))
      .orderBy(desc(schema.gateToken.createdAt));
    return c.json(rows);
  })
  /** The token is in this answer once; GarnetOps keeps only its hash. */
  .post("/repositories/:id/tokens", async (c) => {
    const actor = c.get("actor");
    requireRole(actor, "admin");
    const repo = await ownRepository(actor.organizationId, c.req.param("id"));
    const input = tokenBody.parse(await c.req.json());
    const { token, hash, prefix } = newGateToken();
    const id = newId("gtok");
    await db.insert(schema.gateToken).values({
      id,
      organizationId: actor.organizationId,
      repositoryId: repo.id,
      tokenHash: hash,
      prefix,
      label: input.label,
      createdBy: actor.userId,
    });
    await audit(
      actor,
      "gate.token_created",
      { type: "repository", id: repo.id },
      { tokenId: id, prefix, label: input.label },
    );
    return c.json({ id, token, prefix, label: input.label }, 201);
  })
  .delete("/repositories/:id/tokens/:tokenId", async (c) => {
    const actor = c.get("actor");
    requireRole(actor, "admin");
    const repo = await ownRepository(actor.organizationId, c.req.param("id"));
    const [row] = await db
      .update(schema.gateToken)
      .set({ revokedAt: new Date() })
      .where(
        and(
          eq(schema.gateToken.id, c.req.param("tokenId")),
          eq(schema.gateToken.repositoryId, repo.id),
          isNull(schema.gateToken.revokedAt),
        ),
      )
      .returning({ prefix: schema.gateToken.prefix });
    if (!row) throw notFound("Token");
    await audit(
      actor,
      "gate.token_revoked",
      { type: "repository", id: repo.id },
      { tokenId: c.req.param("tokenId"), prefix: row.prefix },
    );
    return c.body(null, 204);
  });
