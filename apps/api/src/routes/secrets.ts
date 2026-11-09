/**
 * Secrets and sensitive files found in repositories (ADR 0049). Read by everyone who sees the repository (ADR 0030); closed or
 * reopened by members and above, with a reason, audited. No value is stored, so none can be returned.
 */
import { SECRET_SEVERITIES } from "@garnetops/core/secrets";
import { activeRepository, repositoryVisibleTo, schema, visibleRepository } from "@garnetops/db";
import { and, count, desc, eq, gt, inArray, sql } from "drizzle-orm";
import { type Context, Hono } from "hono";
import { z } from "zod";
import { db } from "../db.ts";
import { audit } from "../lib/audit.ts";
import { type AppEnv, requireRole } from "../lib/context.ts";
import { notFound, ProblemError } from "../lib/problem.ts";
import { rateLimit } from "../lib/rate-limit.ts";
import { queueScan } from "../lib/scan-queue.ts";

const s = schema.secretFinding;
const r = schema.repository;

export const SECRET_STATES = ["open", "revoked", "dismissed"] as const;
const MAX_ROWS = 500;

const csv = <T extends string>(values: readonly T[]) =>
  z
    .string()
    .optional()
    .transform((text, ctx) => {
      if (!text) return [] as T[];
      const parts = text.split(",").filter(Boolean);
      for (const p of parts) {
        if (!(values as readonly string[]).includes(p)) {
          ctx.addIssue({ code: "custom", message: `Unknown value: ${p}` });
          return z.NEVER;
        }
      }
      return parts as T[];
    });

const listQuery = z.object({
  state: z.enum([...SECRET_STATES, "all"]).default("open"),
  severity: csv(SECRET_SEVERITIES),
  repositoryId: z.string().max(64).optional(),
});

const reasonBody = z.object({
  reason: z
    .string()
    .trim()
    .min(10, "Explain in at least 10 characters")
    .max(1000)
    .transform((t) => t.replace(/[\p{Cc}\p{Cf}]/gu, " ")),
});

function where(actor: { organizationId: string; userId: string }, input: z.infer<typeof listQuery>) {
  return and(
    eq(s.organizationId, actor.organizationId),
    visibleRepository(s.repositoryId, actor),
    // Over the whole organisation, repositories set aside are left out; one repository shows them (ADR 0043).
    input.repositoryId ? eq(s.repositoryId, input.repositoryId) : activeRepository(s.repositoryId),
    input.state === "all" ? undefined : eq(s.state, input.state),
    input.severity.length ? inArray(s.severity, input.severity) : undefined,
  );
}

const listColumns = {
  id: s.id,
  repositoryId: s.repositoryId,
  repositoryName: r.name,
  ruleId: s.ruleId,
  severity: s.severity,
  state: s.state,
  inTree: s.inTree,
  treeLocations: s.treeLocations,
  treeLocationCount: s.treeLocationCount,
  historyLocationCount: s.historyLocationCount,
  firstSeenAt: s.firstSeenAt,
  lastSeenAt: s.lastSeenAt,
};

/** The first place to name in a list: in the files if it is there, else in the history. */
function firstPlace(row: { treeLocations: { path: string; line: number | null }[] }) {
  return row.treeLocations[0] ?? null;
}

export const secretRoutes = new Hono<AppEnv>()
  .get("/", async (c) => {
    const actor = c.get("actor");
    const input = listQuery.parse(c.req.query());
    const rows = await db
      .select(listColumns)
      .from(s)
      .innerJoin(r, eq(r.id, s.repositoryId))
      .where(where(actor, input))
      .orderBy(desc(s.severityRank), desc(s.lastSeenAt), s.id)
      .limit(MAX_ROWS + 1);
    return c.json({
      items: rows.slice(0, MAX_ROWS).map(({ treeLocations, ...row }) => ({
        ...row,
        place: firstPlace({ treeLocations }),
      })),
      more: rows.length > MAX_ROWS,
    });
  })
  /** Counts per state and, for open secrets, per severity: the page's toggles and the menu. */
  .get("/counts", async (c) => {
    const actor = c.get("actor");
    const input = listQuery.parse(c.req.query());
    const rows = await db
      .select({ state: s.state, severity: s.severity, n: count() })
      .from(s)
      .where(where(actor, { ...input, state: "all", severity: [] }))
      .groupBy(s.state, s.severity);
    const states: Record<(typeof SECRET_STATES)[number], number> = { open: 0, revoked: 0, dismissed: 0 };
    const open: Record<string, number> = {};
    for (const row of rows) {
      states[row.state] += row.n;
      if (row.state === "open") open[row.severity] = row.n;
    }
    return c.json({ states, open });
  })
  .get("/:id", async (c) => {
    const actor = c.get("actor");
    const [row] = await db
      .select({ secret: s, repositoryName: r.name, stateByName: schema.user.name })
      .from(s)
      .innerJoin(r, eq(r.id, s.repositoryId))
      .leftJoin(schema.user, eq(schema.user.id, s.stateBy))
      .where(
        and(
          eq(s.id, c.req.param("id")),
          eq(s.organizationId, actor.organizationId),
          visibleRepository(s.repositoryId, actor),
        ),
      )
      .limit(1);
    if (!row) throw notFound("Secret");
    const { secret } = row;
    return c.json({
      id: secret.id,
      repositoryId: secret.repositoryId,
      repositoryName: row.repositoryName,
      ruleId: secret.ruleId,
      severity: secret.severity,
      state: secret.state,
      stateReason: secret.stateReason,
      stateAt: secret.stateAt,
      stateByName: row.stateByName,
      inTree: secret.inTree,
      treeLocations: secret.treeLocations,
      treeLocationCount: secret.treeLocationCount,
      historyLocations: secret.historyLocations,
      historyLocationCount: secret.historyLocationCount,
      firstSeenAt: secret.firstSeenAt,
      lastSeenAt: secret.lastSeenAt,
    });
  })
  .post("/:id/revoke", (c) => close(c, "revoked"))
  .post("/:id/dismiss", (c) => close(c, "dismissed"))
  .post("/:id/reopen", async (c) => {
    const actor = c.get("actor");
    requireRole(actor, "member");
    const id = c.req.param("id");
    const [row] = await db
      .update(s)
      .set({
        state: "open",
        stateReason: null,
        stateBy: actor.userId,
        stateAt: new Date(),
        updatedAt: new Date(),
      })
      .where(
        and(
          eq(s.id, id),
          eq(s.organizationId, actor.organizationId),
          visibleRepository(s.repositoryId, actor),
          sql`${s.state} <> 'open'`,
        ),
      )
      .returning({ id: s.id, repositoryId: s.repositoryId });
    if (!row) throw new ProblemError(409, "not-closed", "Only revoked or dismissed secrets can be reopened");
    await audit(actor, "secret.reopened", { type: "secret", id }, { repositoryId: row.repositoryId });
    return c.json({ ok: true });
  });

async function close(c: Context<AppEnv>, state: "revoked" | "dismissed"): Promise<Response> {
  const actor = c.get("actor");
  requireRole(actor, "member");
  const input = reasonBody.parse(await c.req.json());
  const id = c.req.param("id") as string;
  const now = new Date();
  const [row] = await db
    .update(s)
    .set({ state, stateReason: input.reason, stateBy: actor.userId, stateAt: now, updatedAt: now })
    .where(
      and(
        eq(s.id, id),
        eq(s.organizationId, actor.organizationId),
        visibleRepository(s.repositoryId, actor),
        eq(s.state, "open"),
      ),
    )
    .returning({ id: s.id, repositoryId: s.repositoryId, ruleId: s.ruleId });
  if (!row) throw new ProblemError(409, "not-open", "Only open secrets can be closed");
  await audit(
    actor,
    state === "revoked" ? "secret.revoked" : "secret.dismissed",
    { type: "secret", id },
    {
      repositoryId: row.repositoryId,
      rule: row.ruleId,
    },
  );
  return c.json({ ok: true });
}

const historyBody = z.object({ enabled: z.boolean() });

/** What a repository's Secrets card shows (ADR 0049). */
async function repositorySecrets(repo: typeof r.$inferSelect) {
  const rows = await db
    .select({ severity: s.severity, n: count() })
    .from(s)
    .where(and(eq(s.repositoryId, repo.id), eq(s.state, "open")))
    .groupBy(s.severity);
  const [lastScan] = await db
    .select({ secretScan: schema.scan.secretScan, finishedAt: schema.scan.finishedAt })
    .from(schema.scan)
    .where(
      and(
        eq(schema.scan.repositoryId, repo.id),
        eq(schema.scan.state, "succeeded"),
        sql`${schema.scan.ref} is null`,
      ),
    )
    .orderBy(desc(schema.scan.finishedAt))
    .limit(1);
  return {
    open: Object.fromEntries(rows.map((row) => [row.severity, row.n])),
    lastCheck: lastScan?.secretScan ?? null,
    history: {
      enabled: repo.secretHistoryAt !== null,
      enabledAt: repo.secretHistoryAt,
      checkedAt: repo.secretHistoryCheckedAt,
    },
  };
}

/** Mounted at /repositories/:id/secrets. */
export const repositorySecretRoutes = new Hono<AppEnv>()
  .get("/", async (c) => {
    const actor = c.get("actor");
    const repo = await visibleRepo(actor, c.req.param("id"));
    return c.json(await repositorySecrets(repo));
  })
  /** Check the whole history on every scan: admins, or a member for their own private repository (as ADR 0043). */
  .put("/history", async (c) => {
    const actor = c.get("actor");
    const repo = await visibleRepo(actor, c.req.param("id"));
    if (!(repo.visibility === "private" && repo.ownerUserId === actor.userId)) requireRole(actor, "admin");
    const body = historyBody.parse(await c.req.json());
    if (body.enabled !== (repo.secretHistoryAt !== null)) {
      const now = new Date();
      await db
        .update(r)
        .set({
          secretHistoryAt: body.enabled ? now : null,
          secretHistoryBy: body.enabled ? actor.userId : null,
          updatedAt: now,
        })
        .where(eq(r.id, repo.id));
      await audit(
        actor,
        body.enabled ? "repository.secret_history_enabled" : "repository.secret_history_disabled",
        { type: "repository", id: repo.id },
        { url: repo.url },
      );
    }
    const [after] = await db.select().from(r).where(eq(r.id, repo.id)).limit(1);
    return c.json(await repositorySecrets(after ?? repo));
  })
  /** Check the history once now: members and above, at most once an hour per repository. */
  .post("/history-check", async (c) => {
    const actor = c.get("actor");
    requireRole(actor, "member");
    const repo = await visibleRepo(actor, c.req.param("id"));
    const [active] = await db
      .select({ id: schema.scan.id })
      .from(schema.scan)
      .where(and(eq(schema.scan.repositoryId, repo.id), inArray(schema.scan.state, ["queued", "running"])))
      .limit(1);
    if (active) throw new ProblemError(409, "scan-running", "A scan of this repository is already running");
    const [recent] = await db
      .select({ id: schema.scan.id })
      .from(schema.scan)
      .where(
        and(
          eq(schema.scan.repositoryId, repo.id),
          eq(schema.scan.secretHistory, true),
          gt(schema.scan.createdAt, new Date(Date.now() - 3600_000)),
        ),
      )
      .limit(1);
    if (recent) throw new ProblemError(429, "rate-limited", "The history was checked less than an hour ago");
    await rateLimit(`secret-history:${actor.organizationId}`, 20, 3600_000);
    const scanId = await queueScan(
      actor.organizationId,
      repo.id,
      actor.userId,
      "manual",
      { ref: null, expectedSha: null },
      { secretHistory: true },
    );
    await audit(
      actor,
      "scan.requested",
      { type: "repository", id: repo.id },
      { scanId, secretHistory: true },
    );
    return c.json({ scanId }, 202);
  });

async function visibleRepo(actor: { organizationId: string; userId: string }, id: string | undefined) {
  const [repo] = await db
    .select()
    .from(r)
    .where(and(eq(r.id, id ?? ""), repositoryVisibleTo(actor)))
    .limit(1);
  if (!repo) throw notFound("Repository");
  return repo;
}
