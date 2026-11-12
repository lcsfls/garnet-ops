/**
 * Secrets and sensitive files found in repositories (ADR 0049). Read by everyone who sees the repository (ADR 0030); closed or
 * reopened by members and above, with a reason, audited. No value is stored, so none can be returned.
 */
import { newId } from "@garnetops/core";
import { IGNORE_PATTERN_MAX, ignorePatternProblem, SECRET_SEVERITIES } from "@garnetops/core/secrets";
import {
  activeRepository,
  applySecretIgnoreRules,
  isTimeZone,
  repositoryVisibleTo,
  schema,
  visibleRepository,
} from "@garnetops/db";
import { LANGUAGES, resources } from "@garnetops/i18n";
import { and, count, desc, eq, gt, ilike, inArray, isNull, or, sql } from "drizzle-orm";
import { type Context, Hono } from "hono";
import { z } from "zod";
import { db } from "../db.ts";
import { toCsv } from "../export/csv.ts";
import {
  CONTENT_TYPES,
  EXPORT_FORMATS,
  type ExportFormat,
  exportFileName,
  fill,
} from "../export/findings-report.ts";
import { toPdf } from "../export/pdf.ts";
import { secretsReport } from "../export/secrets-report.ts";
import { toText } from "../export/txt.ts";
import { toXlsx } from "../export/xlsx.ts";
import { audit } from "../lib/audit.ts";
import { type AppEnv, requireRole } from "../lib/context.ts";
import { notFound, ProblemError } from "../lib/problem.ts";
import { rateLimit } from "../lib/rate-limit.ts";
import { queueScan } from "../lib/scan-queue.ts";
import { requireRecentSignIn } from "../lib/step-up.ts";

const s = schema.secretFinding;
const ir = schema.secretIgnoreRule;
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
  /** "open" leaves out what an ignore rule sets aside; "ignored" lists exactly that (ADR 0049 addendum). */
  state: z.enum([...SECRET_STATES, "ignored", "all"]).default("open"),
  severity: csv(SECRET_SEVERITIES),
  repositoryId: z.string().max(64).optional(),
  /** Part of the rule id or of a path where it was found (0.1.5). */
  q: z.string().trim().max(120).optional(),
});

/**
 * The list as it is filtered, as a file (CSV, XLSX, PDF or text), like the findings export. The browser sends its zone (dates in
 * the file) and UI language (column names). Never a value: there is none to export.
 */
const exportQuery = listQuery.extend({
  format: z.enum(EXPORT_FORMATS),
  lang: z.enum(LANGUAGES).default("en"),
  tz: z.string().max(64).refine(isTimeZone, "Unknown time zone").default("UTC"),
});
const MAX_EXPORT_ROWS: Record<ExportFormat, number> = { csv: 50_000, xlsx: 50_000, txt: 50_000, pdf: 5_000 };
const WRITERS = { csv: toCsv, xlsx: toXlsx, pdf: toPdf, txt: toText } as const;

const reasonBody = z.object({
  reason: z
    .string()
    .trim()
    .min(10, "Explain in at least 10 characters")
    .max(1000)
    .transform((t) => t.replace(/[\p{Cc}\p{Cf}]/gu, " ")),
});

/**
 * Set aside: by an ignore rule (ADR 0049 addendum) or by the repository's own gitleaks configuration (addendum 2026-11-12). Not
 * counted, not in the gate, not notified; listed under "Ignored".
 */
const setAside = sql`(${s.ignoredBy} is not null or ${s.setAsideByRepository})`;
const notSetAside = sql`(${s.ignoredBy} is null and not ${s.setAsideByRepository})`;

function where(actor: { organizationId: string; userId: string }, input: z.infer<typeof listQuery>) {
  const like = input.q ? `%${input.q.replace(/[%_\\]/g, "\\$&")}%` : null;
  const inPlaces = (column: typeof s.treeLocations | typeof s.historyLocations) =>
    sql`exists (select 1 from jsonb_array_elements(${column}) as place where place->>'path' ilike ${like})`;
  return and(
    eq(s.organizationId, actor.organizationId),
    visibleRepository(s.repositoryId, actor),
    // Over the whole organisation, repositories set aside are left out; one repository shows them (ADR 0043).
    input.repositoryId ? eq(s.repositoryId, input.repositoryId) : activeRepository(s.repositoryId),
    input.state === "all"
      ? undefined
      : input.state === "open"
        ? and(eq(s.state, "open"), notSetAside)
        : input.state === "ignored"
          ? and(eq(s.state, "open"), setAside)
          : eq(s.state, input.state),
    input.severity.length ? inArray(s.severity, input.severity) : undefined,
    like ? or(ilike(s.ruleId, like), inPlaces(s.treeLocations), inPlaces(s.historyLocations)) : undefined,
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
  ignoredBy: s.ignoredBy,
  setAsideByRepository: s.setAsideByRepository,
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
  .get("/export", async (c) => {
    const actor = c.get("actor");
    const input = exportQuery.parse(c.req.query());
    const [repository] = input.repositoryId
      ? await db
          .select({ name: r.name })
          .from(r)
          .where(and(eq(r.id, input.repositoryId), repositoryVisibleTo(actor)))
      : [];
    if (input.repositoryId && !repository) throw notFound("Repository");
    const condition = where(actor, input);
    const [rows, totalRow] = await Promise.all([
      db
        .select({
          severity: s.severity,
          ruleId: s.ruleId,
          state: s.state,
          ignored: sql<boolean>`${setAside}`,
          repositoryName: r.name,
          inTree: s.inTree,
          treeLocations: s.treeLocations,
          treeLocationCount: s.treeLocationCount,
          historyLocations: s.historyLocations,
          historyLocationCount: s.historyLocationCount,
          firstSeenAt: s.firstSeenAt,
          lastSeenAt: s.lastSeenAt,
          stateAt: s.stateAt,
          stateReason: s.stateReason,
        })
        .from(s)
        .innerJoin(r, eq(r.id, s.repositoryId))
        .where(condition)
        .orderBy(desc(s.severityRank), desc(s.lastSeenAt), s.id)
        .limit(MAX_EXPORT_ROWS[input.format]),
      db.select({ n: count() }).from(s).where(condition),
    ]);
    const total = totalRow[0]?.n ?? 0;

    // The filters in words, in the file's language.
    const m = resources[input.lang].translation;
    const filters = [
      input.state !== "all" ? fill(m.export.filterState, { state: m.secrets.state[input.state] }) : null,
      input.severity.length
        ? fill(m.export.filterSeverity, { severity: input.severity.map((v) => m.severity[v]).join(", ") })
        : null,
      repository ? fill(m.export.filterRepository, { repository: repository.name }) : null,
      input.q ? fill(m.export.filterText, { text: input.q }) : null,
    ].filter((x): x is string => x !== null);

    const now = new Date();
    const report = secretsReport(rows, {
      language: input.lang,
      timeZone: input.tz,
      filters,
      repositoryName: repository?.name ?? null,
      total,
      now,
    });
    const file = WRITERS[input.format](report);
    await audit(actor, "secret.exported", undefined, {
      format: input.format,
      count: rows.length,
      filters: filters.join(", ") || null,
    });
    return c.body(new Uint8Array(file), 200, {
      "content-type": CONTENT_TYPES[input.format],
      "content-disposition": `attachment; filename="${exportFileName(input.format, repository?.name ?? null, input.tz, now, "secrets")}"`,
      "cache-control": "no-store",
    });
  })
  /** Counts per state and, for open secrets, per severity: the page's toggles and the menu. */
  .get("/counts", async (c) => {
    const actor = c.get("actor");
    const input = listQuery.parse(c.req.query());
    const rows = await db
      .select({
        state: s.state,
        severity: s.severity,
        ignored: sql<boolean>`${setAside}`,
        n: count(),
      })
      .from(s)
      .where(where(actor, { ...input, state: "all", severity: [] }))
      .groupBy(s.state, s.severity, setAside);
    const states = { open: 0, ignored: 0, revoked: 0, dismissed: 0 };
    const open: Record<string, number> = {};
    for (const row of rows) {
      if (row.state === "open" && row.ignored) states.ignored += row.n;
      else states[row.state] += row.n;
      if (row.state === "open" && !row.ignored) open[row.severity] = (open[row.severity] ?? 0) + row.n;
    }
    /** `states.ignored` (0.1.4): open secrets an ignore rule sets aside; `open` leaves them out. */
    return c.json({ states, open });
  })
  /** The organisation's ignore rules, as far as their repository is visible to the person. */
  .get("/ignore-rules", async (c) => {
    const actor = c.get("actor");
    const rows = await db
      .select({
        id: ir.id,
        repositoryId: ir.repositoryId,
        repositoryName: r.name,
        pathPattern: ir.pathPattern,
        ruleId: ir.ruleId,
        reason: ir.reason,
        createdByName: schema.user.name,
        createdAt: ir.createdAt,
        ignored: sql<number>`(select count(*)::int from ${s} where ${s.ignoredBy} = ${ir.id} and ${s.state} = 'open')`,
      })
      .from(ir)
      .leftJoin(r, eq(r.id, ir.repositoryId))
      .leftJoin(schema.user, eq(schema.user.id, ir.createdBy))
      .where(
        and(
          eq(ir.organizationId, actor.organizationId),
          or(isNull(ir.repositoryId), visibleRepository(ir.repositoryId, actor)),
        ),
      )
      .orderBy(desc(ir.createdAt), ir.id);
    return c.json({ items: rows });
  })
  /** Admins, with a recent sign-in: a rule hides findings, so making one is treated like changing a security setting. */
  .post("/ignore-rules", async (c) => {
    const actor = c.get("actor");
    requireRole(actor, "admin");
    requireRecentSignIn(actor);
    const input = ignoreRuleBody.parse(await c.req.json());
    if (input.repositoryId) {
      const [repo] = await db
        .select({ id: r.id })
        .from(r)
        .where(and(eq(r.id, input.repositoryId), repositoryVisibleTo(actor)))
        .limit(1);
      if (!repo) throw notFound("Repository");
    }
    const id = newId("sir");
    await db.insert(ir).values({
      id,
      organizationId: actor.organizationId,
      repositoryId: input.repositoryId ?? null,
      pathPattern: input.pathPattern ?? null,
      ruleId: input.ruleId ?? null,
      reason: input.reason,
      createdBy: actor.userId,
    });
    await applySecretIgnoreRules(db, actor.organizationId);
    await audit(
      actor,
      "secret.ignore_rule_created",
      { type: "secret_ignore_rule", id },
      {
        repositoryId: input.repositoryId ?? null,
        pathPattern: input.pathPattern ?? null,
        rule: input.ruleId ?? null,
        reason: input.reason,
      },
    );
    const [{ n } = { n: 0 }] = await db
      .select({ n: count() })
      .from(s)
      .where(and(eq(s.ignoredBy, id), eq(s.state, "open")));
    return c.json({ id, ignored: n }, 201);
  })
  .delete("/ignore-rules/:ruleId", async (c) => {
    const actor = c.get("actor");
    requireRole(actor, "admin");
    requireRecentSignIn(actor);
    const id = c.req.param("ruleId");
    const [rule] = await db
      .delete(ir)
      .where(and(eq(ir.id, id), eq(ir.organizationId, actor.organizationId)))
      .returning();
    if (!rule) throw notFound("Ignore rule");
    // Its findings come back at once (the foreign key cleared them; this sets aside what another rule still covers).
    await applySecretIgnoreRules(db, actor.organizationId);
    await audit(
      actor,
      "secret.ignore_rule_deleted",
      { type: "secret_ignore_rule", id },
      {
        repositoryId: rule.repositoryId,
        pathPattern: rule.pathPattern,
        rule: rule.ruleId,
      },
    );
    return c.body(null, 204);
  })
  .get("/:id", async (c) => {
    const actor = c.get("actor");
    const [row] = await db
      .select({
        secret: s,
        repositoryName: r.name,
        stateByName: schema.user.name,
        ignoreRule: { id: ir.id, pathPattern: ir.pathPattern, ruleId: ir.ruleId, reason: ir.reason },
      })
      .from(s)
      .innerJoin(r, eq(r.id, s.repositoryId))
      .leftJoin(schema.user, eq(schema.user.id, s.stateBy))
      .leftJoin(ir, eq(ir.id, s.ignoredBy))
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
      ignoredBy: row.ignoreRule?.id ? row.ignoreRule : null,
      setAsideByRepository: secret.setAsideByRepository,
      treeLocations: secret.treeLocations,
      treeLocationCount: secret.treeLocationCount,
      historyLocations: secret.historyLocations,
      historyLocationCount: secret.historyLocationCount,
      firstSeenAt: secret.firstSeenAt,
      lastSeenAt: secret.lastSeenAt,
    });
  })
  /**
   * Closes or reopens several secrets with one reason. Only the ones the person sees and that are in the right state change; the
   * answer counts the rest. Each one is audited on its own, as if closed one by one.
   */
  .post("/bulk", async (c) => {
    const actor = c.get("actor");
    requireRole(actor, "member");
    const input = bulkBody.parse(await c.req.json());
    const ids = [...new Set(input.ids)];
    const now = new Date();
    const reopen = input.action === "reopen";
    const state = input.action === "revoke" ? "revoked" : input.action === "dismiss" ? "dismissed" : "open";
    const rows = await db
      .update(s)
      .set({
        state,
        stateReason: reopen ? null : (input.reason ?? null),
        stateBy: actor.userId,
        stateAt: now,
        updatedAt: now,
      })
      .where(
        and(
          inArray(s.id, ids),
          eq(s.organizationId, actor.organizationId),
          visibleRepository(s.repositoryId, actor),
          reopen ? sql`${s.state} <> 'open'` : eq(s.state, "open"),
        ),
      )
      .returning({ id: s.id, repositoryId: s.repositoryId, ruleId: s.ruleId });
    const action = reopen ? "secret.reopened" : state === "revoked" ? "secret.revoked" : "secret.dismissed";
    for (const row of rows) {
      await audit(
        actor,
        action,
        { type: "secret", id: row.id },
        reopen
          ? { repositoryId: row.repositoryId, bulk: true }
          : { repositoryId: row.repositoryId, rule: row.ruleId, bulk: true },
      );
    }
    return c.json({ changed: rows.length, skipped: ids.length - rows.length });
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

/** Several secrets at once (0.1.5): the ones from the list the person ticked, with one reason for all. */
const bulkBody = z
  .object({
    ids: z.array(z.string().min(1).max(64)).min(1).max(MAX_ROWS),
    action: z.enum(["revoke", "dismiss", "reopen"]),
    reason: reasonBody.shape.reason.optional(),
  })
  .refine((b) => b.action === "reopen" || b.reason !== undefined, {
    message: "Explain in at least 10 characters",
    path: ["reason"],
  });

const ignoreRuleBody = z
  .object({
    repositoryId: z.string().min(1).max(64).nullish(),
    pathPattern: z
      .string()
      .trim()
      .max(IGNORE_PATTERN_MAX)
      .optional()
      .transform((v) => v || undefined)
      .refine((v) => v === undefined || ignorePatternProblem(v) === null, {
        message: "A relative path pattern such as test/fixtures/** that does not match everything",
      }),
    ruleId: z
      .string()
      .trim()
      .optional()
      .transform((v) => v || undefined)
      .refine((v) => v === undefined || /^[a-z0-9][a-z0-9-]{1,79}$/.test(v), {
        message: "A rule id such as generic-api-key",
      }),
    reason: z
      .string()
      .trim()
      .min(10, "Explain in at least 10 characters")
      .max(1000)
      .transform((t) => t.replace(/[\p{Cc}\p{Cf}]/gu, " ")),
  })
  .refine((v) => v.pathPattern || v.ruleId, {
    message: "Name a path pattern, a rule or both",
    path: ["pathPattern"],
  });

const historyBody = z.object({ enabled: z.boolean() });

/** What a repository's Secrets card shows (ADR 0049). */
async function repositorySecrets(repo: typeof r.$inferSelect) {
  const rows = await db
    .select({ severity: s.severity, n: count() })
    .from(s)
    .where(and(eq(s.repositoryId, repo.id), eq(s.state, "open"), notSetAside))
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
    /** The repository's own gitleaks configuration (ADR 0049 addendum 2026-11-12), added in 0.1.6. */
    repoConfig: {
      enabled: repo.secretRepoConfigAt !== null,
      enabledAt: repo.secretRepoConfigAt,
      last: repo.secretRepoConfigAt ? (repo.secretRepoConfigResult ?? null) : null,
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
  /**
   * Respect the repository's own gitleaks configuration (ADR 0049 addendum 2026-11-12): admins only, with a recent sign-in, since
   * it lets the repository set findings aside. Switching it off brings them back at once; switching it on applies from the next
   * scan.
   */
  .put("/repo-config", async (c) => {
    const actor = c.get("actor");
    requireRole(actor, "admin");
    requireRecentSignIn(actor);
    const repo = await visibleRepo(actor, c.req.param("id"));
    const body = historyBody.parse(await c.req.json());
    if (body.enabled !== (repo.secretRepoConfigAt !== null)) {
      const now = new Date();
      await db.transaction(async (tx) => {
        await tx
          .update(r)
          .set({
            secretRepoConfigAt: body.enabled ? now : null,
            secretRepoConfigBy: body.enabled ? actor.userId : null,
            secretRepoConfigResult: null,
            updatedAt: now,
          })
          .where(eq(r.id, repo.id));
        if (!body.enabled) {
          await tx
            .update(s)
            .set({ setAsideByRepository: false, updatedAt: now })
            .where(and(eq(s.repositoryId, repo.id), eq(s.setAsideByRepository, true)));
        }
      });
      await audit(
        actor,
        "secret.repo_config_changed",
        { type: "repository", id: repo.id },
        { enabled: body.enabled, url: repo.url },
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
