/**
 * Servers (ADR 0011): agentless inventory over SSH. Everyone in the organisation reads;
 * owners and admins change. Adding or removing a server and confirming a host key also need
 * a recent sign-in (step-up). Everything that changes something is written to the audit log.
 */
import { createHash, randomBytes } from "node:crypto";
import { newId, SEVERITIES } from "@garnetops/core";
import { renderSetupScript, SETUP_LINK_MINUTES, setupOneLiner } from "@garnetops/core/host-setup";
import {
  type HostInput,
  MAX_HOSTS,
  parseAllowedSource,
  parseHostCsv,
  validateHostInput,
} from "@garnetops/core/hosts";
import { pageSizeSchema } from "@garnetops/core/pagination";
import { parseProxmoxSourceRef, proxmoxSourceRef } from "@garnetops/core/proxmox-flags";
import { parseWazuhSourceRef, wazuhSourceRef } from "@garnetops/core/wazuh";
import { schema } from "@garnetops/db";
import { and, count, desc, eq, getTableColumns, ilike, inArray, or, sql } from "drizzle-orm";
import { Hono } from "hono";
import { z } from "zod";
import { boss, db, QUEUES } from "../db.ts";
import { env } from "../env.ts";
import { audit } from "../lib/audit.ts";
import { type AppEnv, requireRole } from "../lib/context.ts";
import {
  type KeysetSpec,
  keysetQuery,
  parseDate,
  parseInt10,
  parseNumber,
  parseText,
  type SortOption,
  sortSpec,
  toPage,
} from "../lib/paginate.ts";
import { notFound, ProblemError } from "../lib/problem.ts";
import { rateLimit } from "../lib/rate-limit.ts";
import { requireRecentSignIn } from "../lib/step-up.ts";

const h = schema.host;
type HostRow = typeof h.$inferSelect;
type SortKey = string | number | Date;

/** Same job options as the worker uses when the nightly schedule queues an inventory. */
const INVENTORY_JOB = { retryLimit: 1, expireInSeconds: 20 * 60 };
const KEYSCAN_JOB = { retryLimit: 1, expireInSeconds: 5 * 60 };

const escapeLike = (text: string) => `%${text.replace(/[%_\\]/g, "\\$&")}%`;

/* -------------------------------------------------------------------------- */
/* Lists                                                                       */
/* -------------------------------------------------------------------------- */

const openOf = (severity: string) =>
  sql`(select count(*)::int from ${schema.hostFinding} f where f.host_id = ${h.id} and f.state = 'open' and f.severity = ${severity})`;

const SORTS = {
  name: { keys: [h.name], parse: [parseText], dir: "asc" },
  address: { keys: [h.address], parse: [parseText], dir: "asc" },
  os: { keys: [sql`coalesce(${h.osName}, '')`], parse: [parseText], dir: "asc" },
  packages: { keys: [sql`coalesce(${h.packageCount}, -1)`], parse: [parseNumber], dir: "desc" },
  critical: { keys: [openOf("critical")], parse: [parseNumber], dir: "desc" },
  high: { keys: [openOf("high")], parse: [parseNumber], dir: "desc" },
  medium: { keys: [openOf("medium")], parse: [parseNumber], dir: "desc" },
  updates: { keys: [sql`coalesce(${h.pendingUpdates}, -1)`], parse: [parseNumber], dir: "desc" },
  lastInventory: {
    keys: [sql`coalesce(date_trunc('milliseconds', ${h.lastInventoryAt}), 'epoch'::timestamptz)`],
    parse: [parseDate],
    dir: "desc",
  },
} satisfies Record<string, SortOption>;
type SortName = keyof typeof SORTS;
const sortNames = Object.keys(SORTS) as [SortName, ...SortName[]];

type ListRow = HostRow & { sortKeys?: SortKey[] };
const defaultSpec: KeysetSpec<ListRow> = {
  keys: [h.name, h.id],
  direction: "asc",
  keyOf: (row) => [row.name, row.id],
  parse: [parseText, parseText],
};

const listQuery = z.object({
  cursor: z.string().optional(),
  pageSize: pageSizeSchema,
  q: z.string().trim().max(100).optional(),
  /** "vulnerable": open critical or high findings. "attention": host key not confirmed, or the last inventory failed. */
  status: z.enum(["all", "vulnerable", "attention"]).default("all"),
  sort: z.enum(sortNames).optional(),
  dir: z.enum(["asc", "desc"]).optional(),
});

const hasOpen = (severities: string[]) =>
  sql`exists (select 1 from ${schema.hostFinding} f where f.host_id = ${h.id} and f.state = 'open' and f.severity in (${sql.join(
    severities.map((s) => sql`${s}`),
    sql`, `,
  )}))`;

function statusFilter(status: string) {
  if (status === "vulnerable") return hasOpen(["critical", "high"]);
  if (status === "attention") return sql`(${h.hostKeyStatus} <> 'confirmed' or ${h.lastError} is not null)`;
  return undefined;
}

function searchFilter(q: string | undefined) {
  if (!q) return undefined;
  const like = escapeLike(q);
  return or(ilike(h.name, like), ilike(h.address, like), ilike(h.osName, like));
}

/** Open findings per host and severity, for the hosts on one page. */
async function openCounts(hostIds: string[]) {
  const map = new Map<string, Record<string, number>>();
  if (hostIds.length === 0) return map;
  const rows = await db
    .select({ hostId: schema.hostFinding.hostId, severity: schema.hostFinding.severity, n: count() })
    .from(schema.hostFinding)
    .where(and(eq(schema.hostFinding.state, "open"), inArray(schema.hostFinding.hostId, hostIds)))
    .groupBy(schema.hostFinding.hostId, schema.hostFinding.severity);
  for (const row of rows) map.set(row.hostId, { ...(map.get(row.hostId) ?? {}), [row.severity]: row.n });
  return map;
}

/** The latest inventory run of each host in any state, so queued and running ones show up. */
async function latestRuns(hostIds: string[]) {
  if (hostIds.length === 0) return new Map<string, LatestRun>();
  const r = schema.hostInventoryRun;
  const rows = await db
    .selectDistinctOn([r.hostId], {
      hostId: r.hostId,
      id: r.id,
      state: r.state,
      trigger: r.trigger,
      error: r.error,
      createdAt: r.createdAt,
      finishedAt: r.finishedAt,
    })
    .from(r)
    .where(inArray(r.hostId, hostIds))
    .orderBy(r.hostId, desc(r.createdAt), desc(r.id));
  return new Map(rows.map(({ hostId, ...run }) => [hostId, run]));
}
type LatestRun = {
  id: string;
  state: "queued" | "running" | "succeeded" | "failed";
  trigger: "manual" | "schedule" | "setup";
  error: string | null;
  createdAt: Date;
  finishedAt: Date | null;
};

/** The Proxmox guest a server was created from (ADR 0012), if it is still known. */
type ProxmoxLink = {
  guestId: string;
  clusterId: string;
  clusterName: string;
  vmid: number;
  type: "qemu" | "lxc";
  name: string;
  status: string;
};

/** Looks up the guests of the servers on one page: `source = proxmox`, `source_ref = cluster:vmid`. */
async function proxmoxLinks(rows: HostRow[]) {
  const map = new Map<string, ProxmoxLink>();
  const refs = rows.filter((r) => r.source === "proxmox" && r.sourceRef).map((r) => r.sourceRef as string);
  if (refs.length === 0) return map;
  const found = await db
    .select({
      guestId: schema.proxmoxGuest.id,
      clusterId: schema.proxmoxGuest.clusterId,
      clusterName: schema.proxmoxCluster.name,
      vmid: schema.proxmoxGuest.vmid,
      type: schema.proxmoxGuest.type,
      name: schema.proxmoxGuest.name,
      status: schema.proxmoxGuest.status,
    })
    .from(schema.proxmoxGuest)
    .innerJoin(schema.proxmoxCluster, eq(schema.proxmoxCluster.id, schema.proxmoxGuest.clusterId))
    .where(
      and(
        eq(schema.proxmoxGuest.organizationId, rows[0]?.organizationId ?? ""),
        inArray(
          sql<string>`${schema.proxmoxGuest.clusterId} || ':' || ${schema.proxmoxGuest.vmid}::text`,
          refs,
        ),
      ),
    );
  for (const f of found) map.set(proxmoxSourceRef(f.clusterId, f.vmid), f);
  return map;
}

/** The Wazuh agent a server is linked to (ADR 0015), if any. */
type WazuhLink = { agentId: string; agentName: string; status: string; connectionName: string };

/** Looks up the agents linked to the servers of one page (`wazuh_agent.host_id`). */
async function wazuhLinks(rows: HostRow[]) {
  const map = new Map<string, WazuhLink>();
  if (rows.length === 0) return map;
  const a = schema.wazuhAgent;
  const found = await db
    .select({
      hostId: a.hostId,
      agentId: a.id,
      agentName: a.name,
      status: a.status,
      connectionName: schema.wazuhConnection.name,
    })
    .from(a)
    .innerJoin(schema.wazuhConnection, eq(schema.wazuhConnection.id, a.connectionId))
    .where(
      and(
        eq(a.organizationId, rows[0]?.organizationId ?? ""),
        inArray(
          a.hostId,
          rows.map((r) => r.id),
        ),
      ),
    );
  for (const f of found) if (f.hostId) map.set(f.hostId, f);
  return map;
}

/** What the web app shows of a server. Never the key blobs or anything from the access key's secret. */
function present(
  row: HostRow,
  open: Record<string, number>,
  run: LatestRun | null,
  proxmox: ProxmoxLink | null,
  wazuh: WazuhLink | null = null,
) {
  return {
    id: row.id,
    name: row.name,
    address: row.address,
    port: row.port,
    sshUser: row.sshUser,
    source: row.source,
    proxmox,
    wazuh,
    hostKey: {
      status: row.hostKeyStatus,
      type: row.hostKeyType,
      fingerprint: row.hostKeyFingerprint,
      confirmedAt: row.hostKeyConfirmedAt,
      candidate: row.candidateKeyFingerprint
        ? {
            type: row.candidateKeyType,
            fingerprint: row.candidateKeyFingerprint,
            seenAt: row.candidateKeySeenAt,
          }
        : null,
    },
    os: { id: row.osId, versionId: row.osVersionId, name: row.osName },
    kernel: row.kernel,
    arch: row.arch,
    packageCount: row.packageCount,
    pendingUpdates: row.pendingUpdates,
    securityUpdates: row.securityUpdates,
    lastInventoryAt: row.lastInventoryAt,
    lastError: row.lastError,
    open,
    run,
    createdAt: row.createdAt,
  };
}

async function ownHost(organizationId: string, id: string): Promise<HostRow> {
  const [row] = await db
    .select()
    .from(h)
    .where(and(eq(h.id, id), eq(h.organizationId, organizationId)))
    .limit(1);
  if (!row) throw notFound("Server");
  return row;
}

/* -------------------------------------------------------------------------- */
/* Writes                                                                      */
/* -------------------------------------------------------------------------- */

const createBody = z.object({
  address: z.string().max(300),
  name: z.string().max(300).optional(),
  port: z.union([z.number(), z.string().max(10)]).optional(),
  sshUser: z.string().max(64).optional(),
  /**
   * A server created from a Proxmox guest (ADR 0012, `sourceRef` "cluster:vmid") or from a Wazuh
   * agent (ADR 0015, `sourceRef` "connection:agent").
   */
  source: z.enum(["proxmox", "wazuh"]).optional(),
  sourceRef: z.string().max(80).optional(),
});

function invalid(errors: { field: string; code: string }[]): ProblemError {
  return new ProblemError(422, "validation", "The request is not valid", undefined, {
    errors: errors.map((e) => ({ path: e.field, message: e.code })),
  });
}

async function queueKeyscan(hostId: string) {
  await boss.send(QUEUES.hostKeyscan, { hostId }, { ...KEYSCAN_JOB, singletonKey: hostId });
}

/** Makes sure the organisation has an access key; the worker creates it if not. */
async function activeAccessKey(organizationId: string, queueIfMissing: boolean) {
  const [key] = await db
    .select()
    .from(schema.hostAccessKey)
    .where(
      and(eq(schema.hostAccessKey.organizationId, organizationId), eq(schema.hostAccessKey.state, "active")),
    )
    .limit(1);
  if (!key && queueIfMissing) {
    await boss.send(
      QUEUES.hostAccessKey,
      { organizationId },
      { singletonKey: organizationId, retryLimit: 2 },
    );
  }
  return key ?? null;
}

async function countHosts(organizationId: string) {
  const [row] = await db.select({ n: count() }).from(h).where(eq(h.organizationId, organizationId));
  return row?.n ?? 0;
}

/** Queues an inventory unless one is already waiting or running. */
async function queueInventory(
  organizationId: string,
  hostId: string,
  requestedBy: string | null,
  trigger: "manual" | "setup",
): Promise<{ runId: string; alreadyQueued: boolean }> {
  const r = schema.hostInventoryRun;
  const [active] = await db
    .select({ id: r.id })
    .from(r)
    .where(and(eq(r.hostId, hostId), inArray(r.state, ["queued", "running"])))
    .limit(1);
  if (active) return { runId: active.id, alreadyQueued: true };
  const runId = newId("hrun");
  await db.insert(r).values({
    id: runId,
    organizationId,
    hostId,
    state: "queued",
    trigger,
    requestedBy,
    // Millisecond precision on purpose: this column is a pagination key (see lib/paginate.ts).
    createdAt: new Date(),
  });
  await boss.send(QUEUES.hostInventory, { runId }, { ...INVENTORY_JOB, singletonKey: hostId });
  return { runId, alreadyQueued: false };
}

const confirmBody = z.object({ fingerprint: z.string().regex(/^SHA256:[A-Za-z0-9+/]{43}$/) });

const sourceBody = z.object({ allowedSource: z.string().max(400) });
function allowedSourceOf(raw: string): string {
  const parsed = parseAllowedSource(raw);
  if (!parsed.ok) throw invalid([{ field: "allowedSource", code: `source_${parsed.problem}` }]);
  return parsed.value;
}

/** The token of a setup link: 256 random bits, shown once, stored only as a hash. */
export const hashToken = (token: string) => createHash("sha256").update(token).digest("hex");

export const hostRoutes = new Hono<AppEnv>()
  /* ------------------------------ lists ------------------------------ */
  .get("/", async (c) => {
    const actor = c.get("actor");
    const input = listQuery.parse(c.req.query());
    const where = and(
      eq(h.organizationId, actor.organizationId),
      searchFilter(input.q),
      statusFilter(input.status),
    );
    const sorted = input.sort ? sortSpec(SORTS[input.sort], input.dir, h.id) : null;
    const activeSpec = (sorted?.spec ?? defaultSpec) as KeysetSpec<ListRow>;
    const q = keysetQuery(activeSpec, input.cursor, input.pageSize);
    const [rows, totalRow] = await Promise.all([
      db
        .select({ ...getTableColumns(h), sortKeys: sorted ? sorted.select : sql<null>`null` })
        .from(h)
        .where(and(where, q.where))
        .orderBy(...q.orderBy)
        .limit(q.limit),
      db.select({ n: count() }).from(h).where(where),
    ]);
    const page = toPage(
      activeSpec,
      q,
      rows as ListRow[],
      totalRow[0]?.n ?? 0,
      input.pageSize,
      Boolean(input.cursor),
      (row) => row,
    );
    const ids = page.items.map((x) => x.id);
    const [open, runs, links, agentLinks] = await Promise.all([
      openCounts(ids),
      latestRuns(ids),
      proxmoxLinks(page.items),
      wazuhLinks(page.items),
    ]);
    return c.json({
      ...page,
      items: page.items.map((row) =>
        present(
          row,
          open.get(row.id) ?? {},
          runs.get(row.id) ?? null,
          (row.sourceRef && links.get(row.sourceRef)) || null,
          agentLinks.get(row.id) ?? null,
        ),
      ),
    });
  })
  .get("/counts", async (c) => {
    const actor = c.get("actor");
    const input = z.object({ q: z.string().trim().max(100).optional() }).parse(c.req.query());
    const where = and(eq(h.organizationId, actor.organizationId), searchFilter(input.q));
    const counts = await Promise.all(
      (["all", "vulnerable", "attention"] as const).map(async (status) => {
        const [row] = await db
          .select({ n: count() })
          .from(h)
          .where(and(where, statusFilter(status)));
        return [status, row?.n ?? 0] as const;
      }),
    );
    return c.json(Object.fromEntries(counts));
  })

  /* --------------------- access key and setup script ------------------ */
  .get("/access", async (c) => {
    const actor = c.get("actor");
    const key = await activeAccessKey(actor.organizationId, false);
    return c.json(
      key
        ? {
            ready: true,
            publicKey: key.publicKey,
            fingerprint: key.fingerprint,
            allowedSource: key.allowedSource,
            createdAt: key.createdAt,
          }
        : { ready: false },
    );
  })
  .post("/access", async (c) => {
    // Asks the worker to create the organisation's access key (the API never sees the private half).
    const actor = c.get("actor");
    requireRole(actor, "admin");
    const key = await activeAccessKey(actor.organizationId, true);
    return c.json({ ready: Boolean(key) }, key ? 200 : 202);
  })
  .post("/setup-script", async (c) => {
    const actor = c.get("actor");
    requireRole(actor, "admin");
    const input = sourceBody.parse(await c.req.json());
    const allowedSource = allowedSourceOf(input.allowedSource);
    const key = await activeAccessKey(actor.organizationId, true);
    if (!key)
      throw new ProblemError(
        409,
        "access-key-pending",
        "The access key is being created, try again in a moment",
      );
    const script = renderSetupScript({ publicKey: key.publicKey, allowedSource });
    await db.update(schema.hostAccessKey).set({ allowedSource }).where(eq(schema.hostAccessKey.id, key.id));
    await audit(
      actor,
      "host.setup_script_created",
      { type: "host_access_key", id: key.id },
      { allowedSource, sha256: script.sha256 },
    );
    return c.json({
      script: script.script,
      sha256: script.sha256,
      filename: script.filename,
      keyFingerprint: script.keyFingerprint,
      wrapperSha256: script.wrapperSha256,
      /** The source addresses as they were written into the script (normalised). */
      allowedSource,
    });
  })
  .post("/setup-links", async (c) => {
    const actor = c.get("actor");
    requireRole(actor, "admin");
    const input = sourceBody.parse(await c.req.json());
    const allowedSource = allowedSourceOf(input.allowedSource);
    await rateLimit(`host-setup-link:${actor.organizationId}`, 20, 60 * 60_000);
    const key = await activeAccessKey(actor.organizationId, true);
    if (!key)
      throw new ProblemError(
        409,
        "access-key-pending",
        "The access key is being created, try again in a moment",
      );
    const script = renderSetupScript({ publicKey: key.publicKey, allowedSource });
    const token = randomBytes(32).toString("base64url");
    const id = newId("hsl");
    const expiresAt = new Date(Date.now() + SETUP_LINK_MINUTES * 60_000);
    await db.insert(schema.hostSetupLink).values({
      id,
      organizationId: actor.organizationId,
      accessKeyId: key.id,
      tokenHash: hashToken(token),
      allowedSource,
      scriptSha256: script.sha256,
      createdBy: actor.userId,
      expiresAt,
    });
    await db.update(schema.hostAccessKey).set({ allowedSource }).where(eq(schema.hostAccessKey.id, key.id));
    await audit(
      actor,
      "host.setup_link_created",
      { type: "host_setup_link", id },
      { allowedSource, sha256: script.sha256, expiresAt: expiresAt.toISOString() },
    );
    const url = `${env.PUBLIC_URL.replace(/\/+$/, "")}/api/v1/host-setup/${token}`;
    return c.json({ url, command: setupOneLiner(url, script.sha256), sha256: script.sha256, expiresAt }, 201);
  })

  /* ------------------------------ adding ------------------------------ */
  .post("/", async (c) => {
    const actor = c.get("actor");
    requireRole(actor, "admin");
    const body = createBody.parse(await c.req.json());
    const checked = validateHostInput(body);
    if (!checked.ok) throw invalid(checked.errors);
    requireRecentSignIn(actor);
    if ((await countHosts(actor.organizationId)) >= MAX_HOSTS) {
      throw new ProblemError(
        409,
        "limit-reached",
        "The organisation has reached the number of servers it may have",
      );
    }
    const input = checked.value;
    // A server created from a Proxmox guest or a Wazuh agent: it must exist in this organisation and not be linked yet.
    let sourceRef: string | null = null;
    let wazuhAgentRowId: string | null = null;
    if (body.source !== undefined || body.sourceRef !== undefined) {
      if (body.source === "proxmox") {
        const ref = body.sourceRef ? parseProxmoxSourceRef(body.sourceRef) : null;
        if (!ref) throw invalid([{ field: "sourceRef", code: "source_invalid" }]);
        const [guest] = await db
          .select({ id: schema.proxmoxGuest.id })
          .from(schema.proxmoxGuest)
          .where(
            and(
              eq(schema.proxmoxGuest.organizationId, actor.organizationId),
              eq(schema.proxmoxGuest.clusterId, ref.clusterId),
              eq(schema.proxmoxGuest.vmid, ref.vmid),
            ),
          )
          .limit(1);
        if (!guest) throw invalid([{ field: "sourceRef", code: "source_unknown" }]);
        sourceRef = proxmoxSourceRef(ref.clusterId, ref.vmid);
        const [linked] = await db
          .select({ id: h.id })
          .from(h)
          .where(
            and(
              eq(h.organizationId, actor.organizationId),
              eq(h.source, "proxmox"),
              eq(h.sourceRef, sourceRef),
            ),
          )
          .limit(1);
        if (linked) throw new ProblemError(409, "already-linked", "A server is already linked to this guest");
      } else if (body.source === "wazuh") {
        const ref = body.sourceRef ? parseWazuhSourceRef(body.sourceRef) : null;
        if (!ref) throw invalid([{ field: "sourceRef", code: "source_invalid" }]);
        const a = schema.wazuhAgent;
        const [agent] = await db
          .select({ id: a.id, hostId: a.hostId, isManager: a.isManager })
          .from(a)
          .where(
            and(
              eq(a.organizationId, actor.organizationId),
              eq(a.connectionId, ref.connectionId),
              eq(a.agentId, ref.agentId),
            ),
          )
          .limit(1);
        if (!agent) throw invalid([{ field: "sourceRef", code: "source_unknown" }]);
        if (agent.hostId || agent.isManager) {
          throw new ProblemError(409, "already-linked", "A server is already linked to this agent");
        }
        sourceRef = wazuhSourceRef(ref.connectionId, ref.agentId);
        wazuhAgentRowId = agent.id;
      } else {
        throw invalid([{ field: "sourceRef", code: "source_invalid" }]);
      }
    }
    const [existing] = await db
      .select({ id: h.id })
      .from(h)
      .where(
        and(eq(h.organizationId, actor.organizationId), eq(h.address, input.address), eq(h.port, input.port)),
      )
      .limit(1);
    if (existing) throw new ProblemError(409, "duplicate", "This server is already added");

    const id = newId("host");
    const source = sourceRef ? (body.source ?? "manual") : "manual";
    await db.transaction(async (tx) => {
      await tx.insert(h).values({
        id,
        organizationId: actor.organizationId,
        name: input.name,
        address: input.address,
        port: input.port,
        sshUser: input.sshUser,
        source,
        sourceRef,
        createdBy: actor.userId,
      });
      // A server made from a Wazuh agent is the machine behind that agent: link them in the same step.
      if (wazuhAgentRowId) {
        await tx
          .update(schema.wazuhAgent)
          .set({
            hostId: id,
            linkedAt: new Date(),
            linkedBy: actor.userId,
            suggestedHostId: null,
            suggestionReason: null,
          })
          .where(eq(schema.wazuhAgent.id, wazuhAgentRowId));
      }
    });
    await audit(
      actor,
      "host.created",
      { type: "host", id },
      {
        name: input.name,
        address: input.address,
        port: input.port,
        source,
        ...(sourceRef ? { sourceRef } : {}),
      },
    );
    await queueKeyscan(id);
    await activeAccessKey(actor.organizationId, true);
    return c.json({ id }, 201);
  })
  .post("/import", async (c) => {
    const actor = c.get("actor");
    requireRole(actor, "admin");
    const body = z.object({ csv: z.string().max(300_000) }).parse(await c.req.json());
    const parsed = parseHostCsv(body.csv);
    if (!parsed.ok) {
      const code = { empty: "csv_empty", tooLarge: "csv_too_large", tooManyRows: "csv_too_many_rows" }[
        parsed.problem
      ];
      throw invalid([{ field: "csv", code }]);
    }
    requireRecentSignIn(actor);

    const existing = await db
      .select({ address: h.address, port: h.port })
      .from(h)
      .where(eq(h.organizationId, actor.organizationId));
    const known = new Set(existing.map((e) => `${e.address}:${e.port}`));
    let room = MAX_HOSTS - existing.length;

    const created: { id: string; line: number; input: HostInput }[] = [];
    const skipped: { line: number; address: string; reason: "duplicate" | "limit" }[] = [];
    const invalidRows: { line: number; address: string; errors: { field: string; code: string }[] }[] = [];
    for (const row of parsed.rows) {
      const checked = validateHostInput(row);
      if (!checked.ok) {
        invalidRows.push({ line: row.line, address: row.address.slice(0, 100), errors: checked.errors });
        continue;
      }
      const key = `${checked.value.address}:${checked.value.port}`;
      if (known.has(key)) {
        skipped.push({ line: row.line, address: checked.value.address, reason: "duplicate" });
        continue;
      }
      if (room <= 0) {
        skipped.push({ line: row.line, address: checked.value.address, reason: "limit" });
        continue;
      }
      room--;
      known.add(key);
      created.push({ id: newId("host"), line: row.line, input: checked.value });
    }

    if (created.length > 0) {
      await db.transaction(async (tx) => {
        await tx.insert(h).values(
          created.map((x) => ({
            id: x.id,
            organizationId: actor.organizationId,
            name: x.input.name,
            address: x.input.address,
            port: x.input.port,
            sshUser: x.input.sshUser,
            source: "csv",
            createdBy: actor.userId,
          })),
        );
        await tx.insert(schema.auditLog).values([
          ...created.map((x) => ({
            organizationId: actor.organizationId,
            actorUserId: actor.userId,
            action: "host.created",
            targetType: "host",
            targetId: x.id,
            ip: actor.ip,
            data: { name: x.input.name, address: x.input.address, port: x.input.port, source: "csv" },
          })),
          {
            organizationId: actor.organizationId,
            actorUserId: actor.userId,
            action: "host.imported",
            targetType: null,
            targetId: null,
            ip: actor.ip,
            data: { created: created.length, skipped: skipped.length, invalid: invalidRows.length },
          },
        ]);
      });
      for (const x of created) await queueKeyscan(x.id);
      await activeAccessKey(actor.organizationId, true);
    }
    return c.json(
      {
        created: created.map((x) => ({
          id: x.id,
          line: x.line,
          address: x.input.address,
          name: x.input.name,
        })),
        skipped,
        invalid: invalidRows,
      },
      201,
    );
  })

  /* ------------------------------ one server ------------------------------ */
  .get("/:id", async (c) => {
    const actor = c.get("actor");
    const row = await ownHost(actor.organizationId, c.req.param("id"));
    const [open, runs, links, agentLinks, states] = await Promise.all([
      openCounts([row.id]),
      latestRuns([row.id]),
      proxmoxLinks([row]),
      wazuhLinks([row]),
      db
        .select({ state: schema.hostFinding.state, n: count() })
        .from(schema.hostFinding)
        .where(eq(schema.hostFinding.hostId, row.id))
        .groupBy(schema.hostFinding.state),
    ]);
    return c.json({
      ...present(
        row,
        open.get(row.id) ?? {},
        runs.get(row.id) ?? null,
        (row.sourceRef && links.get(row.sourceRef)) || null,
        agentLinks.get(row.id) ?? null,
      ),
      states: Object.fromEntries(states.map((s) => [s.state, s.n])),
    });
  })
  .delete("/:id", async (c) => {
    const actor = c.get("actor");
    requireRole(actor, "admin");
    requireRecentSignIn(actor);
    const id = c.req.param("id");
    const [row] = await db
      .delete(h)
      .where(and(eq(h.id, id), eq(h.organizationId, actor.organizationId)))
      .returning({ name: h.name, address: h.address, port: h.port });
    if (!row) throw notFound("Server");
    await audit(
      actor,
      "host.deleted",
      { type: "host", id },
      { name: row.name, address: row.address, port: row.port },
    );
    return c.body(null, 204);
  })
  .post("/:id/inventory", async (c) => {
    const actor = c.get("actor");
    requireRole(actor, "admin");
    const row = await ownHost(actor.organizationId, c.req.param("id"));
    if (row.hostKeyStatus !== "confirmed") {
      throw new ProblemError(409, "host-key-unconfirmed", "Confirm the host key of this server first");
    }
    const result = await queueInventory(actor.organizationId, row.id, actor.userId, "manual");
    if (!result.alreadyQueued) {
      await audit(
        actor,
        "host.inventory_requested",
        { type: "host", id: row.id },
        { runId: result.runId, address: row.address },
      );
    }
    return c.json(result, result.alreadyQueued ? 200 : 202);
  })
  .post("/:id/host-key/scan", async (c) => {
    const actor = c.get("actor");
    requireRole(actor, "admin");
    const row = await ownHost(actor.organizationId, c.req.param("id"));
    await queueKeyscan(row.id);
    await audit(actor, "host.key_scan_requested", { type: "host", id: row.id }, { address: row.address });
    return c.body(null, 202);
  })
  .post("/:id/host-key/confirm", async (c) => {
    const actor = c.get("actor");
    requireRole(actor, "admin");
    const input = confirmBody.parse(await c.req.json());
    requireRecentSignIn(actor);
    const row = await ownHost(actor.organizationId, c.req.param("id"));
    if (!row.candidateKey || !row.candidateKeyFingerprint) {
      throw new ProblemError(409, "no-host-key", "There is no host key waiting for confirmation");
    }
    // The admin confirms the fingerprint they compared, not "whatever is pending now".
    if (row.candidateKeyFingerprint !== input.fingerprint) {
      throw new ProblemError(
        409,
        "fingerprint-mismatch",
        "The host key has changed since it was shown; compare the new fingerprint",
      );
    }
    const now = new Date();
    const updated = await db
      .update(h)
      .set({
        hostKeyStatus: "confirmed",
        hostKeyType: row.candidateKeyType,
        hostKey: row.candidateKey,
        hostKeyFingerprint: row.candidateKeyFingerprint,
        hostKeyConfirmedAt: now,
        hostKeyConfirmedBy: actor.userId,
        candidateKeyType: null,
        candidateKey: null,
        candidateKeyFingerprint: null,
        candidateKeySeenAt: null,
        lastError: null,
        updatedAt: now,
      })
      .where(and(eq(h.id, row.id), eq(h.candidateKeyFingerprint, input.fingerprint)))
      .returning({ id: h.id });
    if (updated.length === 0) {
      throw new ProblemError(
        409,
        "fingerprint-mismatch",
        "The host key has changed since it was shown; compare the new fingerprint",
      );
    }
    await audit(
      actor,
      "host.key_confirmed",
      { type: "host", id: row.id },
      {
        address: row.address,
        type: row.candidateKeyType,
        fingerprint: input.fingerprint,
        previous: row.hostKeyFingerprint,
      },
    );
    const run = await queueInventory(
      actor.organizationId,
      row.id,
      actor.userId,
      row.hostKeyFingerprint ? "manual" : "setup",
    );
    return c.json({ runId: run.runId }, 200);
  })

  /* ---------------- packages, findings and history of a server ---------------- */
  .get("/:id/packages", async (c) => {
    const actor = c.get("actor");
    const row = await ownHost(actor.organizationId, c.req.param("id"));
    const p = schema.hostPackage;
    const input = z
      .object({
        cursor: z.string().optional(),
        pageSize: pageSizeSchema,
        q: z.string().trim().max(120).optional(),
        updatable: z.enum(["1"]).optional(),
        sort: z.enum(["name", "version", "type", "update"]).optional(),
        dir: z.enum(["asc", "desc"]).optional(),
      })
      .parse(c.req.query());
    const sorts = {
      name: { keys: [p.name, p.version], parse: [parseText, parseText], dir: "asc" },
      version: { keys: [p.version], parse: [parseText], dir: "asc" },
      type: { keys: [p.type], parse: [parseText], dir: "asc" },
      update: { keys: [sql`(${p.upgradableTo} is not null)::int`], parse: [parseNumber], dir: "desc" },
    } satisfies Record<string, SortOption>;
    type Row = {
      id: string;
      name: string;
      version: string;
      sortKeys?: SortKey[];
    };
    const spec: KeysetSpec<Row> = {
      keys: [p.name, p.version, p.id],
      direction: "asc",
      keyOf: (r) => [r.name, r.version, r.id],
      parse: [parseText, parseText, parseText],
    };
    const sorted = input.sort ? sortSpec(sorts[input.sort], input.dir, p.id) : null;
    const activeSpec = (sorted?.spec ?? spec) as KeysetSpec<Row>;
    const q = keysetQuery(activeSpec, input.cursor, input.pageSize);
    const where = and(
      eq(p.hostId, row.id),
      input.q ? ilike(p.name, escapeLike(input.q)) : undefined,
      input.updatable ? sql`${p.upgradableTo} is not null` : undefined,
    );
    const [rows, totalRow] = await Promise.all([
      db
        .select({
          id: p.id,
          name: p.name,
          version: p.version,
          arch: p.arch,
          type: p.type,
          origin: p.origin,
          upgradableTo: p.upgradableTo,
          securityUpdate: p.securityUpdate,
          sortKeys: sorted ? sorted.select : sql<null>`null`,
        })
        .from(p)
        .where(and(where, q.where))
        .orderBy(...q.orderBy)
        .limit(q.limit),
      db.select({ n: count() }).from(p).where(where),
    ]);
    return c.json(
      toPage(
        activeSpec,
        q,
        rows as Row[],
        totalRow[0]?.n ?? 0,
        input.pageSize,
        Boolean(input.cursor),
        (r) => r,
      ),
    );
  })
  .get("/:id/findings", async (c) => {
    const actor = c.get("actor");
    const row = await ownHost(actor.organizationId, c.req.param("id"));
    const f = schema.hostFinding;
    const v = schema.vulnerability;
    const input = z
      .object({
        cursor: z.string().optional(),
        pageSize: pageSizeSchema,
        state: z.enum(["open", "resolved", "all"]).default("open"),
        severity: z
          .string()
          .optional()
          .transform((s) =>
            s ? s.split(",").filter((x) => (SEVERITIES as readonly string[]).includes(x)) : [],
          ),
        q: z.string().trim().max(120).optional(),
        sort: z.enum(["vulnerability", "cvss", "epss", "package", "firstSeen"]).optional(),
        dir: z.enum(["asc", "desc"]).optional(),
      })
      .parse(c.req.query());
    const sorts = {
      vulnerability: { keys: [f.vulnerabilityId], parse: [parseText], dir: "asc" },
      cvss: { keys: [sql`coalesce(${v.cvssScore}::numeric, -1)`], parse: [parseNumber], dir: "desc" },
      epss: { keys: [sql`coalesce(${v.epss}::numeric, -1)`], parse: [parseNumber], dir: "desc" },
      package: { keys: [f.packageName, f.packageVersion], parse: [parseText, parseText], dir: "asc" },
      firstSeen: {
        keys: [sql`date_trunc('milliseconds', ${f.firstSeenAt})`],
        parse: [parseDate],
        dir: "desc",
      },
    } satisfies Record<string, SortOption>;
    type Row = { id: string; severityRank: number; lastSeenAt: Date; sortKeys?: SortKey[] };
    const spec: KeysetSpec<Row> = {
      keys: [f.severityRank, f.lastSeenAt, f.id],
      direction: "desc",
      keyOf: (r) => [r.severityRank, r.lastSeenAt, r.id],
      parse: [parseInt10, parseDate, parseText],
    };
    const sorted = input.sort ? sortSpec(sorts[input.sort], input.dir, f.id) : null;
    const activeSpec = (sorted?.spec ?? spec) as KeysetSpec<Row>;
    const q = keysetQuery(activeSpec, input.cursor, input.pageSize);
    const like = input.q ? escapeLike(input.q) : null;
    const where = and(
      eq(f.hostId, row.id),
      input.state === "all" ? undefined : eq(f.state, input.state),
      input.severity.length ? inArray(f.severity, input.severity) : undefined,
      like ? or(ilike(f.packageName, like), ilike(f.vulnerabilityId, like)) : undefined,
    );
    const [rows, totalRow] = await Promise.all([
      db
        .select({
          id: f.id,
          severityRank: f.severityRank,
          lastSeenAt: f.lastSeenAt,
          severity: f.severity,
          state: f.state,
          packageName: f.packageName,
          packageVersion: f.packageVersion,
          packageType: f.packageType,
          fixedIn: f.fixedIn,
          vulnerabilityId: f.vulnerabilityId,
          knownExploited: v.knownExploited,
          cvssScore: v.cvssScore,
          epss: v.epss,
          publishedAt: v.publishedAt,
          firstSeenAt: f.firstSeenAt,
          sortKeys: sorted ? sorted.select : sql<null>`null`,
        })
        .from(f)
        .innerJoin(v, eq(v.id, f.vulnerabilityId))
        .where(and(where, q.where))
        .orderBy(...q.orderBy)
        .limit(q.limit),
      db.select({ n: count() }).from(f).where(where),
    ]);
    return c.json(
      toPage(
        activeSpec,
        q,
        rows as Row[],
        totalRow[0]?.n ?? 0,
        input.pageSize,
        Boolean(input.cursor),
        (r) => r,
      ),
    );
  })
  .get("/:id/runs", async (c) => {
    const actor = c.get("actor");
    const row = await ownHost(actor.organizationId, c.req.param("id"));
    const r = schema.hostInventoryRun;
    const input = z.object({ cursor: z.string().optional(), pageSize: pageSizeSchema }).parse(c.req.query());
    type Row = { id: string; createdAt: Date };
    const spec: KeysetSpec<Row> = {
      keys: [r.createdAt, r.id],
      direction: "desc",
      keyOf: (x) => [x.createdAt, x.id],
      parse: [parseDate, parseText],
    };
    const q = keysetQuery(spec, input.cursor, input.pageSize);
    const where = eq(r.hostId, row.id);
    const [rows, totalRow] = await Promise.all([
      db
        .select({
          id: r.id,
          state: r.state,
          trigger: r.trigger,
          packageCount: r.packageCount,
          pendingUpdates: r.pendingUpdates,
          newFindings: r.newFindings,
          resolvedFindings: r.resolvedFindings,
          severityCounts: r.severityCounts,
          scannerVersions: r.scannerVersions,
          error: r.error,
          startedAt: r.startedAt,
          finishedAt: r.finishedAt,
          createdAt: r.createdAt,
        })
        .from(r)
        .where(and(where, q.where))
        .orderBy(...q.orderBy)
        .limit(q.limit),
      db.select({ n: count() }).from(r).where(where),
    ]);
    return c.json(
      toPage(spec, q, rows as Row[], totalRow[0]?.n ?? 0, input.pageSize, Boolean(input.cursor), (x) => x),
    );
  });
