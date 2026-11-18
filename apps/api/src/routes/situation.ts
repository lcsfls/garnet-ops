/**
 * The situation per vulnerability (ADR 0052): one vulnerability across repositories, running containers and hosts, with the state
 * of each system and what fixes it. Computed from the findings the scans and the host agent already store; nothing is written.
 * Repositories by ADR 0030 (only what the person sees, active ones); hosts and containers while the hosts module is on.
 */
import { SEVERITIES, SEVERITY_RANK, type Severity } from "@garnetops/core";
import { imageRefKey } from "@garnetops/core/agent";
import { classifyFinding, upgradeCommand } from "@garnetops/core/apt";
import { pageSizeSchema } from "@garnetops/core/pagination";
import { HOST_STALE_AFTER_MS } from "@garnetops/core/reports";
import {
  FIX_PATHS,
  type FixPath,
  fixPathOf,
  SITUATION_MAX_SYSTEMS,
  type SituationKind,
  type SituationStatus,
} from "@garnetops/core/situation";
import { isSsholeFinding, ssholeSafeReasons } from "@garnetops/core/sshd";
import { activeRepository, repositoryVisibleTo, schema, visibleRepository } from "@garnetops/db";
import { and, asc, desc, eq, inArray, isNull, type SQL, sql } from "drizzle-orm";
import { Hono } from "hono";
import { z } from "zod";
import { db } from "../db.ts";
import type { Actor, AppEnv } from "../lib/context.ts";
import { modulesOf } from "../lib/modules.ts";
import { notFound } from "../lib/problem.ts";
import { updateOf, updatesByRef, visibleRepositoriesByKey } from "./hosts.ts";

const f = schema.finding;
const r = schema.repository;
const h = schema.agentHost;
const hc = schema.hostContainer;
const ci = schema.containerImage;
const cf = schema.containerImageFinding;
const hf = schema.hostPackageFinding;
const kf = schema.hostKernelFinding;
const v = schema.vulnerability;

const SHOW = ["all", "exploited", "critical", "high"] as const;
const listQuery = z.object({
  /** Part of the vulnerability's id or of an affected package's name. */
  q: z.string().trim().max(120).optional(),
  show: z.enum(SHOW).default("all"),
  kind: z.enum(["repository", "container", "host"]).optional(),
  /** The offset of the page, as the previous answer's `next` or `prev` gave it. */
  cursor: z
    .string()
    .regex(/^\d{1,7}$/)
    .optional(),
  pageSize: pageSizeSchema,
});
const idParam = z.string().regex(/^[A-Za-z0-9][A-Za-z0-9._:-]{0,99}$/);

const severityOfRank = (rank: number): Severity =>
  SEVERITIES.find((s) => SEVERITY_RANK[s] === rank) ?? "unknown";
const hasFix = (column: SQL) => sql`(jsonb_array_length(coalesce(${column}, '[]'::jsonb)) > 0)`;

/**
 * Every open finding the person may see, one row per system and package: the vulnerability, the kind and id of the system, the
 * package, its severity rank and whether a fixed version is known. Hosts and containers only while the module is on.
 */
function systemRows(actor: Actor, hostsOn: boolean): SQL {
  const repositories = sql`select ${f.vulnerabilityId} as vid, 'repository' as kind, ${f.repositoryId} as system,
      ${f.packageName} as pkg, ${f.severityRank} as rank, ${hasFix(sql`${f.fixedIn}`)} as fix
    from ${f}
    where ${f.organizationId} = ${actor.organizationId} and ${f.state} = 'open'
      and ${visibleRepository(f.repositoryId, actor)} and ${activeRepository(f.repositoryId)}`;
  if (!hostsOn) return repositories;
  return sql`${repositories}
    union all
    select ${cf.vulnerabilityId}, 'container', ${hc.hostId} || '/' || ${hc.containerId}, ${cf.packageName},
      ${cf.severityRank}, ${hasFix(sql`${cf.fixedIn}`)}
    from ${cf} join ${hc} on ${hc.organizationId} = ${cf.organizationId} and ${hc.imageId} = ${cf.imageId}
    where ${cf.organizationId} = ${actor.organizationId}
    union all
    select ${hf.vulnerabilityId}, 'host', ${hf.hostId}, ${hf.packageName}, ${hf.severityRank}, ${hasFix(sql`${hf.fixedIn}`)}
    from ${hf} where ${hf.organizationId} = ${actor.organizationId}
    union all
    select ${kf.vulnerabilityId}, 'host', ${kf.hostId}, ${kf.packageName}, ${kf.severityRank}, ${hasFix(sql`${kf.fixedIn}`)}
    from ${kf} where ${kf.organizationId} = ${actor.organizationId}`;
}

const escapeLike = (text: string) => text.replace(/[%_\\]/g, "\\$&");

/** One row per vulnerability over the system rows, with the filters that do not depend on `show`. */
function grouped(actor: Actor, hostsOn: boolean, input: { q?: string; kind?: SituationKind }): SQL {
  const like = input.q ? `%${escapeLike(input.q)}%` : null;
  return sql`select s.vid, max(s.rank)::int as rank,
      (count(distinct s.system) filter (where s.kind = 'repository'))::int as repositories,
      (count(distinct s.system) filter (where s.kind = 'container'))::int as containers,
      (count(distinct s.system) filter (where s.kind = 'host'))::int as hosts,
      (count(distinct s.kind || ':' || s.system))::int as systems,
      bool_or(s.fix) as fix_known,
      to_jsonb((array_agg(distinct s.pkg order by s.pkg))[1:3]) as packages,
      (count(distinct s.pkg))::int as package_count
    from (${systemRows(actor, hostsOn)}) s
    where ${input.kind ? sql`s.kind = ${input.kind}` : sql`true`}
      and ${like ? sql`(s.vid ilike ${like} or s.pkg ilike ${like})` : sql`true`}
    group by s.vid`;
}

function showFilter(show: (typeof SHOW)[number]): SQL {
  if (show === "exploited") return sql`${v.knownExploited}`;
  if (show === "critical") return sql`g.rank = ${SEVERITY_RANK.critical}`;
  if (show === "high") return sql`g.rank = ${SEVERITY_RANK.high}`;
  return sql`true`;
}

type NotCheckedReason =
  | "never-scanned"
  | "scan-failed"
  | "not-reporting"
  | "packages-not-matched"
  | "host-packages-not-reported"
  | "image-not-checked";

const clip = (text: string | null | undefined, max: number) => (text ?? "").slice(0, max);

export const situationRoutes = new Hono<AppEnv>()
  /** The vulnerabilities open anywhere the person sees, each once: known exploited first, then by severity and reach. */
  .get("/", async (c) => {
    const actor = c.get("actor");
    const input = listQuery.parse(c.req.query());
    const hostsOn = (await modulesOf(actor.organizationId)).hosts;
    const offset = input.cursor ? Number(input.cursor) : 0;
    const base = sql`from (${grouped(actor, hostsOn, input)}) g join ${v} on ${v.id} = g.vid`;
    const [rows, counts] = await Promise.all([
      db.execute<{
        vid: string;
        rank: number;
        repositories: number;
        containers: number;
        hosts: number;
        systems: number;
        fix_known: boolean;
        packages: string[] | null;
        package_count: number;
        cvss_score: number | null;
        known_exploited: boolean;
        epss: number | null;
        published_at: string | null;
      }>(sql`select g.*, ${v.cvssScore} as cvss_score, ${v.knownExploited} as known_exploited, ${v.epss} as epss,
          ${v.publishedAt} as published_at
        ${base} where ${showFilter(input.show)}
        order by ${v.knownExploited} desc, g.rank desc, g.systems desc, g.vid asc
        limit ${input.pageSize} offset ${offset}`),
      db.execute<{
        all: number;
        exploited: number;
        critical: number;
        high: number;
      }>(sql`select count(*)::int as "all",
          (count(*) filter (where ${v.knownExploited}))::int as exploited,
          (count(*) filter (where g.rank = ${SEVERITY_RANK.critical}))::int as critical,
          (count(*) filter (where g.rank = ${SEVERITY_RANK.high}))::int as high
        ${base}`),
    ]);
    const totals = counts.rows[0] ?? { all: 0, exploited: 0, critical: 0, high: 0 };
    const total = totals[input.show];
    return c.json({
      items: rows.rows.map((row) => ({
        id: row.vid,
        severity: severityOfRank(row.rank),
        cvssScore: row.cvss_score,
        knownExploited: row.known_exploited,
        epss: row.epss,
        publishedAt: row.published_at,
        repositories: row.repositories,
        containers: row.containers,
        hosts: row.hosts,
        systems: row.systems,
        fixKnown: row.fix_known,
        packages: (row.packages ?? []).map((p) => clip(p, 120)),
        packageCount: row.package_count,
      })),
      total,
      pageSize: input.pageSize,
      next: offset + rows.rows.length < total ? String(offset + input.pageSize) : null,
      prev: offset > 0 ? String(Math.max(0, offset - input.pageSize)) : null,
      counts: totals,
      /** Hosts and containers are part of the situation only while the hosts module is on. */
      hostsOn,
    });
  })
  /** One vulnerability: every system that has it with its state and what fixes it, and what could not be checked. */
  .get("/:id", async (c) => {
    const actor = c.get("actor");
    const id = idParam.safeParse(c.req.param("id"));
    if (!id.success) throw notFound("Vulnerability");
    const [vulnerability] = await db.select().from(v).where(eq(v.id, id.data)).limit(1);
    if (!vulnerability) throw notFound("Vulnerability");
    const hostsOn = (await modulesOf(actor.organizationId)).hosts;
    const now = new Date();
    const org = actor.organizationId;

    /* ------------------------------ repositories ------------------------------ */
    const repositories = await db
      .select({ id: r.id, name: r.name, lastScanId: r.lastScanId })
      .from(r)
      .where(and(repositoryVisibleTo(actor), isNull(r.inactiveAt)))
      .orderBy(asc(r.name));
    const repositoryIds = repositories.map((x) => x.id);
    const [repositoryFindings, lastScans] = await Promise.all([
      db
        .select({
          id: f.id,
          repositoryId: f.repositoryId,
          packageName: f.packageName,
          packageVersion: f.packageVersion,
          packageType: f.packageType,
          fixedIn: f.fixedIn,
          severityRank: f.severityRank,
        })
        .from(f)
        .where(
          and(
            eq(f.organizationId, org),
            eq(f.vulnerabilityId, vulnerability.id),
            eq(f.state, "open"),
            visibleRepository(f.repositoryId, actor),
            activeRepository(f.repositoryId),
          ),
        )
        .orderBy(asc(f.packageName), asc(f.packageVersion)),
      repositoryIds.length
        ? db
            .selectDistinctOn([schema.scan.repositoryId], {
              repositoryId: schema.scan.repositoryId,
              state: schema.scan.state,
            })
            .from(schema.scan)
            // Checks of other refs (pull requests) are not the repository's state.
            .where(and(inArray(schema.scan.repositoryId, repositoryIds), isNull(schema.scan.ref)))
            .orderBy(schema.scan.repositoryId, desc(schema.scan.createdAt))
        : Promise.resolve([]),
    ]);
    const lastScanState = new Map(lastScans.map((s) => [s.repositoryId, s.state]));

    type Package = { name: string; version: string; type: string; fixedIn: string[] };
    interface System {
      kind: SituationKind;
      /** The repository's or the host's id; for a container the host's. */
      id: string;
      name: string;
      status: SituationStatus;
      severity: Severity;
      packages: Package[];
      fixPath: FixPath;
      /** Why the flaw cannot be used on this system as configured (status `not-reachable`). */
      reasons: string[];
      repository: { id: string; name: string; findingId: string | null } | null;
      container: { name: string; imageRef: string; update: { state: string; tag: string | null } } | null;
      host: { id: string; name: string; reporting: boolean } | null;
      patch: { state: string; fixedIn: string | null; command: string | null } | null;
      kernel: boolean;
    }
    const systems: System[] = [];
    const notChecked: { kind: SituationKind; id: string; name: string; reason: NotCheckedReason }[] = [];
    const pkg = (x: {
      packageName: string;
      packageVersion: string;
      packageType: string;
      fixedIn: string[] | null;
    }) => ({
      name: clip(x.packageName, 200),
      version: clip(x.packageVersion, 100),
      type: clip(x.packageType, 40),
      fixedIn: (x.fixedIn ?? []).slice(0, 5).map((ver) => clip(ver, 60)),
    });
    /** The path of a system from its packages: the first one somebody can act on, else "no fix yet". */
    const pathOf = (paths: FixPath[]): FixPath => paths.find((p) => p !== "vendor") ?? "vendor";

    const byRepository = new Map<string, typeof repositoryFindings>();
    for (const row of repositoryFindings)
      byRepository.set(row.repositoryId, [...(byRepository.get(row.repositoryId) ?? []), row]);
    let checked = 0;
    for (const repository of repositories) {
      const found = byRepository.get(repository.id);
      if (found?.length) {
        systems.push({
          kind: "repository",
          id: repository.id,
          name: repository.name,
          status: "affected",
          severity: severityOfRank(Math.max(...found.map((x) => x.severityRank))),
          packages: found.map(pkg),
          fixPath: pathOf(found.map((x) => fixPathOf({ kind: "repository", ...x }))),
          reasons: [],
          repository: { id: repository.id, name: repository.name, findingId: found[0]?.id ?? null },
          container: null,
          host: null,
          patch: null,
          kernel: false,
        });
      } else if (repository.lastScanId === null) {
        notChecked.push({
          kind: "repository",
          id: repository.id,
          name: repository.name,
          reason: "never-scanned",
        });
      } else if (lastScanState.get(repository.id) === "failed") {
        notChecked.push({
          kind: "repository",
          id: repository.id,
          name: repository.name,
          reason: "scan-failed",
        });
      } else checked++;
    }

    /* --------------------------- hosts and containers -------------------------- */
    if (hostsOn) {
      const [hosts, containers, imageFindings, packageFindings, kernelFindings, linked] = await Promise.all([
        db.select().from(h).where(eq(h.organizationId, org)).orderBy(asc(h.name)),
        db
          .select({
            hostId: hc.hostId,
            name: hc.name,
            imageRef: hc.imageRef,
            imageId: hc.imageId,
            sourceKey: ci.sourceKey,
            digests: ci.digests,
            hasPackages: sql<boolean>`${ci.packages} is not null`,
            matchedAt: ci.matchedAt,
            matchError: ci.matchError,
          })
          .from(hc)
          .leftJoin(ci, and(eq(ci.organizationId, hc.organizationId), eq(ci.imageId, hc.imageId)))
          .where(eq(hc.organizationId, org))
          .orderBy(asc(hc.name)),
        db
          .select({
            imageId: cf.imageId,
            packageName: cf.packageName,
            packageVersion: cf.packageVersion,
            packageType: cf.packageType,
            fixedIn: cf.fixedIn,
            severityRank: cf.severityRank,
          })
          .from(cf)
          .where(and(eq(cf.organizationId, org), eq(cf.vulnerabilityId, vulnerability.id)))
          .orderBy(asc(cf.packageName)),
        db
          .select({
            hostId: hf.hostId,
            vulnerabilityId: hf.vulnerabilityId,
            packageName: hf.packageName,
            packageVersion: hf.packageVersion,
            packageType: hf.packageType,
            fixedIn: hf.fixedIn,
            fixState: hf.fixState,
            severityRank: hf.severityRank,
          })
          .from(hf)
          .where(and(eq(hf.organizationId, org), eq(hf.vulnerabilityId, vulnerability.id)))
          .orderBy(asc(hf.packageName)),
        db
          .select({
            hostId: kf.hostId,
            packageName: kf.packageName,
            packageVersion: kf.packageVersion,
            fixedIn: kf.fixedIn,
            severityRank: kf.severityRank,
          })
          .from(kf)
          .where(and(eq(kf.organizationId, org), eq(kf.vulnerabilityId, vulnerability.id))),
        // Only repositories the person sees link a container to a repository (ADR 0030).
        visibleRepositoriesByKey(actor),
      ]);
      const updates = await updatesByRef(
        org,
        containers.map((x) => imageRefKey(x.imageRef)).filter((x): x is string => Boolean(x)),
      );
      const hostOf = new Map(hosts.map((host) => [host.id, host]));
      const reporting = (host: (typeof hosts)[number]) =>
        Boolean(host.lastInventoryAt && now.getTime() - host.lastInventoryAt.getTime() < HOST_STALE_AFTER_MS);
      const hostRef = (hostId: string) => {
        const host = hostOf.get(hostId);
        return host ? { id: host.id, name: host.name, reporting: reporting(host) } : null;
      };

      const byImage = new Map<string, typeof imageFindings>();
      for (const row of imageFindings) byImage.set(row.imageId, [...(byImage.get(row.imageId) ?? []), row]);
      for (const container of containers) {
        const host = hostRef(container.hostId);
        if (!host) continue;
        const label = `${container.name} (${host.name})`;
        const found = byImage.get(container.imageId);
        if (found?.length) {
          const repository = container.sourceKey ? (linked.get(container.sourceKey) ?? null) : null;
          const ref = imageRefKey(container.imageRef);
          const update = updateOf(ref ? updates.get(ref) : undefined, container.digests ?? []);
          systems.push({
            kind: "container",
            id: host.id,
            name: clip(container.name, 200),
            status: "affected",
            severity: severityOfRank(Math.max(...found.map((x) => x.severityRank))),
            packages: found.map(pkg),
            fixPath: pathOf(
              found.map((x) =>
                fixPathOf({ kind: "container", ...x, builtByRepository: repository !== null }),
              ),
            ),
            reasons: [],
            repository: repository ? { ...repository, findingId: null } : null,
            container: {
              name: clip(container.name, 200),
              imageRef: clip(container.imageRef, 300),
              update: { state: update.state, tag: update.tag },
            },
            host,
            patch: null,
            kernel: false,
          });
        } else if (!container.hasPackages || container.matchError || !container.matchedAt) {
          notChecked.push({
            kind: "container",
            id: host.id,
            name: clip(label, 300),
            reason: "image-not-checked",
          });
        } else checked++;
      }

      const byHost = new Map<string, typeof packageFindings>();
      for (const row of packageFindings) byHost.set(row.hostId, [...(byHost.get(row.hostId) ?? []), row]);
      const kernelByHost = new Map(kernelFindings.map((row) => [row.hostId, row]));
      for (const host of hosts) {
        const found = byHost.get(host.id) ?? [];
        const kernel = kernelByHost.get(host.id);
        if (found.length > 0 || kernel) {
          // A flaw that depends on configuration: not reachable when every finding of it is ruled out by what the host reported.
          const safe = ssholeSafeReasons(host.sshdFacts);
          const ruledOut = !kernel && safe.length > 0 && found.every(isSsholeFinding);
          const verdicts = found.map((x) => classifyFinding(x, host.aptFacts, now));
          const first = verdicts[0];
          const patchable = found.filter((_, i) => verdicts[i]?.state === "patchable-now");
          const all = [
            ...found.map(pkg),
            ...(kernel ? [pkg({ ...kernel, packageType: "linux-kernel" })] : []),
          ];
          systems.push({
            kind: "host",
            id: host.id,
            name: host.name,
            status: ruledOut ? "not-reachable" : "affected",
            severity: severityOfRank(
              Math.max(...found.map((x) => x.severityRank), kernel?.severityRank ?? 0),
            ),
            packages: all,
            fixPath: pathOf(
              all.map((x) => fixPathOf({ kind: "host", packageType: x.type, fixedIn: x.fixedIn })),
            ),
            reasons: ruledOut ? safe : [],
            repository: null,
            container: null,
            host: { id: host.id, name: host.name, reporting: reporting(host) },
            patch: first
              ? {
                  state: first.state,
                  fixedIn: first.fixedIn,
                  command: upgradeCommand(patchable.map((x) => x.packageName)),
                }
              : null,
            kernel: Boolean(kernel),
          });
        } else if (!reporting(host)) {
          notChecked.push({ kind: "host", id: host.id, name: host.name, reason: "not-reporting" });
        } else if (host.hostPackagesMatchError) {
          notChecked.push({ kind: "host", id: host.id, name: host.name, reason: "packages-not-matched" });
        } else if (!host.hostPackagesAt) {
          notChecked.push({
            kind: "host",
            id: host.id,
            name: host.name,
            reason: "host-packages-not-reported",
          });
        } else checked++;
      }
    }

    if (systems.length === 0) {
      // A vulnerability nothing the person sees has: not a page of theirs.
      throw notFound("Vulnerability");
    }
    const order: Record<SituationStatus, number> = { affected: 0, "not-reachable": 1, "not-checked": 2 };
    systems.sort(
      (a, b) =>
        order[a.status] - order[b.status] ||
        SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity] ||
        a.kind.localeCompare(b.kind) ||
        a.name.localeCompare(b.name),
    );
    const count = (status: SituationStatus) => systems.filter((s) => s.status === status).length;
    return c.json({
      vulnerability: {
        id: vulnerability.id,
        severity: severityOfRank(Math.max(0, ...systems.map((s) => SEVERITY_RANK[s.severity]))),
        cvssScore: vulnerability.cvssScore,
        knownExploited: vulnerability.knownExploited,
        epss: vulnerability.epss,
        publishedAt: vulnerability.publishedAt,
        description: clip(vulnerability.description, 2000) || null,
        urls: (vulnerability.urls ?? []).filter((u) => /^https:\/\//.test(u)).slice(0, 5),
        aliases: (vulnerability.aliases ?? []).slice(0, 10),
      },
      systems: systems.slice(0, SITUATION_MAX_SYSTEMS),
      truncated: Math.max(0, systems.length - SITUATION_MAX_SYSTEMS),
      counts: {
        affected: count("affected"),
        notReachable: count("not-reachable"),
        notChecked: notChecked.length,
        /** Checked and without the vulnerable version: counted, not listed, and never called fine. */
        checked,
        byPath: Object.fromEntries(
          FIX_PATHS.map((p) => [p, systems.filter((s) => s.status === "affected" && s.fixPath === p).length]),
        ) as Record<FixPath, number>,
      },
      notChecked: notChecked.slice(0, SITUATION_MAX_SYSTEMS),
      hostsOn,
    });
  });
