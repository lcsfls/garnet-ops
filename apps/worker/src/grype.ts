import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { SEVERITY_RANK, type Severity, severitySchema } from "@garnetops/core";
import { z } from "zod";
import { env } from "./env.ts";
import { runGrype } from "./grype-run.ts";

/* Only the fields we use. Unknown fields are ignored, missing optional ones tolerated. */
const cvss = z.object({
  version: z.string().optional(),
  vector: z.string().optional(),
  metrics: z.object({ baseScore: z.number().optional() }).partial().optional(),
});

const vulnerability = z.object({
  id: z.string().min(1).max(200),
  namespace: z.string().optional(),
  severity: z.string().optional(),
  description: z.string().optional(),
  urls: z.array(z.string()).optional(),
  cvss: z.array(cvss).optional(),
  epss: z.array(z.object({ epss: z.number() }).partial()).optional(),
  knownExploited: z.array(z.unknown()).optional(),
  fix: z.object({ versions: z.array(z.string()).optional(), state: z.string().optional() }).optional(),
});

const match = z.object({
  vulnerability,
  relatedVulnerabilities: z
    .array(z.object({ id: z.string(), cvss: z.array(cvss).optional() }).partial())
    .optional(),
  artifact: z.object({
    name: z.string().min(1),
    version: z.string(),
    type: z.string(),
    purl: z.string().optional(),
    locations: z.array(z.object({ path: z.string() }).partial()).optional(),
  }),
});

const report = z.object({
  matches: z.array(match),
  descriptor: z
    .object({
      version: z.string().optional(),
      db: z
        .object({ status: z.object({ built: z.string().optional() }).partial().optional() })
        .partial()
        .optional(),
    })
    .partial()
    .optional(),
});

export interface ParsedVulnerability {
  id: string;
  namespace: string | null;
  severity: Severity;
  cvssScore: number | null;
  cvssVector: string | null;
  description: string | null;
  urls: string[];
  aliases: string[];
  knownExploited: boolean;
  epss: number | null;
  publishedAt: Date | null;
  modifiedAt: Date | null;
}

export interface ParsedFinding {
  dedupKey: string;
  vulnerabilityId: string;
  packageName: string;
  packageVersion: string;
  packageType: string;
  packagePurl: string | null;
  fixedIn: string[];
  fixState: string | null;
  locations: string[];
  severity: Severity;
  severityRank: number;
}

export interface ParsedReport {
  vulnerabilities: Map<string, ParsedVulnerability>;
  findings: Map<string, ParsedFinding>;
  grypeVersion: string | null;
  dbBuiltAt: Date | null;
}

function normaliseSeverity(value: string | undefined): Severity {
  const parsed = severitySchema.safeParse((value ?? "unknown").toLowerCase());
  return parsed.success ? parsed.data : "unknown";
}

function bestCvss(list: z.infer<typeof cvss>[] | undefined) {
  // Prefer the newest CVSS version with a score.
  const scored = (list ?? []).filter((c) => typeof c.metrics?.baseScore === "number");
  scored.sort((a, b) => Number.parseFloat(b.version ?? "0") - Number.parseFloat(a.version ?? "0"));
  const top = scored[0];
  return top
    ? { score: top.metrics?.baseScore ?? null, vector: top.vector ?? null }
    : { score: null, vector: null };
}

/** Keeps only http(s) URLs, so nothing like javascript: ever reaches a link in the UI. */
function safeUrls(urls: string[] | undefined): string[] {
  return (urls ?? []).filter((u) => /^https?:\/\//i.test(u)).slice(0, 25);
}

export function parseReport(json: unknown, repositoryId: string): ParsedReport {
  const data = report.parse(json);
  const vulnerabilities = new Map<string, ParsedVulnerability>();
  const findings = new Map<string, ParsedFinding>();

  for (const m of data.matches) {
    const v = m.vulnerability;
    const severity = normaliseSeverity(v.severity);
    const own = bestCvss(v.cvss);
    const related = bestCvss(m.relatedVulnerabilities?.flatMap((r) => r.cvss ?? []));
    const score = own.score ?? related.score;
    if (!vulnerabilities.has(v.id)) {
      vulnerabilities.set(v.id, {
        id: v.id,
        namespace: v.namespace ?? null,
        severity,
        cvssScore: score,
        cvssVector: own.vector ?? related.vector,
        description: v.description?.slice(0, 4000) ?? null,
        urls: safeUrls(v.urls),
        aliases: (m.relatedVulnerabilities ?? [])
          .map((r) => r.id)
          .filter((id): id is string => Boolean(id) && id !== v.id),
        knownExploited: (v.knownExploited?.length ?? 0) > 0,
        epss: v.epss?.[0]?.epss ?? null,
        publishedAt: null,
        modifiedAt: null,
      });
    }

    const a = m.artifact;
    const dedupKey = `${repositoryId}|${v.id}|${a.type}|${a.name}`;
    const locations = (a.locations ?? []).map((l) => l.path).filter((p): p is string => Boolean(p));
    const existing = findings.get(dedupKey);
    if (existing) {
      // Same vulnerability in the same package found in several places: merge locations.
      existing.locations = [...new Set([...existing.locations, ...locations])].slice(0, 50);
      continue;
    }
    findings.set(dedupKey, {
      dedupKey,
      vulnerabilityId: v.id,
      packageName: a.name.slice(0, 300),
      packageVersion: a.version.slice(0, 200),
      packageType: a.type.slice(0, 50),
      packagePurl: a.purl?.slice(0, 500) ?? null,
      fixedIn: (v.fix?.versions ?? []).slice(0, 10),
      fixState: v.fix?.state ?? null,
      locations: locations.slice(0, 50),
      severity,
      severityRank: SEVERITY_RANK[severity],
    });
  }

  const built = data.descriptor?.db?.status?.built;
  return {
    vulnerabilities,
    findings,
    grypeVersion: data.descriptor?.version ?? null,
    dbBuiltAt: built ? new Date(built) : null,
  };
}

/** Runs grype in this process's container (no scanner service) and returns its parsed report. */
export async function scanTarget(target: string, outDir: string): Promise<unknown> {
  const out = await runGrype(env.GARNETOPS_GRYPE_BIN, env.GARNETOPS_GRYPE_DB_DIR, target, outDir);
  return JSON.parse(await readFile(out, "utf8"));
}

/** grype's datetime text ("2021-02-15 13:15:12.56+00:00") as an instant, or null. */
export function parseDbDate(value: unknown): Date | null {
  if (typeof value !== "string" || !value) return null;
  const date = new Date(value.replace(" ", "T"));
  return Number.isNaN(date.getTime()) ? null : date;
}

/**
 * Adds publication and change dates from the local vulnerability database; grype's JSON
 * report does not carry them. The publication date is the earliest one of the advisory and the
 * CVEs it aliases (a GHSA is often published weeks after its CVE), the change date the latest.
 * The database is opened read-only; a missing or unreadable database
 * leaves the dates empty instead of failing the scan.
 */
export function addAdvisoryDates(vulnerabilities: Map<string, ParsedVulnerability>, dbDir: string): void {
  if (vulnerabilities.size === 0) return;
  const names = new Set<string>();
  for (const v of vulnerabilities.values()) for (const n of [v.id, ...v.aliases]) names.add(n);
  const dates = new Map<string, { published: Date | null; modified: Date | null }>();
  let db: DatabaseSync | null = null;
  try {
    db = new DatabaseSync(join(dbDir, "6", "vulnerability.db"), { readOnly: true });
    const list = [...names];
    for (let i = 0; i < list.length; i += 500) {
      const chunk = list.slice(i, i + 500);
      const rows = db
        .prepare(
          `select name, min(published_date) as published, max(modified_date) as modified
             from vulnerability_handles where name collate nocase in (${chunk.map(() => "?").join(",")})
             group by name`,
        )
        .all(...chunk);
      for (const row of rows) {
        dates.set(String(row.name).toUpperCase(), {
          published: parseDbDate(row.published),
          modified: parseDbDate(row.modified),
        });
      }
    }
  } catch (error) {
    console.error("advisory dates: the vulnerability database could not be read:", (error as Error).message);
    return;
  } finally {
    db?.close();
  }
  const earliest = (values: (Date | null | undefined)[]) =>
    values.filter((d): d is Date => d instanceof Date).sort((a, b) => a.getTime() - b.getTime())[0] ?? null;
  const latest = (values: (Date | null | undefined)[]) =>
    values.filter((d): d is Date => d instanceof Date).sort((a, b) => b.getTime() - a.getTime())[0] ?? null;
  for (const v of vulnerabilities.values()) {
    const own = dates.get(v.id.toUpperCase());
    const related = v.aliases.map((a) => dates.get(a.toUpperCase()));
    v.publishedAt = earliest([own?.published, ...related.map((d) => d?.published)]);
    v.modifiedAt = latest([own?.modified, ...related.map((d) => d?.modified)]);
  }
}
