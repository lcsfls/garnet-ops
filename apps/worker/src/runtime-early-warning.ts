/**
 * Early warnings for what runs (ADR 0041). The hourly tick matches images, host kernels and host packages again whenever a newer
 * vulnerability database arrives (ADR 0034, 0037). A finding that such a match adds, and whose advisory was published or changed
 * after the database of the previous match, came with the new database: it is recorded as an early warning. It is a finding of the
 * image or host at once (no scan has to confirm it); the warning stays open while the finding exists and closes as cleared when a
 * later match no longer has it. A first match, or a package that is simply new on the host, never makes a warning.
 */
import { newId } from "@garnetops/core";
import { schema } from "@garnetops/db";
import { and, eq, inArray } from "drizzle-orm";
import type { db } from "./db.ts";
import type { ParsedFinding, ParsedVulnerability } from "./grype.ts";
import { tellUsers } from "./user-notify.ts";

type Tx = Parameters<Parameters<typeof db.transaction>[0]>[0];
type Kind = (typeof schema.runtimeEarlyWarning.$inferSelect)["kind"];

export interface RuntimeSubject {
  organizationId: string;
  kind: Kind;
  /** The image id for an image, the host id otherwise. */
  subjectId: string;
  hostId: string | null;
}

/** What identifies one finding of a subject across matches. The type is left out: host packages store their own. */
export const runtimeKey = (f: { vulnerabilityId: string; packageName: string }) =>
  `${f.vulnerabilityId}|${f.packageName}`;

/** The latest of an advisory's published and changed dates, or null when it has neither. */
function changedAt(v: ParsedVulnerability | undefined): Date | null {
  const dates = [v?.publishedAt, v?.modifiedAt].filter((d): d is Date => d instanceof Date);
  return dates.length ? new Date(Math.max(...dates.map((d) => d.getTime()))) : null;
}

/**
 * Inside the transaction that replaces a subject's findings: closes the open warnings whose finding is gone and records the new
 * findings that the newer database brought. Returns how many it recorded.
 */
export async function recordRuntimeWarnings(
  tx: Tx,
  subject: RuntimeSubject,
  input: {
    /** The subject's finding keys before this match. */
    previous: Set<string>;
    /** The database build of the previous match; null for a first match. */
    previousDb: Date | null;
    findings: ParsedFinding[];
    vulnerabilities: Map<string, ParsedVulnerability>;
    dbBuiltAt: Date | null;
    now: Date;
  },
): Promise<number> {
  const r = schema.runtimeEarlyWarning;
  const current = new Set(input.findings.map(runtimeKey));
  const open = await tx
    .select({ id: r.id, vulnerabilityId: r.vulnerabilityId, packageName: r.packageName })
    .from(r)
    .where(
      and(
        eq(r.organizationId, subject.organizationId),
        eq(r.kind, subject.kind),
        eq(r.subjectId, subject.subjectId),
        eq(r.state, "open"),
      ),
    );
  const gone = open.filter((w) => !current.has(runtimeKey(w))).map((w) => w.id);
  if (gone.length > 0) {
    await tx.update(r).set({ state: "cleared", closedAt: input.now }).where(inArray(r.id, gone));
  }

  const previousDb = input.previousDb;
  // A first match has nothing to compare with; a match with the same or an older database brings nothing new.
  if (!previousDb || (input.dbBuiltAt && input.dbBuiltAt <= previousDb)) return 0;
  const fresh = input.findings.filter((f) => {
    if (input.previous.has(runtimeKey(f))) return false;
    const changed = changedAt(input.vulnerabilities.get(f.vulnerabilityId));
    return changed !== null && changed > previousDb;
  });
  if (fresh.length === 0) return 0;
  const added = await tx
    .insert(r)
    .values(
      fresh.map((f) => ({
        id: newId("rew"),
        organizationId: subject.organizationId,
        kind: subject.kind,
        subjectId: subject.subjectId,
        hostId: subject.hostId,
        vulnerabilityId: f.vulnerabilityId,
        packageName: f.packageName,
        packageVersion: f.packageVersion,
        packageType: f.packageType,
        fixedIn: f.fixedIn,
        severity: f.severity,
        severityRank: f.severityRank,
        dbBuiltAt: input.dbBuiltAt,
        detectedAt: input.now,
      })),
    )
    .onConflictDoNothing()
    .returning({ id: r.id });
  return added.length;
}

/** One personal notification per subject that got new warnings; never throws. */
export async function tellAboutRuntimeWarnings(
  subject: RuntimeSubject & { label: string },
  count: number,
): Promise<void> {
  if (count === 0) return;
  await tellUsers({
    organizationId: subject.organizationId,
    titleKey: "hostsNewAdvisory",
    params: { subject: subject.label, count },
    link: "/early-warnings?source=hosts",
  });
}
