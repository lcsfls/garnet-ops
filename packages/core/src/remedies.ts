/**
 * "Fix first" on the overview: the open findings grouped by the upgrade that closes them, and the facts behind the
 * overview's top statement. Pure functions over the findings the viewer may see; the API loads them.
 *
 * A remedy is one package of one ecosystem at one installed version, across every repository that has it. Its target is
 * always one of the advisories' own fixed versions (no registry is asked: GarnetOps works offline), chosen as the fix
 * proposals choose theirs (selectTarget in versions.ts): per vulnerability the lowest fixed version in the installed
 * major release, and the highest of those for the group. Pre-releases are never a target. When a vulnerability is fixed
 * only in a later major release, the group has no single fix within its major release: the target then closes what the
 * installed major release can close, and the rest is listed with the later version that would close everything.
 */
import { SEVERITIES, type Severity } from "./index.ts";
import {
  compareVersions,
  type Ecosystem,
  ecosystemOfPackageType,
  isPrerelease,
  parseVersion,
  schemeOfPackageType,
  selectTarget,
  type VersionScheme,
} from "./versions.ts";

export interface RemedyFinding {
  id: string;
  repositoryId: string;
  repositoryName: string;
  vulnerabilityId: string;
  severity: string;
  /** 5 for critical down to 1 for low (finding.severityRank). */
  severityRank: number;
  packageType: string;
  packageName: string;
  packageVersion: string;
  fixedIn: string[];
  knownExploited: boolean;
}

export interface Remedy {
  /** Stable for the group: package type, name and installed version. */
  key: string;
  packageType: string;
  packageName: string;
  ecosystem: Ecosystem | null;
  fromVersion: string;
  /** The version to upgrade to, or null when no fixed version in the installed major release is known. */
  toVersion: string | null;
  /** The upgrade closes every open finding of the group. False: "no single fix". */
  complete: boolean;
  /** When the group has no single fix: the lowest later version that would close everything, if one is known. */
  laterVersion: string | null;
  /** What the upgrade closes. */
  closes: {
    findingIds: string[];
    total: number;
    /** Findings per severity (critical, high, medium, low, negligible, unknown); only severities that occur. */
    bySeverity: Partial<Record<Severity, number>>;
    knownExploited: number;
    vulnerabilityIds: string[];
    /** The highest severity rank among them, 0 when it closes nothing. */
    worstRank: number;
  };
  /** Vulnerabilities the upgrade leaves open (later major release only, or no usable fixed version). */
  remainingVulnerabilityIds: string[];
  /** Open findings of the group with a fixed version, closed or not. */
  findings: number;
  /** Known exploited findings in the group, closed or not. */
  knownExploited: number;
  repositories: { id: string; name: string }[];
}

const severityOrder = (s: string) => {
  const i = (SEVERITIES as readonly string[]).indexOf(s);
  return i < 0 ? SEVERITIES.length : i;
};

/** The fixed versions a target may be chosen from: parseable, newer than the installed version, never a pre-release. */
function usableFixes(scheme: VersionScheme, installed: string, fixedIn: string[]): string[] {
  return fixedIn.filter((raw) => {
    const parsed = parseVersion(scheme, raw);
    return parsed !== null && !isPrerelease(parsed) && (compareVersions(scheme, raw, installed) ?? 0) > 0;
  });
}

function remedyOf(group: RemedyFinding[]): Remedy {
  const first = group[0] as RemedyFinding;
  const scheme = schemeOfPackageType(first.packageType);
  const installed = first.packageVersion;
  const installedMajor = parseVersion(scheme, installed)?.nums[0] ?? null;

  const fixesOf = new Map<string, Set<string>>();
  for (const f of group) {
    const set = fixesOf.get(f.vulnerabilityId) ?? new Set<string>();
    for (const v of usableFixes(scheme, installed, f.fixedIn)) set.add(v);
    fixesOf.set(f.vulnerabilityId, set);
  }
  const vulnerabilities = [...fixesOf].map(([id, set]) => ({ id, fixedIn: [...set] }));
  const sameMajor = vulnerabilities.map((v) => ({
    id: v.id,
    fixedIn: v.fixedIn.filter((raw) => parseVersion(scheme, raw)?.nums[0] === installedMajor),
  }));

  // Within the installed major release only; the vulnerabilities fixed only later stay open.
  const inMajor =
    installedMajor === null ? null : selectTarget({ scheme, installed, vulnerabilities: sameMajor });
  // Across major releases: the version that would close everything, named when the major release is not enough.
  const anyMajor = selectTarget({ scheme, installed, vulnerabilities });
  const closedIds = new Set(inMajor?.fixes ?? []);
  const complete = inMajor !== null && inMajor.unresolved.length === 0;

  const closed = group.filter((f) => closedIds.has(f.vulnerabilityId));
  const bySeverity: Partial<Record<Severity, number>> = {};
  for (const f of closed) bySeverity[f.severity as Severity] = (bySeverity[f.severity as Severity] ?? 0) + 1;
  const repositories = new Map<string, string>();
  for (const f of group) repositories.set(f.repositoryId, f.repositoryName);

  return {
    key: [first.packageType, first.packageName, installed].join("\u001f"),
    packageType: first.packageType,
    packageName: first.packageName,
    ecosystem: ecosystemOfPackageType(first.packageType),
    fromVersion: installed,
    toVersion: inMajor?.version ?? null,
    complete,
    laterVersion:
      !complete && anyMajor && anyMajor.unresolved.length === 0 && anyMajor.majorUpgrade
        ? anyMajor.version
        : null,
    closes: {
      findingIds: closed.map((f) => f.id).sort(),
      total: closed.length,
      bySeverity: Object.fromEntries(
        Object.entries(bySeverity).sort(([a], [b]) => severityOrder(a) - severityOrder(b)),
      ) as Partial<Record<Severity, number>>,
      knownExploited: closed.filter((f) => f.knownExploited).length,
      vulnerabilityIds: [...closedIds].sort(),
      worstRank: closed.reduce((worst, f) => Math.max(worst, f.severityRank), 0),
    },
    remainingVulnerabilityIds: vulnerabilities
      .map((v) => v.id)
      .filter((id) => !closedIds.has(id))
      .sort(),
    findings: group.length,
    knownExploited: group.filter((f) => f.knownExploited).length,
    repositories: [...repositories]
      .map(([id, name]) => ({ id, name }))
      .sort((a, b) => a.name.localeCompare(b.name) || a.id.localeCompare(b.id)),
  };
}

/**
 * The open findings with a fixed version, grouped by remedy, in the order to fix them: groups with a known exploited
 * finding first, then by the worst severity the upgrade closes, then by how many findings it closes.
 */
export function groupRemedies(findings: RemedyFinding[]): Remedy[] {
  const groups = new Map<string, RemedyFinding[]>();
  for (const f of findings) {
    if (f.fixedIn.length === 0) continue;
    const key = [f.packageType, f.packageName, f.packageVersion].join("\u001f");
    const list = groups.get(key) ?? [];
    list.push(f);
    groups.set(key, list);
  }
  return [...groups.values()]
    .map(remedyOf)
    .sort(
      (a, b) =>
        Number(b.knownExploited > 0) - Number(a.knownExploited > 0) ||
        b.closes.worstRank - a.closes.worstRank ||
        b.closes.total - a.closes.total ||
        a.packageName.localeCompare(b.packageName) ||
        a.fromVersion.localeCompare(b.fromVersion),
    );
}

export interface RemedySummary {
  /** Upgrades that close at least one finding. */
  upgrades: number;
  /** Findings those upgrades close. */
  closes: number;
  /** Every open finding the overview counts, with or without a fixed version. */
  open: number;
}

export function summarizeRemedies(remedies: Remedy[], open: number): RemedySummary {
  const useful = remedies.filter((r) => r.closes.total > 0);
  return { upgrades: useful.length, closes: useful.reduce((sum, r) => sum + r.closes.total, 0), open };
}

export interface HeadlineFacts {
  /** The worst severity that is open, as far as the top statement cares: critical, high, or none of the two. */
  level: "critical" | "high" | "none";
  /** Open findings of that severity (0 for none). */
  count: number;
  /** Repositories they are in. */
  repositories: number;
  /** The one package and version they all come from, or null when they come from several. */
  package: { name: string; version: string } | null;
  /** Distinct packages (name and version) they come from. */
  packages: number;
  /** The one upgrade that closes all of them, or null. */
  oneUpgrade: { remedyKey: string; packageName: string; fromVersion: string; toVersion: string } | null;
  /** How many of them an upgrade closes, and how many upgrades that takes. */
  fixable: number;
  upgrades: number;
  /** How many of them are known to be exploited (CISA KEV). */
  knownExploited: number;
}

/**
 * The facts of the overview's top statement, e.g. "2 critical findings in 2 repositories. Both come from minimist 1.2.0.
 * One upgrade fixes both. None is known to be exploited." `findings` are the viewer's open findings (at least every
 * critical and high one), `remedies` the groups of groupRemedies over the same findings.
 */
export function headlineFacts(findings: RemedyFinding[], remedies: Remedy[]): HeadlineFacts {
  const level = findings.some((f) => f.severity === "critical")
    ? "critical"
    : findings.some((f) => f.severity === "high")
      ? "high"
      : "none";
  if (level === "none") {
    return {
      level,
      count: 0,
      repositories: 0,
      package: null,
      packages: 0,
      oneUpgrade: null,
      fixable: 0,
      upgrades: 0,
      knownExploited: 0,
    };
  }
  const at = findings.filter((f) => f.severity === level);
  const ids = new Set(at.map((f) => f.id));
  const packages = new Map<string, { name: string; version: string }>();
  for (const f of at)
    packages.set([f.packageType, f.packageName, f.packageVersion].join("\u001f"), {
      name: f.packageName,
      version: f.packageVersion,
    });
  const helping = remedies
    .map((r) => ({ r, n: r.closes.findingIds.filter((id) => ids.has(id)).length }))
    .filter((x) => x.n > 0 && x.r.toVersion !== null);
  const fixable = helping.reduce((sum, x) => sum + x.n, 0);
  const one = helping.length === 1 && helping[0]?.n === at.length ? helping[0].r : null;
  return {
    level,
    count: at.length,
    repositories: new Set(at.map((f) => f.repositoryId)).size,
    package: packages.size === 1 ? ([...packages.values()][0] ?? null) : null,
    packages: packages.size,
    oneUpgrade:
      one?.toVersion != null
        ? {
            remedyKey: one.key,
            packageName: one.packageName,
            fromVersion: one.fromVersion,
            toVersion: one.toVersion,
          }
        : null,
    fixable,
    upgrades: helping.length,
    knownExploited: at.filter((f) => f.knownExploited).length,
  };
}
