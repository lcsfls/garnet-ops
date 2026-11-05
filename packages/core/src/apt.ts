/**
 * What can be patched now on an apt host (Debian, Ubuntu). The vulnerability database says in which version the distribution fixed a
 * flaw; whether this host can install that version today depends on its own apt sources: a local mirror may not have it yet, `apt
 * update` may not have run for days, the fix may exist only in Ubuntu Pro (ESM), or the package may come from a third-party source
 * the distribution's security data does not cover at all. The systemd agent reports what the host's apt lists offer for its installed
 * packages (read from `/var/lib/apt/lists`, nothing fetched); these pure functions turn that into a verdict per finding and a few
 * hints per host. Nothing here asks a mirror anything: GarnetOps stays air-gap capable.
 *
 * Everything in the facts comes from the host and is hostile text; it is schema-checked and cut before it is stored
 * (`aptFactsSchema` in agent.ts) and only ever shown as text.
 */
import { compareDebVersions, debUpstream, parseDebVersion } from "./deb-version.ts";
import { EOL_DATA } from "./eol-data.ts";
import { judgeSoftware } from "./software.ts";

/** One apt source as the lists name it: a host, a path, a suite (`noble-security`) and what its Release file says. */
export interface AptSource {
  id: number;
  host: string;
  path: string;
  suite: string;
  components: string[];
  /** Release file fields: `Origin`, `Label`, `Codename`. */
  origin: string | null;
  label: string | null;
  codename: string | null;
  /** The Release file's `Date:` (when the archive built the index), ISO 8601. */
  date: string | null;
  /** The Release file's modification time on the host, ISO 8601. */
  fetchedAt: string | null;
}

/** An installed package the lists have something to say about: newer versions offered, or a third-party origin. */
export interface AptPackage {
  name: string;
  arch: string;
  installed: string;
  /** The sources that offer exactly the installed version. */
  from: number[];
  /** The newest version each source offers, where it is newer than the installed one. */
  offers: { source: number; version: string }[];
}

export interface AptFacts {
  /** When `apt update` last ran, as far as the host shows it (stamps and the lists' modification times), ISO 8601. */
  listsUpdatedAt: string | null;
  /** dpkg's architecture of the host ("amd64", "arm64"). */
  arch: string | null;
  sources: AptSource[];
  packages: AptPackage[];
}

/** Lists older than this count as stale: `apt update` has not run, so what the host "offers" is old news. */
export const APT_LISTS_STALE_DAYS = 3;
/** A security pocket whose index is this much older than the last `apt update` comes from a mirror that lags. */
export const SECURITY_INDEX_LAG_DAYS = 2;
const DAY_MS = 86_400_000;

export const PATCH_STATES = [
  "patchable-now",
  "waiting-for-mirror",
  "lists-stale",
  "pro-only",
  "no-fix-yet",
  "unknown",
] as const;
export type PatchState = (typeof PATCH_STATES)[number];

const DISTRIBUTION_ORIGINS = new Set(["ubuntu", "debian"]);
const OFFICIAL_HOSTS =
  /^(?:(?:[a-z]{2}\.)?archive\.ubuntu\.com|security\.ubuntu\.com|ports\.ubuntu\.com|deb\.debian\.org|security\.debian\.org)$/;

/** A source of the distribution itself (its own archive or a mirror of it): Origin "Ubuntu" or "Debian", or an official host. */
export function isDistributionSource(s: AptSource): boolean {
  if (s.origin) return DISTRIBUTION_ORIGINS.has(s.origin.trim().toLowerCase());
  return OFFICIAL_HOSTS.test(s.host);
}

/** Ubuntu Pro's Expanded Security Maintenance (`esm.ubuntu.com`, Origin "UbuntuESM", "UbuntuESMApps"). */
export function isEsmSource(s: AptSource): boolean {
  return s.host === "esm.ubuntu.com" || /^ubuntuesm/i.test(s.origin ?? "");
}

export const isSecurityPocket = (s: AptSource): boolean => /-security$|\/updates$/.test(s.suite);

/** Where Ubuntu and Debian publish security updates first; any other host serving a security pocket is a mirror. */
export function isOfficialSecurityHost(s: AptSource): boolean {
  if (s.host === "security.ubuntu.com" || s.host === "ports.ubuntu.com") return true;
  if (s.host === "security.debian.org") return true;
  return s.host === "deb.debian.org" && s.path.replace(/\/+$/, "") === "debian-security";
}

/** A version only Ubuntu Pro ships: "+esm1" or "~esm1" in the Debian revision. */
export const isEsmVersion = (version: string): boolean =>
  /[+~]esm\d*/i.test(parseDebVersion(version)?.revision ?? "");

/** How many whole days ago the lists were updated; null when the host does not show it. */
export function listsAgeDays(facts: AptFacts, now: Date): number | null {
  const at = facts.listsUpdatedAt ? Date.parse(facts.listsUpdatedAt) : Number.NaN;
  return Number.isNaN(at) ? null : Math.max(0, Math.floor((now.getTime() - at) / DAY_MS));
}

const listsStale = (facts: AptFacts, now: Date) => {
  const age = listsAgeDays(facts, now);
  return age !== null && age >= APT_LISTS_STALE_DAYS;
};

export interface PatchFindingInput {
  packageName: string;
  packageVersion: string;
  fixedIn: string[] | null;
  fixState: string | null;
}

export interface PatchVerdict {
  state: PatchState;
  /** The lowest fixed version above the installed one: what has to be installed. */
  fixedIn: string | null;
  /** The newest version a configured source offers for the package (above the installed one), and which source. */
  offered: { version: string; source: number } | null;
}

/** The apt entry of a finding's package: the same name and installed version (several architectures can share a name). */
function aptPackage(facts: AptFacts, f: PatchFindingInput): AptPackage | undefined {
  return (
    facts.packages.find((p) => p.name === f.packageName && p.installed === f.packageVersion) ??
    facts.packages.find((p) => p.name === f.packageName)
  );
}

/**
 * Whether a finding can be patched now from the host's own apt sources:
 * - `patchable-now`: a configured source offers a version at least as new as the fix (Debian version order);
 * - `pro-only`: the fix exists only as an Ubuntu Pro (`+esm`) build and no ESM source is configured;
 * - `lists-stale`: no source offers the fix, but the lists are older than three days, so `apt update` may well bring it;
 * - `waiting-for-mirror`: the distribution has a fix, the fresh lists do not offer it (a mirror that has not caught up, or a missing
 *   pocket such as `-security`);
 * - `no-fix-yet`: the distribution has no fixed version;
 * - `unknown`: the host reported no apt facts (an older agent, another package manager).
 */
export function classifyFinding(f: PatchFindingInput, facts: AptFacts | null, now: Date): PatchVerdict {
  const fixes = (f.fixedIn ?? [])
    .filter((v) => parseDebVersion(v) !== null && compareDebVersions(v, f.packageVersion) > 0)
    .sort(compareDebVersions);
  const fixedIn = fixes[0] ?? null;
  if (!fixedIn) return { state: "no-fix-yet", fixedIn: null, offered: null };
  if (!facts) return { state: "unknown", fixedIn, offered: null };
  const offers = aptPackage(facts, f)?.offers ?? [];
  const best = offers.reduce<{ version: string; source: number } | null>(
    (top, o) => (!top || compareDebVersions(o.version, top.version) > 0 ? o : top),
    null,
  );
  const offered = best ? { version: best.version, source: best.source } : null;
  if (offered && compareDebVersions(offered.version, fixedIn) >= 0)
    return { state: "patchable-now", fixedIn, offered };
  if (fixes.every(isEsmVersion) && !facts.sources.some(isEsmSource))
    return { state: "pro-only", fixedIn, offered };
  if (listsStale(facts, now)) return { state: "lists-stale", fixedIn, offered };
  return { state: "waiting-for-mirror", fixedIn, offered };
}

/** A Debian package name (policy 5.6.1); anything else never goes into a command. */
const PACKAGE_NAME = /^[a-z0-9][a-z0-9+.-]{0,99}$/;
const MAX_COMMAND_PACKAGES = 50;

/** The command that installs the fixed versions of these packages, and nothing else; null when there is none to name. */
export function upgradeCommand(names: readonly string[]): string | null {
  const valid = [...new Set(names.filter((n) => PACKAGE_NAME.test(n)))].sort().slice(0, MAX_COMMAND_PACKAGES);
  return valid.length ? `sudo apt install --only-upgrade ${valid.join(" ")}` : null;
}

export interface PatchSummary {
  counts: Record<PatchState, number>;
  listsAgeDays: number | null;
  listsStale: boolean;
  /** Installs every package that is patchable now. */
  command: string | null;
}

export function patchSummary(
  findings: readonly (PatchFindingInput & { verdict: PatchVerdict })[],
  facts: AptFacts | null,
  now: Date,
): PatchSummary {
  const counts = Object.fromEntries(PATCH_STATES.map((s) => [s, 0])) as Record<PatchState, number>;
  for (const f of findings) counts[f.verdict.state] += 1;
  return {
    counts,
    listsAgeDays: facts ? listsAgeDays(facts, now) : null,
    listsStale: facts ? listsStale(facts, now) : false,
    command: upgradeCommand(
      findings.filter((f) => f.verdict.state === "patchable-now").map((f) => f.packageName),
    ),
  };
}

/* -------------------------------------------------------------------------- */
/* Hints per host: where security updates come from                            */
/* -------------------------------------------------------------------------- */

export type AptHint =
  | {
      kind: "securityFromMirror";
      /** The mirror that serves the security pocket. */
      host: string;
      suite: string;
      /** How much older its index is than the last `apt update`, in whole days; null when unknown. */
      lagDays: number | null;
      /** The sources line Ubuntu and Debian recommend for security updates. */
      line: string;
    }
  | { kind: "noSecuritySource"; line: string };

const DEFAULT_COMPONENTS = { ubuntu: ["main", "restricted", "universe", "multiverse"], debian: ["main"] };
const VALID_WORD = /^[a-z0-9][a-z0-9._+-]{0,39}$/;

/** The sources line for the distribution's own security pocket; null when the distribution or its release is unknown. */
export function securitySourcesLine(facts: AptFacts, components?: readonly string[]): string | null {
  const own = facts.sources.filter(isDistributionSource);
  const ubuntu = own.some((s) => /ubuntu/i.test(s.origin ?? s.host));
  const debian = !ubuntu && own.some((s) => /debian/i.test(s.origin ?? s.host));
  if (!ubuntu && !debian) return null;
  // Debian's security index names itself "bookworm-security": the release is the part before the pocket.
  const codename =
    own.map((s) => (s.codename ?? s.suite).replace(/[-/].*$/, "")).find((c) => VALID_WORD.test(c)) ?? null;
  if (!codename) return null;
  const parts = (components?.length ? components : own.flatMap((s) => s.components)).filter((c) =>
    VALID_WORD.test(c),
  );
  const list = [...new Set(parts.length ? parts : DEFAULT_COMPONENTS[ubuntu ? "ubuntu" : "debian"])].join(
    " ",
  );
  if (debian) return `deb http://deb.debian.org/debian-security ${codename}-security ${list}`;
  const ports = facts.arch !== null && facts.arch !== "amd64" && facts.arch !== "i386";
  return ports
    ? `deb http://ports.ubuntu.com/ubuntu-ports ${codename}-security ${list}`
    : `deb http://security.ubuntu.com/ubuntu ${codename}-security ${list}`;
}

/**
 * Where the host takes security updates from. Ubuntu and Debian recommend taking the `-security` pocket directly from their security
 * servers, because mirrors can lag behind: a hint names the mirror when the host has a finding waiting for it, or when its security
 * index is much older than the last `apt update`. A host without any security pocket gets a hint too.
 */
export function aptHints(facts: AptFacts | null, waitingForMirror: number): AptHint[] {
  if (!facts) return [];
  const own = facts.sources.filter(isDistributionSource);
  if (own.length === 0) return [];
  const security = own.filter(isSecurityPocket);
  if (security.length === 0) {
    const line = securitySourcesLine(facts);
    return line ? [{ kind: "noSecuritySource", line }] : [];
  }
  if (security.some(isOfficialSecurityHost)) return [];
  const updated = facts.listsUpdatedAt ? Date.parse(facts.listsUpdatedAt) : Number.NaN;
  const hints: AptHint[] = [];
  for (const s of security) {
    const date = s.date ? Date.parse(s.date) : Number.NaN;
    const lagDays =
      Number.isNaN(updated) || Number.isNaN(date) ? null : Math.max(0, Math.floor((updated - date) / DAY_MS));
    if (waitingForMirror === 0 && (lagDays === null || lagDays < SECURITY_INDEX_LAG_DAYS)) continue;
    const line = securitySourcesLine(facts, s.components);
    if (line) hints.push({ kind: "securityFromMirror", host: s.host, suite: s.suite, lagDays, line });
  }
  return hints.slice(0, 1);
}

/* -------------------------------------------------------------------------- */
/* Third-party packages                                                        */
/* -------------------------------------------------------------------------- */

export interface ThirdPartyOrigin {
  /** The source's Origin field, or its host and path. */
  origin: string;
  host: string;
  packages: { name: string; installed: string }[];
}

export interface PhpLineJudgement {
  /** The upstream version ("8.3.14" of "8.3.14-1+ubuntu24.04.1+deb.sury.org+1"). */
  version: string;
  status: "endOfLife" | "outdated" | "current" | "unknown";
  cycle: string | null;
  eol: string | null;
  latest: string | null;
  severity: "high" | "medium" | null;
  /** The packages of this version (php8.3, php8.3-cli, php8.3-fpm, ...). */
  packages: string[];
}

const MAX_THIRD_PARTY_LISTED = 200;

/**
 * Installed packages whose version only a source outside the distribution offers (a PPA such as ondrej/php, packages.sury.org, a
 * vendor's repository). The distribution's security data does not cover them, so no finding about them means nothing; the host page
 * says so, per origin.
 */
export function thirdPartyPackages(facts: AptFacts | null): ThirdPartyOrigin[] {
  if (!facts) return [];
  const byId = new Map(facts.sources.map((s) => [s.id, s]));
  const origins = new Map<string, ThirdPartyOrigin>();
  for (const p of facts.packages) {
    const from = p.from.map((id) => byId.get(id)).filter((s): s is AptSource => s !== undefined);
    if (from.length === 0 || from.some(isDistributionSource)) continue;
    const source = from[0] as AptSource;
    const origin = source.origin ?? `${source.host}/${source.path}`.replace(/\/+$/, "");
    const entry = origins.get(origin) ?? { origin, host: source.host, packages: [] };
    if (entry.packages.length < MAX_THIRD_PARTY_LISTED)
      entry.packages.push({ name: p.name, installed: p.installed });
    origins.set(origin, entry);
  }
  return [...origins.values()]
    .map((o) => ({ ...o, packages: o.packages.sort((a, b) => a.name.localeCompare(b.name)) }))
    .sort((a, b) => a.origin.localeCompare(b.origin));
}

/** PHP's own packages ("php8.3", "php8.3-cli", "php-common" is not one: it names no line). */
const PHP_PACKAGE = /^php(\d+\.\d+)(?:-[a-z0-9.+-]+)?$/;

/**
 * PHP from a third-party source (ondrej/php, packages.sury.org) is judged by its upstream version against PHP's end-of-life data,
 * as the website rules judge a PHP version a site names (ADR 0038): a line without security fixes, or a version behind the latest of
 * its line. The version of a package is exact, so it counts like a version the site states itself.
 */
export function thirdPartyPhp(
  origins: readonly ThirdPartyOrigin[],
  now: Date,
  data = EOL_DATA,
): PhpLineJudgement[] {
  const byVersion = new Map<string, string[]>();
  for (const o of origins) {
    for (const p of o.packages) {
      if (!PHP_PACKAGE.test(p.name)) continue;
      const upstream = debUpstream(p.installed)?.replace(/[^0-9.].*$/, "");
      if (!upstream || !/^\d+\.\d+\.\d+$/.test(upstream)) continue;
      byVersion.set(upstream, [...(byVersion.get(upstream) ?? []), p.name]);
    }
  }
  return [...byVersion.entries()]
    .map(([version, packages]): PhpLineJudgement => {
      const j = judgeSoftware({ product: "php", version, source: "plugin" }, now, data);
      const status = j.status === "distribution" ? "unknown" : j.status;
      const severity = status === "endOfLife" ? "high" : status === "outdated" ? "medium" : null;
      return {
        version,
        status,
        cycle: j.cycle,
        eol: j.eol,
        latest: j.latest,
        severity,
        packages: packages.sort(),
      };
    })
    .sort((a, b) => compareDebVersions(b.version, a.version));
}
