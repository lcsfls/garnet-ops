/**
 * Version comparison and the choice of a fix version for the Fix proposals page (ADR 0014).
 *
 * No dependency: a small comparator per version scheme. Package ecosystems do not agree on
 * what a version is, so each scheme is parsed on its own and a string that does not parse
 * is "unknown", never guessed at:
 *
 *  - semver-like (npm, Cargo, Composer, Go): numeric core with up to six parts, an optional
 *    pre-release, build metadata ignored. A leading "v" is accepted.
 *  - PEP 440 (Python): epoch, release, pre-release, post-release, dev release; local
 *    versions after "+" are ignored.
 *  - generic (everything else): numeric parts only, used for display and sorting.
 *
 * The scheme only decides the order of versions. Whether a fixed version really fixes a
 * vulnerability is decided by the next scan, never here.
 */

export const ECOSYSTEMS = ["npm", "pypi", "go", "cargo", "composer"] as const;
/** Ecosystems whose manifests GarnetOps can edit (packages/core/src/manifests.ts). */
export type Ecosystem = (typeof ECOSYSTEMS)[number];

export type VersionScheme = "semver" | "pep440" | "generic";

const PACKAGE_TYPES: Record<string, Ecosystem> = {
  npm: "npm",
  python: "pypi",
  "go-module": "go",
  "rust-crate": "cargo",
  "php-composer": "composer",
};

/** The ecosystem of a syft package type, or null for one GarnetOps cannot edit (jar, gem, deb …). */
export function ecosystemOfPackageType(packageType: string): Ecosystem | null {
  return PACKAGE_TYPES[packageType] ?? null;
}

/** The version scheme to compare a package type's versions with. */
export function schemeOfPackageType(packageType: string): VersionScheme {
  if (packageType === "python") return "pep440";
  if (ecosystemOfPackageType(packageType)) return "semver";
  return "generic";
}

export interface ParsedVersion {
  scheme: VersionScheme;
  /** Release numbers, e.g. [1, 2, 3]. */
  nums: number[];
  /** semver: pre-release identifiers, or null for a release. */
  pre: (string | number)[] | null;
  /** pep440 only. */
  epoch: number;
  preKind: number | null;
  preNum: number;
  post: number | null;
  dev: number | null;
}

const MAX_PARTS = 6;
const MAX_LENGTH = 100;
const MAX_NUMBER = 1_000_000_000_000;

function numbers(core: string): number[] | null {
  const parts = core.split(".");
  if (parts.length === 0 || parts.length > MAX_PARTS) return null;
  const out: number[] = [];
  for (const part of parts) {
    if (!/^\d{1,13}$/.test(part)) return null;
    const n = Number(part);
    if (n > MAX_NUMBER) return null;
    out.push(n);
  }
  return out;
}

const blank = (scheme: VersionScheme, nums: number[]): ParsedVersion => ({
  scheme,
  nums,
  pre: null,
  epoch: 0,
  preKind: null,
  preNum: 0,
  post: null,
  dev: null,
});

function parseSemver(value: string): ParsedVersion | null {
  const match = /^[vV]?=?(\d+(?:\.\d+){0,5})(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?$/.exec(value);
  if (!match) return null;
  const nums = numbers(match[1] as string);
  if (!nums) return null;
  const parsed = blank("semver", nums);
  if (match[2] !== undefined) {
    const ids = match[2].split(".");
    if (ids.some((id) => id === "")) return null;
    parsed.pre = ids.map((id) => (/^\d{1,13}$/.test(id) ? Number(id) : id));
  }
  return parsed;
}

const PEP440 = new RegExp(
  [
    "^v?(?:(?<epoch>[0-9]+)!)?(?<release>[0-9]+(?:\\.[0-9]+)*)",
    "(?:[-_.]?(?<preLabel>alpha|a|beta|b|preview|pre|c|rc)[-_.]?(?<preNum>[0-9]+)?)?",
    "(?:-(?<postImplicit>[0-9]+)|[-_.]?(?<postLabel>post|rev|r)[-_.]?(?<postNum>[0-9]+)?)?",
    "(?:[-_.]?(?<devLabel>dev)[-_.]?(?<devNum>[0-9]+)?)?",
    "(?:\\+[a-z0-9]+(?:[-_.][a-z0-9]+)*)?$",
  ].join(""),
  "i",
);

/** a < b < rc, so the number orders the kinds. */
const PRE_KIND: Record<string, number> = { a: 0, alpha: 0, b: 1, beta: 1, c: 2, rc: 2, pre: 2, preview: 2 };

function parsePep440(value: string): ParsedVersion | null {
  const g = PEP440.exec(value)?.groups;
  if (!g) return null;
  const nums = numbers(g.release as string);
  if (!nums) return null;
  const parsed = blank("pep440", nums);
  if (g.epoch !== undefined) parsed.epoch = Number(g.epoch);
  if (g.preLabel !== undefined) {
    parsed.preKind = PRE_KIND[g.preLabel.toLowerCase()] ?? null;
    parsed.preNum = g.preNum ? Number(g.preNum) : 0;
  }
  if (g.postImplicit !== undefined) parsed.post = Number(g.postImplicit);
  else if (g.postLabel !== undefined) parsed.post = g.postNum ? Number(g.postNum) : 0;
  if (g.devLabel !== undefined) parsed.dev = g.devNum ? Number(g.devNum) : 0;
  return parsed;
}

function parseGeneric(value: string): ParsedVersion | null {
  const match = /^[vV]?(\d+(?:\.\d+){0,5})(?:[-+~].*)?$/.exec(value);
  if (!match) return null;
  const nums = numbers(match[1] as string);
  if (!nums) return null;
  const parsed = blank("generic", nums);
  if (/[-~]/.test(value.slice((match[1] as string).length + (/^[vV]/.test(value) ? 1 : 0))))
    parsed.pre = ["x"];
  return parsed;
}

/** Parses a version, or null if it is not one in this scheme. */
export function parseVersion(scheme: VersionScheme, value: string): ParsedVersion | null {
  const text = value.trim();
  if (!text || text.length > MAX_LENGTH) return null;
  if (scheme === "pep440") return parsePep440(text);
  if (scheme === "semver") return parseSemver(text);
  return parseGeneric(text);
}

const cmp = (a: number, b: number) => (a < b ? -1 : a > b ? 1 : 0);

function compareNums(a: number[], b: number[]): number {
  const length = Math.max(a.length, b.length);
  for (let i = 0; i < length; i++) {
    const c = cmp(a[i] ?? 0, b[i] ?? 0);
    if (c !== 0) return c;
  }
  return 0;
}

function comparePre(a: (string | number)[] | null, b: (string | number)[] | null): number {
  if (a === null && b === null) return 0;
  if (a === null) return 1; // a release is newer than its pre-release
  if (b === null) return -1;
  const length = Math.min(a.length, b.length);
  for (let i = 0; i < length; i++) {
    const x = a[i] as string | number;
    const y = b[i] as string | number;
    if (x === y) continue;
    if (typeof x === "number" && typeof y === "number") return cmp(x, y);
    if (typeof x === "number") return -1; // numeric identifiers sort before alphanumeric ones
    if (typeof y === "number") return 1;
    return x < y ? -1 : 1;
  }
  return cmp(a.length, b.length);
}

/** PEP 440 ordering key, as in the reference implementation: dev < pre < release < post. */
function pepPre(v: ParsedVersion): [number, number] {
  if (v.preKind === null && v.post === null && v.dev !== null) return [-1, 0];
  if (v.preKind === null) return [3, 0];
  return [v.preKind, v.preNum];
}

function comparePep440(a: ParsedVersion, b: ParsedVersion): number {
  const e = cmp(a.epoch, b.epoch);
  if (e !== 0) return e;
  const n = compareNums(a.nums, b.nums);
  if (n !== 0) return n;
  const [ak, an] = pepPre(a);
  const [bk, bn] = pepPre(b);
  const k = cmp(ak, bk) || cmp(an, bn);
  if (k !== 0) return k;
  const post = cmp(a.post ?? -1, b.post ?? -1);
  if (post !== 0) return post;
  return cmp(a.dev ?? Number.MAX_SAFE_INTEGER, b.dev ?? Number.MAX_SAFE_INTEGER);
}

export function compareParsed(a: ParsedVersion, b: ParsedVersion): number {
  if (a.scheme === "pep440" && b.scheme === "pep440") return comparePep440(a, b);
  return compareNums(a.nums, b.nums) || comparePre(a.pre, b.pre);
}

/** Orders two versions of one scheme: -1, 0, 1, or null if either does not parse. */
export function compareVersions(scheme: VersionScheme, a: string, b: string): number | null {
  const x = parseVersion(scheme, a);
  const y = parseVersion(scheme, b);
  return x && y ? compareParsed(x, y) : null;
}

/** True for a pre-release (semver), a pre, post-less dev or alpha/beta/rc release (PEP 440). */
export function isPrerelease(v: ParsedVersion): boolean {
  if (v.scheme === "pep440") return v.preKind !== null || v.dev !== null;
  return v.pre !== null;
}

export interface VulnerabilityFix {
  id: string;
  /** Versions that fix it, as the scanner reports them (several when more than one release line is fixed). */
  fixedIn: string[];
}

export interface TargetChoice {
  /** The lowest version that fixes every vulnerability that can be fixed, as written by the data (a leading "v" removed). */
  version: string;
  /** The target is in a later major release than the installed version. */
  majorUpgrade: boolean;
  /** Vulnerabilities the target fixes. */
  fixes: string[];
  /** Vulnerabilities no usable fix version was known for. */
  unresolved: string[];
}

function stripV(value: string): string {
  return value.trim().replace(/^[vV](?=\d)/, "");
}

/**
 * The lowest version that fixes all the given vulnerabilities, in the installed version's
 * major release if that is possible. For each vulnerability the fix is the lowest fixed
 * version in the same major release as the installed one; only when it has none, the lowest
 * fixed version above it (a major upgrade). The target is the highest of those. Pre-releases
 * are never proposed unless the installed version is one itself. Returns null when no
 * vulnerability has a usable fix version above the installed version.
 */
export function selectTarget(input: {
  scheme: VersionScheme;
  installed: string;
  vulnerabilities: VulnerabilityFix[];
}): TargetChoice | null {
  const installed = parseVersion(input.scheme, input.installed);
  if (!installed) return null;
  const allowPre = isPrerelease(installed);
  const chosen: { id: string; raw: string; parsed: ParsedVersion }[] = [];
  const unresolved: string[] = [];
  for (const vulnerability of input.vulnerabilities) {
    const candidates = vulnerability.fixedIn
      .map((raw) => ({ raw, parsed: parseVersion(input.scheme, raw) }))
      .filter(
        (c): c is { raw: string; parsed: ParsedVersion } =>
          c.parsed !== null &&
          compareParsed(c.parsed, installed) > 0 &&
          (allowPre || !isPrerelease(c.parsed)),
      )
      .sort((a, b) => compareParsed(a.parsed, b.parsed));
    const sameMajor = candidates.find((c) => major(c.parsed) === major(installed));
    const pick = sameMajor ?? candidates[0];
    if (pick) chosen.push({ id: vulnerability.id, ...pick });
    else unresolved.push(vulnerability.id);
  }
  if (chosen.length === 0) return null;
  const target = chosen.reduce((best, c) => (compareParsed(c.parsed, best.parsed) > 0 ? c : best));
  return {
    version: stripV(target.raw),
    majorUpgrade: major(target.parsed) !== major(installed),
    fixes: chosen.map((c) => c.id),
    unresolved,
  };
}

function major(v: ParsedVersion): number {
  return v.nums[0] ?? 0;
}

/** The major release of a version, or null if it does not parse. */
export function majorOf(scheme: VersionScheme, value: string): number | null {
  const parsed = parseVersion(scheme, value);
  return parsed ? major(parsed) : null;
}
