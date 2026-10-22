/**
 * Fix proposals and fix pull requests (ADR 0014): which open findings a version bump can fix,
 * where the pull request is opened, and what it says. Pure functions, shared by the API
 * (proposals, validation), the worker (the pull request) and the tests.
 *
 * The fixed version always comes from the vulnerability data (`fixed_in` of the findings),
 * never from the AI triage: the model's `upgradeTo` is a hint a human reads, nothing more.
 */
import { createHash } from "node:crypto";
import { isIP } from "node:net";
import { classifyAddress } from "./ai-endpoint.ts";
import {
  bumpSpec,
  type Dependency,
  isSafePackageName,
  type ManifestKind,
  manifestPathFor,
  normalizeName,
  type Refusal,
} from "./manifests.ts";
import {
  compareVersions,
  type Ecosystem,
  ecosystemOfPackageType,
  schemeOfPackageType,
  selectTarget,
} from "./versions.ts";

/* -------------------------------------------------------------------------- */
/* Forges                                                                      */
/* -------------------------------------------------------------------------- */

/** Forgejo is a fork of Gitea with the same REST API; the kind is only shown to people. */
export const FORGE_KINDS = ["github", "gitea", "forgejo"] as const;
export type ForgeKind = (typeof FORGE_KINDS)[number];

export interface RepoLocation {
  /** Host name, lower case, with a port if the repository URL has one (https only). */
  host: string;
  owner: string;
  repo: string;
  /** The repository's page: https://host/owner/repo, without ".git". */
  webBase: string;
}

const NAME_PART = /^[A-Za-z0-9_.-]{1,100}$/;

function cleanRepoName(value: string): string {
  return value.replace(/\.git$/i, "");
}

/** Owner and repository from an https or SSH repository URL, or null (more than two path parts, odd characters). */
export function parseRepoLocation(url: string): RepoLocation | null {
  let host: string;
  let segments: string[];
  let prefix = "";
  if (/^https:\/\//i.test(url)) {
    let parsed: URL;
    try {
      parsed = new URL(url);
    } catch {
      return null;
    }
    if (parsed.username || parsed.password || parsed.search || parsed.hash) return null;
    host = parsed.host.toLowerCase();
    segments = parsed.pathname.split("/").filter(Boolean);
    if (segments.length < 2) return null;
    prefix = segments.slice(0, -2).join("/");
    segments = segments.slice(-2);
  } else {
    const ssh =
      /^ssh:\/\/(?:[^@/]+@)?([^/:]+)(?::\d{1,5})?\/(.+)$/i.exec(url) ?? /^[^@/]+@([^:/]+):(.+)$/.exec(url);
    if (!ssh) return null;
    host = (ssh[1] as string).toLowerCase();
    segments = (ssh[2] as string).split("/").filter(Boolean);
    if (segments.length !== 2) return null;
  }
  const [owner, rawRepo] = segments as [string, string];
  const repo = cleanRepoName(rawRepo);
  if (
    !NAME_PART.test(owner) ||
    !NAME_PART.test(repo) ||
    owner === "." ||
    owner === ".." ||
    repo === "." ||
    repo === ".."
  ) {
    return null;
  }
  return { host, owner, repo, webBase: `https://${host}${prefix ? `/${prefix}` : ""}/${owner}/${repo}` };
}

/** The forge a host name suggests, or null when the admin has to say. */
export function detectForge(host: string): ForgeKind | null {
  const name = host.toLowerCase().replace(/:\d+$/, "");
  if (name === "github.com") return "github";
  if (name === "codeberg.org" || /(^|[.-])forgejo([.-]|$)/.test(name)) return "forgejo";
  if (/(^|[.-])gitea([.-]|$)/.test(name)) return "gitea";
  return null;
}

/** The REST API address of a forge on `host`: api.github.com, GitHub Enterprise Server `/api/v3`, Gitea and Forgejo `/api/v1`. */
export function defaultApiBase(kind: ForgeKind, host: string): string {
  if (kind === "github") return host === "github.com" ? "https://api.github.com" : `https://${host}/api/v3`;
  return `https://${host}/api/v1`;
}

/** Why an API address cannot be used, or null. https only, no credentials, and the path of the forge's API. */
export function apiBaseProblem(kind: ForgeKind, value: string): string | null {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    return "Not a URL";
  }
  if (url.protocol !== "https:") return "Only https:// addresses are allowed";
  if (url.username || url.password) return "No user name or password in the address";
  if (url.search || url.hash) return "No query or fragment in the address";
  const host = url.hostname.replace(/^\[|\]$/g, "").toLowerCase();
  if (host === "localhost" || host.endsWith(".localhost")) return "This address is not allowed";
  if (isIP(host) && classifyAddress(host) === "forbidden") return "This address is not allowed";
  const path = url.pathname.replace(/\/+$/, "");
  if (kind === "github") {
    if (host === "api.github.com" && path === "") return null;
    return /^(?:\/[A-Za-z0-9._~-]+)*\/api\/v3$/.test(path)
      ? null
      : "A GitHub Enterprise Server address ends with /api/v3";
  }
  return /^(?:\/[A-Za-z0-9._~-]+)*\/api\/v1$/.test(path)
    ? null
    : "A Gitea or Forgejo address ends with /api/v1";
}

/** The pull request page for a number, as we build it ourselves (the forge's `html_url` is never trusted). */
export function pullRequestUrl(kind: ForgeKind, webBase: string, number: number): string {
  return `${webBase}/${kind === "github" ? "pull" : "pulls"}/${number}`;
}

/* -------------------------------------------------------------------------- */
/* Proposals                                                                   */
/* -------------------------------------------------------------------------- */

export interface FindingFact {
  id: string;
  vulnerabilityId: string;
  severity: string;
  severityRank: number;
  packageName: string;
  packageType: string;
  packageVersion: string;
  fixedIn: string[];
  locations: string[];
}

export interface ManifestFact {
  path: string;
  kind: ManifestKind;
  /** Git blob id of the file as scanned; the pull request refuses to edit a different file. */
  blobSha: string;
  dependencies: Dependency[];
}

/** Why a proposal cannot be applied automatically. */
export const NO_FIX_REASONS = [
  "no-version",
  "unsupported-ecosystem",
  "no-manifest",
  "transitive",
  "already-satisfied",
  "complex-range",
  "unsupported-source",
  "indirect",
  "major-change",
  "ambiguous",
  "replaced",
  "hashes",
  "bad-target",
  "invalid",
  "not-found",
  "too-large",
] as const;
export type NoFixReason = (typeof NO_FIX_REASONS)[number];

export interface Proposal {
  /** Stable for the same change: repository, ecosystem, manifest, package and target version. */
  key: string;
  repositoryId: string;
  ecosystem: Ecosystem | null;
  packageType: string;
  packageName: string;
  installedVersion: string;
  /** The lowest version that fixes the vulnerabilities, or null when no fixed version is known. */
  targetVersion: string | null;
  majorUpgrade: boolean;
  severity: string;
  severityRank: number;
  /** Vulnerabilities the target version fixes. */
  vulnerabilityIds: string[];
  /** Vulnerabilities of the package with no usable fixed version. */
  unresolvedIds: string[];
  findingIds: string[];
  manifestPath: string | null;
  manifestBlobSha: string | null;
  dependency: "direct" | "transitive" | "unknown";
  section: string | null;
  dev: boolean;
  currentSpec: string | null;
  newSpec: string | null;
  /** "edit": GarnetOps can open a pull request. "manual": a person has to do it. */
  action: "edit" | "manual";
  reason: NoFixReason | null;
}

export function proposalKey(parts: {
  repositoryId: string;
  packageType: string;
  manifestPath: string | null;
  packageName: string;
  targetVersion: string | null;
}): string {
  const text = [
    parts.repositoryId,
    parts.packageType,
    parts.manifestPath ?? "",
    parts.packageName,
    parts.targetVersion ?? "",
  ].join("\u001f");
  return createHash("sha256").update(text).digest("hex").slice(0, 24);
}

const KEY = /^[0-9a-f]{24}$/;
export const isProposalKey = (value: string) => KEY.test(value);

interface Group {
  packageType: string;
  packageName: string;
  manifestPath: string | null;
  findings: FindingFact[];
}

/**
 * Groups the open findings that have a fixed version by package and manifest and chooses
 * the target version for each group. `manifests` are the manifests of the repository's last
 * scan; a package that one of them declares is a direct dependency, any other is
 * transitive (pulled in by a dependency, edited by changing its parent or an override).
 */
export function buildProposals(input: {
  repositoryId: string;
  findings: FindingFact[];
  manifests: ManifestFact[];
}): Proposal[] {
  const manifests = new Map(input.manifests.map((m) => [m.path, m]));
  const groups = new Map<string, Group>();
  for (const finding of input.findings) {
    if (finding.fixedIn.length === 0) continue;
    const ecosystem = ecosystemOfPackageType(finding.packageType);
    const paths = new Set<string | null>();
    if (ecosystem) for (const location of finding.locations) paths.add(manifestPathFor(ecosystem, location));
    if (paths.size === 0) paths.add(null);
    // A package found both in a lockfile we can map and in places we cannot belongs to the mapped manifest.
    if (paths.size > 1) paths.delete(null);
    for (const path of paths) {
      const id = [finding.packageType, finding.packageName, path ?? ""].join("\u001f");
      const group = groups.get(id) ?? {
        packageType: finding.packageType,
        packageName: finding.packageName,
        manifestPath: path,
        findings: [],
      };
      group.findings.push(finding);
      groups.set(id, group);
    }
  }
  return [...groups.values()]
    .map((group) => proposalFor(input.repositoryId, group, manifests))
    .sort(
      (a, b) =>
        b.severityRank - a.severityRank ||
        b.vulnerabilityIds.length - a.vulnerabilityIds.length ||
        a.packageName.localeCompare(b.packageName),
    );
}

function proposalFor(repositoryId: string, group: Group, manifests: Map<string, ManifestFact>): Proposal {
  const scheme = schemeOfPackageType(group.packageType);
  const ecosystem = ecosystemOfPackageType(group.packageType);
  const byVulnerability = new Map<string, Set<string>>();
  for (const finding of group.findings) {
    const set = byVulnerability.get(finding.vulnerabilityId) ?? new Set<string>();
    for (const version of finding.fixedIn) set.add(version);
    byVulnerability.set(finding.vulnerabilityId, set);
  }
  const vulnerabilities = [...byVulnerability].map(([id, set]) => ({ id, fixedIn: [...set] }));
  // The newest installed version of the package is the one that has to move.
  const installed = group.findings
    .map((f) => f.packageVersion)
    .reduce((best, v) => ((compareVersions(scheme, v, best) ?? 0) > 0 ? v : best));
  const choice = selectTarget({ scheme, installed, vulnerabilities });
  const worst = (ids: string[]) =>
    group.findings
      .filter((f) => ids.includes(f.vulnerabilityId))
      .reduce((a, f) => (f.severityRank > a.rank ? { rank: f.severityRank, name: f.severity } : a), {
        rank: -1,
        name: "unknown",
      });
  const fixed = choice?.fixes ?? vulnerabilities.map((v) => v.id);
  const severity = worst(fixed);
  const base = {
    repositoryId,
    ecosystem,
    packageType: group.packageType,
    packageName: group.packageName,
    installedVersion: installed,
    targetVersion: choice?.version ?? null,
    majorUpgrade: choice?.majorUpgrade ?? false,
    severity: severity.name,
    severityRank: severity.rank,
    vulnerabilityIds: fixed.sort(),
    unresolvedIds: (choice?.unresolved ?? []).sort(),
    findingIds: group.findings.map((f) => f.id),
    manifestPath: group.manifestPath,
    manifestBlobSha: null as string | null,
    dependency: "unknown" as Proposal["dependency"],
    section: null as string | null,
    dev: false,
    currentSpec: null as string | null,
    newSpec: null as string | null,
  };
  const manual = (reason: NoFixReason, patch: Partial<Proposal> = {}): Proposal => ({
    ...base,
    ...patch,
    key: proposalKey({ ...base, targetVersion: base.targetVersion }),
    action: "manual",
    reason,
  });
  if (!choice) return manual("no-version");
  if (!ecosystem) return manual("unsupported-ecosystem");
  if (!group.manifestPath) return manual("no-manifest");
  const manifest = manifests.get(group.manifestPath);
  if (!manifest) return manual("no-manifest");
  const wanted = normalizeName(manifest.kind, group.packageName);
  const declared = manifest.dependencies.filter((d) => normalizeName(manifest.kind, d.name) === wanted);
  const withManifest = { manifestBlobSha: manifest.blobSha };
  if (declared.length === 0 || declared.every((d) => d.indirect)) {
    return manual("transitive", { ...withManifest, dependency: "transitive" });
  }
  const direct = declared.filter((d) => !d.indirect);
  const first = direct[0] as Dependency;
  const info = {
    ...withManifest,
    dependency: "direct" as const,
    section: first.section,
    dev: direct.every((d) => d.dev),
    currentSpec: first.spec || null,
  };
  const blocked = direct.find((d) => d.blocked)?.blocked;
  if (blocked) return manual(blocked, info);
  let allSatisfied = true;
  let newSpec: string | null = null;
  for (const dependency of direct) {
    const bumped = bumpSpec(manifest.kind, dependency.spec, choice.version);
    if (!bumped.ok) {
      if (bumped.reason === "already-satisfied") continue;
      return manual(bumped.reason, info);
    }
    allSatisfied = false;
    newSpec = newSpec ?? bumped.spec;
  }
  if (allSatisfied) return manual("already-satisfied", info);
  return {
    ...base,
    ...info,
    newSpec,
    key: proposalKey({ ...base, targetVersion: base.targetVersion }),
    action: "edit",
    reason: null,
  };
}

/* -------------------------------------------------------------------------- */
/* Branch, commit, pull request text                                           */
/* -------------------------------------------------------------------------- */

/** `garnetops/fix-<package>-<version>`: only characters that are valid in a branch name, at most 100 long. */
export function branchName(packageName: string, version: string): string {
  const clean = (value: string) =>
    value
      .replace(/[^A-Za-z0-9._-]+/g, "-")
      .replace(/\.{2,}/g, ".")
      .replace(/^[-.]+|[-.]+$/g, "");
  const name = clean(packageName) || "package";
  const ver = clean(version) || "latest";
  let branch = `garnetops/fix-${name}-${ver}`;
  if (branch.length > 100) {
    const hash = createHash("sha256").update(`${packageName}\u001f${version}`).digest("hex").slice(0, 8);
    branch = `garnetops/fix-${name.slice(0, 55)}-${ver.slice(0, 20)}-${hash}`;
  }
  return branch;
}

/** Characters that mean something in Markdown, escaped with a backslash. */
export function escapeMarkdown(text: string): string {
  return stripControl(text).replace(/[\\`*_{}[\]()#+\-.!|<>~&@:$^=]/g, "\\$&");
}

// biome-ignore lint/suspicious/noControlCharactersInRegex: removing control characters is the point
const CONTROL = /[\u0000-\u001f\u007f-\u009f​-‏‪-‮⁠-⁤⁦-⁩﻿]/g;

/** Text as a single line without control, invisible or bidirectional characters. */
export function stripControl(text: string): string {
  return text.replace(CONTROL, " ").replace(/\s+/g, " ").trim();
}

/** A code span that cannot be closed from the inside; the content is shown as it is, never interpreted. */
export function inlineCode(text: string): string {
  const clean = stripControl(text);
  const longest = Math.max(0, ...(clean.match(/`+/g) ?? []).map((run) => run.length));
  const fence = "`".repeat(longest + 1);
  const pad = clean.startsWith("`") || clean.endsWith("`") ? " " : "";
  return `${fence}${pad}${clean}${pad}${fence}`;
}

const ADVISORY_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,99}$/;

/** A link for a vulnerability id: the ecosystem's canonical page, else the first https address in our data. */
export function advisoryUrl(id: string, urls: readonly string[] = []): string | null {
  if (!ADVISORY_ID.test(id)) return null;
  if (/^CVE-\d{4}-\d{4,}$/.test(id)) return `https://nvd.nist.gov/vuln/detail/${id}`;
  if (/^GHSA(?:-[23456789cfghjmpqrvwx]{4}){3}$/.test(id)) return `https://github.com/advisories/${id}`;
  for (const candidate of urls) {
    try {
      const url = new URL(candidate);
      if (url.protocol === "https:" && !url.username && !url.password && candidate.length <= 300) {
        return url.href.replace(
          /[()<>\s]/g,
          (c) => `%${c.charCodeAt(0).toString(16).toUpperCase().padStart(2, "0")}`,
        );
      }
    } catch {
      // next
    }
  }
  return null;
}

export interface FixPrVulnerability {
  id: string;
  severity: string;
  url: string | null;
}

export interface FixPrInput {
  packageName: string;
  ecosystem: Ecosystem;
  fromVersion: string;
  toVersion: string;
  majorUpgrade: boolean;
  manifestPath: string;
  vulnerabilities: FixPrVulnerability[];
  /** Display name of the person who asked for the pull request. */
  requestedBy: string;
}

const LOCKFILE_HINT: Record<Ecosystem, string> = {
  npm: "package-lock.json, yarn.lock or pnpm-lock.yaml (for example `npm install`)",
  pypi: "the compiled requirements or lock file (for example `pip-compile`)",
  composer: "composer.lock (for example `composer update`)",
  go: "go.sum (for example `go mod tidy`)",
  cargo: "Cargo.lock (for example `cargo update`)",
};

const MAX_LISTED = 25;
const KNOWN_SEVERITIES = new Set(["critical", "high", "medium", "low", "negligible", "unknown"]);

export function pullRequestTitle(
  input: Pick<FixPrInput, "packageName" | "fromVersion" | "toVersion">,
): string {
  return `fix(deps): update ${input.packageName} from ${input.fromVersion} to ${input.toVersion}`.slice(
    0,
    200,
  );
}

/**
 * The fixed text of a fix pull request. Every value that came from scanned data or from a
 * person goes through a code span or an escape; no free text of the advisories is included,
 * only identifiers and links built from them. Package names and versions are validated by the
 * caller as well ({@link isSafePackageName}); this function holds even if they were not.
 */
export function renderPullRequest(input: FixPrInput): { title: string; commitMessage: string; body: string } {
  const title = pullRequestTitle({
    packageName: stripControl(input.packageName),
    fromVersion: stripControl(input.fromVersion),
    toVersion: stripControl(input.toVersion),
  });
  const listed = input.vulnerabilities.filter((v) => ADVISORY_ID.test(v.id)).slice(0, MAX_LISTED);
  const rest = input.vulnerabilities.length - listed.length;
  const lines: string[] = [
    "## Dependency update",
    "",
    `${inlineCode(input.packageName)}: ${inlineCode(input.fromVersion)} → ${inlineCode(input.toVersion)} in ${inlineCode(input.manifestPath)}`,
    "",
    "### Vulnerabilities fixed",
    "",
  ];
  for (const v of listed) {
    const link = v.url ? `[${inlineCode(v.id)}](${v.url})` : inlineCode(v.id);
    lines.push(`- ${link} (${KNOWN_SEVERITIES.has(v.severity) ? v.severity : "unknown"})`);
  }
  if (rest > 0) lines.push(`- and ${rest} more`);
  lines.push("", "### Before you merge", "");
  lines.push(
    `- This pull request changes the manifest only. The lockfile is **not** updated: let your CI or a developer regenerate ${LOCKFILE_HINT[input.ecosystem]} and push it to this branch.`,
  );
  if (input.majorUpgrade) {
    lines.push(
      "- **Major upgrade.** The new version is in a later major release than the one in use. Read the changelog and expect breaking changes.",
    );
  }
  lines.push(
    "- Read the changelog of the new version and run your tests.",
    "- The next GarnetOps scan confirms whether the vulnerabilities are gone.",
    "",
    "---",
    "",
    `Created by GarnetOps at the request of ${inlineCode(input.requestedBy.slice(0, 80))}. Review before merging. GarnetOps never merges, approves or pushes to your default branch.`,
  );
  return {
    title,
    commitMessage:
      `fix(deps): update ${stripControl(input.packageName)} to ${stripControl(input.toVersion)}`.slice(
        0,
        200,
      ),
    body: lines.join("\n"),
  };
}

/* -------------------------------------------------------------------------- */
/* Stored pull requests                                                        */
/* -------------------------------------------------------------------------- */

export const FIX_PR_STATES = ["queued", "running", "open", "merged", "closed", "failed"] as const;
export type FixPrState = (typeof FIX_PR_STATES)[number];

/** States in which a pull request for the same change blocks a new one. */
export const ACTIVE_FIX_PR_STATES = ["queued", "running", "open"] as const;

/** Safe reasons a pull request failed or a refresh did not work. Never a response body, never a secret. */
export const FIX_PR_REASONS = [
  "token-rejected",
  "forbidden",
  "not-found",
  "conflict",
  "rejected",
  "rate-limited",
  "redirect",
  "too-large",
  "timeout",
  "tls",
  "connection-failed",
  "address-refused",
  "unresolvable",
  "bad-response",
  "http-error",
  "manifest-changed",
  "manifest-missing",
  "branch-exists",
  "write-access-missing",
  "no-push-access",
  "repository-gone",
  "interrupted",
  "unexpected",
  ...(
    [
      "too-large",
      "invalid",
      "not-found",
      "ambiguous",
      "complex-range",
      "unsupported-source",
      "indirect",
      "replaced",
      "hashes",
      "major-change",
      "already-satisfied",
      "bad-target",
    ] satisfies Refusal[]
  ).map((r) => `edit-${r}` as const),
] as const;
export type FixPrReason = (typeof FIX_PR_REASONS)[number];

/* -------------------------------------------------------------------------- */
/* Renovate                                                                    */
/* -------------------------------------------------------------------------- */

const RENOVATE_MANAGER: Record<Ecosystem, string> = {
  npm: "npm",
  pypi: "pip_requirements",
  composer: "composer",
  go: "gomod",
  cargo: "cargo",
};

/**
 * A `renovate.json` for customers who run their own Renovate (which is AGPL-3.0 and therefore
 * never bundled or run by GarnetOps): vulnerability alerts on, and a rule per vulnerable
 * package that keeps Renovate from choosing a version below the proposed one.
 */
export function renovateConfig(
  proposals: { packageName: string; ecosystem: Ecosystem | null; targetVersion: string | null }[],
): Record<string, unknown> {
  const rules = new Map<string, { manager: string; name: string; floor: string }>();
  for (const p of proposals) {
    if (!p.ecosystem || !p.targetVersion || !isSafePackageName(p.packageName)) continue;
    const manager = RENOVATE_MANAGER[p.ecosystem];
    const id = `${manager}\u001f${p.packageName}`;
    const existing = rules.get(id);
    if (!existing || (compareVersions("semver", p.targetVersion, existing.floor) ?? 0) > 0) {
      rules.set(id, { manager, name: p.packageName, floor: p.targetVersion });
    }
  }
  return {
    $schema: "https://docs.renovatebot.com/renovate-schema.json",
    extends: ["config:recommended"],
    vulnerabilityAlerts: { enabled: true, labels: ["security"] },
    packageRules: [...rules.values()]
      .sort((a, b) => a.name.localeCompare(b.name) || a.manager.localeCompare(b.manager))
      .map((r) => ({
        description: "Proposed by GarnetOps: the lowest version without the known vulnerabilities.",
        matchManagers: [r.manager],
        matchPackageNames: [r.name],
        allowedVersions: `>=${r.floor}`,
        labels: ["security"],
      })),
  };
}
