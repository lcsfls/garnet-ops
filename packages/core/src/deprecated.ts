/**
 * Deprecated and yanked packages (ADR 0051). Pure: which registry answers for which package type, which names are never sent,
 * the request paths (built only from names that pass a strict check), and the parsers of the three answers. The worker does the
 * requests; registry text is hostile and is cleaned before it is kept.
 */

export const DEPRECATION_ECOSYSTEMS = ["npm", "pypi", "crates"] as const;
export type DeprecationEcosystem = (typeof DEPRECATION_ECOSYSTEMS)[number];

/** The public registry of each ecosystem; an admin may name an own one instead. */
export const DEFAULT_REGISTRIES: Record<DeprecationEcosystem, string> = {
  npm: "https://registry.npmjs.org",
  pypi: "https://pypi.org",
  crates: "https://index.crates.io",
};

export const DEPRECATION_LIMITS = {
  /** Answers are asked again after this long. */
  maxAgeMs: 24 * 60 * 60 * 1000,
  /** Names asked per run and organisation, and at once. */
  maxLookups: 2000,
  concurrency: 4,
  timeoutMs: 20_000,
  maxBytes: 16 * 1024 * 1024,
  maxMessage: 300,
  maxExcluded: 100,
  maxPattern: 100,
  maxRegistryUrl: 300,
} as const;

/** The ecosystem of a package type as grype and syft name it; null for the others. */
export function deprecationEcosystemOf(packageType: string): DeprecationEcosystem | null {
  if (packageType === "npm") return "npm";
  if (packageType === "python") return "pypi";
  if (packageType === "rust-crate") return "crates";
  return null;
}

/** Names as the registries accept them; anything else is never asked. */
const NAME: Record<DeprecationEcosystem, RegExp> = {
  npm: /^(?:@[a-z0-9][a-z0-9._~-]{0,100}\/)?[a-z0-9][a-z0-9._~-]{0,213}$/i,
  pypi: /^[A-Za-z0-9](?:[A-Za-z0-9._-]{0,98}[A-Za-z0-9])?$/,
  crates: /^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$/,
};
const VERSION = /^[A-Za-z0-9][A-Za-z0-9.+_~!-]{0,99}$/;

export const validPackageName = (ecosystem: DeprecationEcosystem, name: string) => NAME[ecosystem].test(name);
export const validPackageVersion = (version: string) => VERSION.test(version);

/**
 * A registry address as an admin may give it: `https://`, a host, an optional port and path, nothing else (no user, password,
 * query or fragment). Returns the address without a trailing slash, or a problem.
 */
export function cleanRegistryUrl(raw: string): { url: string } | { problem: "length" | "https" | "parts" } {
  const text = raw.trim();
  if (!text || text.length > DEPRECATION_LIMITS.maxRegistryUrl) return { problem: "length" };
  let url: URL;
  try {
    url = new URL(text);
  } catch {
    return { problem: "parts" };
  }
  if (url.protocol !== "https:") return { problem: "https" };
  if (url.username || url.password || url.search || url.hash || !url.hostname) return { problem: "parts" };
  return { url: `${url.origin}${url.pathname.replace(/\/+$/, "")}` };
}

/** One excluded entry: an npm scope (`@acme`) or a name pattern where `*` stands for any text (`acme-*`). */
export function excludedEntryProblem(entry: string): string | null {
  if (!entry || entry.length > DEPRECATION_LIMITS.maxPattern) return "length";
  if (!/^@?[A-Za-z0-9*][A-Za-z0-9._~*/-]*$/.test(entry)) return "characters";
  if (/^[*@/]*$/.test(entry.replace(/[.\-_~]/g, ""))) return "everything";
  return null;
}

/** Whether a name stays inside: it matches an excluded scope or pattern (case-insensitive). */
export function isExcluded(name: string, excluded: readonly string[]): boolean {
  const n = name.toLowerCase();
  return excluded.some((raw) => {
    const e = raw.toLowerCase();
    if (/^@[^/*]+$/.test(e)) return n.startsWith(`${e}/`);
    const re = new RegExp(`^${e.replace(/[.+?^${}()|[\]\\]/g, "\\$&").replace(/\*/g, ".*")}$`);
    return re.test(n);
  });
}

/** The request path below the registry's address (npm: the package; PyPI: the version; crates: the index file). */
export function registryPath(ecosystem: DeprecationEcosystem, name: string, version: string): string {
  if (!validPackageName(ecosystem, name)) throw new Error("invalid package name");
  if (ecosystem === "npm") return `/${name.replace("/", "%2f")}`;
  if (ecosystem === "pypi") {
    if (!validPackageVersion(version)) throw new Error("invalid version");
    const normalized = name.toLowerCase().replace(/[-_.]+/g, "-");
    return `/pypi/${normalized}/${encodeURIComponent(version)}/json`;
  }
  const n = name.toLowerCase();
  if (n.length === 1) return `/1/${n}`;
  if (n.length === 2) return `/2/${n}`;
  if (n.length === 3) return `/3/${n[0]}/${n}`;
  return `/${n.slice(0, 2)}/${n.slice(2, 4)}/${n}`;
}

/** Registry text as it may be shown: control and bidirectional characters removed, cut to the limit. */
export function cleanMessage(text: unknown): string | null {
  if (typeof text !== "string") return null;
  // biome-ignore lint/suspicious/noControlCharactersInRegex: removing control characters is the point
  const clean = text.replace(/[\u0000-\u001f\u007f-\u009f​-‏‪-‮⁦-⁩﻿]/g, " ").trim();
  if (!clean) return null;
  return clean.length > DEPRECATION_LIMITS.maxMessage
    ? `${clean.slice(0, DEPRECATION_LIMITS.maxMessage - 1)}…`
    : clean;
}

export type PackageState = "deprecated" | "yanked" | "current" | "unknown";
export interface VersionState {
  state: PackageState;
  message: string | null;
}

const parse = (text: string): unknown => {
  try {
    return JSON.parse(text);
  } catch {
    return null;
  }
};
const isObject = (v: unknown): v is Record<string, unknown> =>
  typeof v === "object" && v !== null && !Array.isArray(v);

/**
 * npm's abbreviated package document: each version may carry `deprecated` (a message; an empty string un-deprecates). A version
 * the document does not list is unknown.
 */
export function parseNpm(text: string, versions: readonly string[]): Map<string, VersionState> {
  const doc = parse(text);
  const all = isObject(doc) && isObject(doc.versions) ? doc.versions : null;
  const out = new Map<string, VersionState>();
  for (const v of versions) {
    const entry = all?.[v];
    if (!isObject(entry)) out.set(v, { state: "unknown", message: null });
    else if (typeof entry.deprecated === "string" && entry.deprecated.trim() !== "")
      out.set(v, { state: "deprecated", message: cleanMessage(entry.deprecated) });
    else out.set(v, { state: "current", message: null });
  }
  return out;
}

/** PyPI's JSON of one version: yanked when every file of it is (`urls[].yanked`), with the reason. */
export function parsePypi(text: string): VersionState {
  const doc = parse(text);
  if (!isObject(doc) || !Array.isArray(doc.urls)) return { state: "unknown", message: null };
  const files = doc.urls.filter(isObject);
  const info = isObject(doc.info) ? doc.info : {};
  const yanked = files.length > 0 ? files.every((f) => f.yanked === true) : info.yanked === true;
  if (!yanked) return { state: "current", message: null };
  const reason = files.find((f) => typeof f.yanked_reason === "string")?.yanked_reason ?? info.yanked_reason;
  return { state: "yanked", message: cleanMessage(reason) };
}

/** A crate's sparse index file: one JSON object per line, each a version with `vers` and `yanked`. */
export function parseCrates(text: string, versions: readonly string[]): Map<string, VersionState> {
  const yanked = new Map<string, boolean>();
  for (const line of text.split("\n")) {
    const entry = line.trim() ? parse(line) : null;
    if (isObject(entry) && typeof entry.vers === "string") yanked.set(entry.vers, entry.yanked === true);
  }
  const out = new Map<string, VersionState>();
  for (const v of versions) {
    const y = yanked.get(v);
    out.set(
      v,
      y === undefined
        ? { state: "unknown", message: null }
        : { state: y ? "yanked" : "current", message: null },
    );
  }
  return out;
}
