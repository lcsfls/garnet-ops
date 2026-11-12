/**
 * The code viewer of a finding (ADR 0048, 0.1.6). Pure: where a vulnerable package is declared (manifests and lockfiles) and where
 * the code imports it (a search by name, per ecosystem), shown as excerpts with a few lines around each place. The worker reads
 * the files from a short-lived clone; nothing here touches a disk or the network, and nothing is executed.
 */

export const CODE_VIEW_LIMITS = {
  /** Files looked at for usages, and time for the search. */
  maxFiles: 20_000,
  maxSearchMs: 30_000,
  /** Files larger than this are skipped (minified bundles, data). */
  maxFileBytes: 1024 * 1024,
  /** Usage places kept, and in how many files; more are counted. */
  maxUsages: 200,
  maxUsageFiles: 50,
  /** Places shown per declaring file. */
  maxDeclarationMatches: 20,
  maxDeclarationFiles: 10,
  /** Lines around a place. */
  usageContext: 3,
  declarationContext: 5,
  /** A longer line is cut and marked. */
  maxLineLength: 2000,
} as const;

/** Folders that hold other people's code or build output: never searched. */
export const SKIPPED_DIRS = new Set([
  ".git",
  "node_modules",
  "vendor",
  "bower_components",
  "dist",
  "build",
  "out",
  "target",
  ".next",
  ".nuxt",
  ".svelte-kit",
  "coverage",
  "__pycache__",
  ".venv",
  "venv",
  ".tox",
]);

export type Ecosystem = "npm" | "python" | "go" | "rust" | "php" | "other";

/** The ecosystem of a finding's package type as grype names it. */
export function ecosystemOf(packageType: string): Ecosystem {
  switch (packageType) {
    case "npm":
      return "npm";
    case "python":
      return "python";
    case "go-module":
      return "go";
    case "rust-crate":
      return "rust";
    case "php-composer":
      return "php";
    default:
      return "other";
  }
}

const escapeRegExp = (s: string) => s.replace(/[.*+?^${}()|[\]\\/]/g, "\\$&");

/** The source files of an ecosystem worth searching, by name. */
export const SOURCE_FILES: Record<Ecosystem, RegExp | null> = {
  npm: /\.(?:[cm]?js|jsx|[cm]?ts|tsx|vue|svelte)$/i,
  python: /\.py$/i,
  go: /\.go$/i,
  rust: /\.rs$/i,
  // Composer packages are used by namespace, which the package name does not tell: declarations only.
  php: null,
  other: null,
};

/**
 * How a source line imports the package: fixed patterns per ecosystem, built from the package name with every special character
 * escaped. Null where the name does not tell how code refers to it.
 */
export function usagePattern(ecosystem: Ecosystem, packageName: string): RegExp | null {
  if (!/^[@A-Za-z0-9][A-Za-z0-9@/._+~-]{0,213}$/.test(packageName)) return null;
  switch (ecosystem) {
    case "npm": {
      const n = escapeRegExp(packageName);
      return new RegExp(
        `(?:\\bfrom\\s*|\\brequire\\s*\\(\\s*|\\bimport\\s*\\(\\s*|^\\s*import\\s+)['"\`]${n}(?:/[^'"\`]*)?['"\`]`,
      );
    }
    case "python": {
      const n = escapeRegExp(packageName.toLowerCase().replace(/-/g, "_"));
      return new RegExp(
        `^\\s*(?:from\\s+${n}(?:\\.[\\w.]+)?\\s+import\\b|import\\s+(?:[\\w.]+\\s*,\\s*)*${n}\\b)`,
        "i",
      );
    }
    case "go":
      return new RegExp(`"${escapeRegExp(packageName)}(?:/[^"]*)?"`);
    case "rust": {
      const n = escapeRegExp(packageName.replace(/-/g, "_"));
      return new RegExp(`(?:\\buse\\s+${n}\\b|\\bextern\\s+crate\\s+${n}\\b|(?<![\\w:])${n}::)`);
    }
    default:
      return null;
  }
}

/** The highlight.js language for a file, chosen by its name only (never guessed from content); null for plain text. */
export function languageOf(path: string): string | null {
  const name = path.slice(path.lastIndexOf("/") + 1).toLowerCase();
  if (name === "dockerfile" || name.endsWith(".dockerfile")) return "dockerfile";
  if (name === "go.mod" || name === "go.sum") return null;
  if (name.endsWith(".lock") && name !== "cargo.lock" && name !== "poetry.lock") return null;
  const ext = name.slice(name.lastIndexOf(".") + 1);
  const byExt: Record<string, string> = {
    js: "javascript",
    mjs: "javascript",
    cjs: "javascript",
    jsx: "javascript",
    ts: "typescript",
    mts: "typescript",
    cts: "typescript",
    tsx: "typescript",
    json: "json",
    py: "python",
    go: "go",
    rs: "rust",
    php: "php",
    toml: "ini",
    lock: "ini",
    yaml: "yaml",
    yml: "yaml",
    ini: "ini",
    cfg: "ini",
    xml: "xml",
    sh: "bash",
    bash: "bash",
  };
  return byExt[ext] ?? null;
}

/** One line as shown: control and bidirectional characters removed (tab kept), cut at the limit. */
export function cleanLine(text: string): { text: string; cut: boolean } {
  // biome-ignore lint/suspicious/noControlCharactersInRegex: removing control characters is the point
  const clean = text.replace(/[\u0000-\u0008\u000b-\u001f\u007f-\u009f​-‏‪-‮⁦-⁩﻿]/g, "");
  return clean.length > CODE_VIEW_LIMITS.maxLineLength
    ? { text: clean.slice(0, CODE_VIEW_LIMITS.maxLineLength), cut: true }
    : { text: clean, cut: false };
}

/** Whether a file's first bytes look like text: no NUL byte. */
export function looksLikeText(head: Uint8Array): boolean {
  return !head.subarray(0, 8192).includes(0);
}

/** The lines of a manifest or lockfile that name the package as a whole token (not as part of a longer name). */
export function declarationLines(text: string, packageName: string): number[] {
  const n = escapeRegExp(packageName);
  const token = new RegExp(`(?:^|[^A-Za-z0-9@/._-])${n}(?:$|[^A-Za-z0-9._-])`);
  const out: number[] = [];
  const lines = text.split(/\r?\n/);
  for (let i = 0; i < lines.length && out.length < CODE_VIEW_LIMITS.maxDeclarationMatches; i += 1) {
    if (token.test(lines[i] as string)) out.push(i + 1);
  }
  return out;
}

export interface CodeLine {
  /** 1-based line number in the file. */
  n: number;
  text: string;
  /** The line was longer and is cut. */
  cut?: boolean;
}

export interface CodeExcerpt {
  /** Relative to the repository. */
  path: string;
  role: "manifest" | "lockfile" | "usage";
  /** highlight.js language, or null for plain text. */
  language: string | null;
  /** The lines shown, in order; a jump in `n` is a gap between two windows. */
  lines: CodeLine[];
  /** The line numbers that matched. */
  marks: number[];
}

/** The lines around each mark, windows merged where they touch. */
export function excerpt(text: string, marks: readonly number[], context: number): CodeLine[] {
  const lines = text.split(/\r?\n/);
  const wanted = new Set<number>();
  for (const m of marks) {
    for (let n = Math.max(1, m - context); n <= Math.min(lines.length, m + context); n += 1) wanted.add(n);
  }
  return [...wanted]
    .sort((a, b) => a - b)
    .map((n) => {
      const line = cleanLine(lines[n - 1] ?? "");
      return line.cut ? { n, text: line.text, cut: true } : { n, text: line.text };
    });
}

/** What the viewer shows for one finding, as the worker hands it over. */
export interface CodeView {
  /** The commit that was read (the branch's head now) and the commit the finding's scan saw. */
  commit: string;
  branch: string;
  scanCommit: string | null;
  ecosystem: Ecosystem;
  declarations: CodeExcerpt[];
  usages: CodeExcerpt[];
  /** All usage places found, and in how many files; `usages` holds the first of them. */
  usageCount: number;
  usageFileCount: number;
  /** Whether the usage search ran, and why it stopped early. */
  search: { ran: boolean; files: number; stopped: "files" | "time" | null };
}

/** A path from the repository, cleaned and relative; null when it is not one. */
export function cleanRepoPath(raw: string): string | null {
  const path = raw
    .replace(/\\/g, "/")
    .replace(/^\.?\/+/, "")
    // biome-ignore lint/suspicious/noControlCharactersInRegex: removing control characters is the point
    .replace(/[\u0000-\u001f\u007f‪-‮⁦-⁩]/g, "");
  if (!path || path.length > 500 || path.split("/").some((p) => p === ".." || p === "" || p === "."))
    return null;
  return path;
}
