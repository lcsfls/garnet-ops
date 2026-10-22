/**
 * Reading and editing dependency manifests as text (ADR 0014). Everything here is pure: a
 * manifest comes in as a string, and the result is either a new string or a refusal with a
 * stable code. Nothing from the repository is executed, no package manager is involved, no
 * file is written.
 *
 * Editing is deliberately conservative and minimal. The files are never parsed and written
 * back; a small scanner finds the exact text of one version (a JSON string, a TOML string,
 * a requirement specifier, a go.mod version) and only that text is replaced, so formatting,
 * comments, line endings (CRLF), a byte order mark and key order stay exactly as they were.
 * Anything the scanner is not sure about is refused instead of guessed: invalid syntax,
 * duplicate keys, a dependency that appears twice in one place, ranges that are not a
 * single version with an operator, git/path/workspace sources, hash-pinned requirements,
 * `replace` directives, indirect Go requirements.
 *
 * Lockfiles are never edited. The pull request says so, and the project's own CI or a
 * developer regenerates them.
 */
import { compareParsed, compareVersions, type Ecosystem, isPrerelease, parseVersion } from "./versions.ts";

export type ManifestKind = Ecosystem;

/** Biggest manifest we read or write. GitHub's contents API returns nothing above 1 MB either. */
export const MAX_MANIFEST_BYTES = 1_000_000;
const MAX_ENTRIES = 20_000;
const MAX_LINE = 10_000;
const MAX_JSON_DEPTH = 64;
const MAX_JSON_NODES = 400_000;

/** Why something cannot be edited automatically. Stable codes; the web app and the worker map them to text. */
export const REFUSALS = [
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
] as const;
export type Refusal = (typeof REFUSALS)[number];

export interface Dependency {
  /** As written in the manifest (Python names are normalised, see {@link normalizeName}). */
  name: string;
  /** The section of the manifest, e.g. "dependencies", "devDependencies", "require-dev". */
  section: string;
  /** The version requirement as written, e.g. "^4.17.20" or "==2.0.1" or "v1.2.3". */
  spec: string;
  /** Go: required only because another module needs it. */
  indirect: boolean;
  /** Only used for development, not shipped. */
  dev: boolean;
  /** Set when this declaration can never be edited automatically, whatever the target version is. */
  blocked?: Refusal;
}

/* -------------------------------------------------------------------------- */
/* Paths                                                                       */
/* -------------------------------------------------------------------------- */

const MANIFEST_NAMES = new Map<string, ManifestKind>([
  ["package.json", "npm"],
  ["composer.json", "composer"],
  ["go.mod", "go"],
  ["Cargo.toml", "cargo"],
]);

/** The ecosystem whose manifest a file is, by name, or null. */
export function manifestKindOfPath(path: string): ManifestKind | null {
  const base = path.split("/").pop() ?? "";
  const named = MANIFEST_NAMES.get(base);
  if (named) return named;
  if (/^requirements(?:[-_.][A-Za-z0-9_.-]{1,60})?\.txt$/.test(base)) return "pypi";
  return null;
}

/** A repository-relative path without a leading slash, or null if it could point anywhere but inside the repository. */
export function safeRepoPath(path: string): string | null {
  const clean = path.replace(/^\/+/, "");
  if (clean.length === 0 || clean.length > 500) return null;
  // biome-ignore lint/suspicious/noControlCharactersInRegex: rejecting control characters is the point
  if (/[\\\u0000-\u001f\u007f]/.test(clean)) return null;
  const parts = clean.split("/");
  if (parts.some((p) => p === "" || p === "." || p === "..")) return null;
  return clean;
}

const LOCK_FILES: Record<Ecosystem, string[]> = {
  npm: ["package.json", "package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml"],
  pypi: [],
  composer: ["composer.json", "composer.lock"],
  go: ["go.mod", "go.sum"],
  cargo: ["Cargo.toml", "Cargo.lock"],
};

/**
 * The manifest to edit for a finding found at `location` (where the scanner saw the package:
 * usually a lockfile): the manifest next to it. Null when there is none we can edit, for
 * instance a package installed inside `node_modules`, or a Poetry/Pipfile project.
 */
export function manifestPathFor(ecosystem: Ecosystem, location: string): string | null {
  const clean = safeRepoPath(location);
  if (!clean) return null;
  if (/(^|\/)(node_modules|vendor|\.git|site-packages|dist-packages|\.venv|venv)\//.test(clean)) return null;
  const slash = clean.lastIndexOf("/");
  const dir = slash >= 0 ? clean.slice(0, slash + 1) : "";
  const base = clean.slice(slash + 1);
  if (ecosystem === "pypi") return manifestKindOfPath(clean) === "pypi" ? clean : null;
  if (!LOCK_FILES[ecosystem].includes(base)) return null;
  const manifest =
    ecosystem === "npm"
      ? "package.json"
      : ecosystem === "composer"
        ? "composer.json"
        : ecosystem === "go"
          ? "go.mod"
          : "Cargo.toml";
  return `${dir}${manifest}`;
}

/** The name as the ecosystem compares it: Python and Cargo treat "-", "_" and "." alike, Composer and npm ignore case. */
export function normalizeName(kind: ManifestKind, name: string): string {
  if (kind === "pypi") return name.toLowerCase().replace(/[-_.]+/g, "-");
  if (kind === "cargo") return name.toLowerCase().replace(/_/g, "-");
  if (kind === "go") return name;
  return name.toLowerCase();
}

/** Package names we are willing to put in a branch name, a commit message or a pull request. */
export function isSafePackageName(name: string): boolean {
  return /^[A-Za-z0-9@][A-Za-z0-9@/._+~-]{0,213}$/.test(name) && !name.includes("..");
}

/* -------------------------------------------------------------------------- */
/* Version requirements                                                        */
/* -------------------------------------------------------------------------- */

export type BumpResult = { ok: true; spec: string } | { ok: false; reason: Refusal };

const refuse = (reason: Refusal): { ok: false; reason: Refusal } => ({ ok: false, reason });

/** The versions we write: digits and dots only, no pre-release. */
const PLAIN_TARGET = /^\d+(?:\.\d+){0,3}$/;

function bumpRange(kind: "npm" | "cargo" | "composer", spec: string, target: string): BumpResult {
  if (!PLAIN_TARGET.test(target)) return refuse("bad-target");
  const text = spec.trim();
  if (/[:/\\#]|^(?:git|file|link|workspace|npm|https?)/i.test(text)) return refuse("unsupported-source");
  if (kind === "composer" && /dev|@/i.test(text)) return refuse("unsupported-source");
  const match = /^(\^|~|>=|=)?\s*[vV]?(\d+(?:\.\d+){0,3})(-[0-9A-Za-z.-]+)?$/.exec(text);
  if (!match) return refuse("complex-range");
  const floor = `${match[2]}${match[3] ?? ""}`;
  const order = compareVersions("semver", floor, target);
  if (order === null) return refuse("complex-range");
  if (order >= 0) return refuse("already-satisfied");
  return { ok: true, spec: `${match[1] ?? ""}${target}` };
}

function bumpPypi(spec: string, target: string): BumpResult {
  const match = /^==\s*([0-9][0-9A-Za-z.!+_-]*)$/.exec(spec.trim());
  if (!match) return refuse("complex-range");
  const to = parseVersion("pep440", target);
  if (!to || isPrerelease(to) || !/^[0-9][0-9A-Za-z.]*$/.test(target)) return refuse("bad-target");
  const from = parseVersion("pep440", match[1] as string);
  if (!from) return refuse("complex-range");
  if (compareParsed(from, to) >= 0) return refuse("already-satisfied");
  return { ok: true, spec: `==${target}` };
}

function bumpGo(spec: string, target: string): BumpResult {
  const to = parseVersion("semver", target);
  if (!to || to.pre || !PLAIN_TARGET.test(target.replace(/^v/, ""))) return refuse("bad-target");
  const match = /^(v\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?)(\+incompatible)?$/.exec(spec.trim());
  if (!match) return refuse("complex-range");
  const from = parseVersion("semver", match[1] as string);
  if (!from) return refuse("complex-range");
  // A new major release of a Go module is a different import path: that needs code changes.
  if ((from.nums[0] ?? 0) !== (to.nums[0] ?? 0)) return refuse("major-change");
  const order = compareVersions("semver", match[1] as string, target);
  if (order === null) return refuse("complex-range");
  if (order >= 0) return refuse("already-satisfied");
  const bare = target.replace(/^v/, "");
  return { ok: true, spec: `v${bare}${match[2] ?? ""}` };
}

/**
 * The requirement after the bump: the operator the project chose stays (`^`, `~`, `=`, `>=`,
 * none), the version becomes the target. A requirement that is not one version with an
 * optional operator is refused ("complex-range"), one that already allows the target is
 * "already-satisfied" (then only the lockfile needs an update).
 */
export function bumpSpec(kind: ManifestKind, spec: string, target: string): BumpResult {
  if (spec.length > 200) return refuse("complex-range");
  if (kind === "pypi") return bumpPypi(spec, target);
  if (kind === "go") return bumpGo(spec, target);
  return bumpRange(kind, spec, target);
}

/* -------------------------------------------------------------------------- */
/* Scanning                                                                    */
/* -------------------------------------------------------------------------- */

/** One occurrence of a dependency with the text range of its requirement. */
interface Entry extends Dependency {
  start: number;
  end: number;
  /** The text to write for a new requirement. */
  compose: (spec: string) => string;
  /** Set when this occurrence can never be edited (git source, renamed, workspace …). */
  refusal?: Refusal;
}

interface Scan {
  entries: Entry[];
  /** Names (normalised) that occur twice in one section, or in a section that appears twice. */
  ambiguous: Set<string>;
  /** Names with a `replace` directive (Go). */
  replaced: Set<string>;
  /** Names with hash pins (Python). */
  hashed: Set<string>;
}

const emptyScan = (): Scan => ({
  entries: [],
  ambiguous: new Set(),
  replaced: new Set(),
  hashed: new Set(),
});

/* ---- JSON (package.json, composer.json) ---- */

type JNode =
  | { t: "obj"; members: { key: string; value: JNode }[] }
  | { t: "str"; start: number; end: number; value: string }
  | { t: "other" };

class JsonError extends Error {}

/**
 * A strict JSON reader that remembers where every string starts and ends. Rejects comments,
 * trailing commas, single quotes, unescaped control characters and anything nested deeper
 * than 64 levels; accepts a leading byte order mark.
 */
function readJson(text: string): JNode {
  let i = text.charCodeAt(0) === 0xfeff ? 1 : 0;
  let nodes = 0;
  const ws = () => {
    while (i < text.length) {
      const c = text.charCodeAt(i);
      if (c === 0x20 || c === 0x0a || c === 0x0d || c === 0x09) i++;
      else break;
    }
  };
  const str = (): JNode & { t: "str" } => {
    const start = i;
    i++; // opening quote
    for (;;) {
      if (i >= text.length) throw new JsonError();
      const c = text.charCodeAt(i);
      if (c === 0x22) break;
      if (c < 0x20) throw new JsonError();
      if (c === 0x5c) {
        const n = text[i + 1];
        if (n === "u") {
          if (!/^[0-9a-fA-F]{4}$/.test(text.slice(i + 2, i + 6))) throw new JsonError();
          i += 6;
          continue;
        }
        if (n === undefined || !'"\\/bfnrt'.includes(n)) throw new JsonError();
        i += 2;
        continue;
      }
      i++;
    }
    i++; // closing quote
    return { t: "str", start, end: i, value: "" };
  };
  const value = (depth: number): JNode => {
    if (++nodes > MAX_JSON_NODES || depth > MAX_JSON_DEPTH) throw new JsonError();
    ws();
    const c = text[i];
    if (c === "{") {
      i++;
      const members: { key: string; value: JNode }[] = [];
      ws();
      if (text[i] === "}") {
        i++;
        return { t: "obj", members };
      }
      for (;;) {
        ws();
        if (text[i] !== '"') throw new JsonError();
        const k = str();
        k.value = JSON.parse(text.slice(k.start, k.end)) as string;
        ws();
        if (text[i] !== ":") throw new JsonError();
        i++;
        members.push({ key: k.value, value: value(depth + 1) });
        ws();
        if (text[i] === ",") {
          i++;
          continue;
        }
        if (text[i] === "}") {
          i++;
          return { t: "obj", members };
        }
        throw new JsonError();
      }
    }
    if (c === "[") {
      i++;
      ws();
      if (text[i] === "]") {
        i++;
        return { t: "other" };
      }
      for (;;) {
        value(depth + 1);
        ws();
        if (text[i] === ",") {
          i++;
          continue;
        }
        if (text[i] === "]") {
          i++;
          return { t: "other" };
        }
        throw new JsonError();
      }
    }
    if (c === '"') {
      const s = str();
      s.value = JSON.parse(text.slice(s.start, s.end)) as string;
      return s;
    }
    const literal = /^(?:true|false|null|-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?)/.exec(
      text.slice(i, i + 400),
    );
    if (!literal) throw new JsonError();
    i += literal[0].length;
    return { t: "other" };
  };
  const root = value(0);
  ws();
  if (i !== text.length || root.t !== "obj") throw new JsonError();
  return root;
}

const JSON_SECTIONS: Record<"npm" | "composer", { name: string; dev: boolean }[]> = {
  npm: [
    { name: "dependencies", dev: false },
    { name: "devDependencies", dev: true },
    { name: "optionalDependencies", dev: false },
  ],
  composer: [
    { name: "require", dev: false },
    { name: "require-dev", dev: true },
  ],
};

function scanJson(kind: "npm" | "composer", text: string): Scan | null {
  let root: JNode;
  try {
    root = readJson(text);
    // Two independent readers must agree that this is JSON.
    JSON.parse(text.charCodeAt(0) === 0xfeff ? text.slice(1) : text);
  } catch {
    return null;
  }
  if (root.t !== "obj") return null;
  const scan = emptyScan();
  for (const section of JSON_SECTIONS[kind]) {
    const holders = root.members.filter((m) => m.key === section.name);
    const seen = new Set<string>();
    for (const holder of holders) {
      if (holder.value.t !== "obj") continue;
      for (const member of holder.value.members) {
        if (kind === "composer" && !member.key.includes("/")) continue; // php, ext-*, lib-*: not packages
        const name = normalizeName(kind, member.key);
        // A section that appears twice, or a name twice in a section: which one wins depends on the reader.
        if (seen.has(name) || holders.length > 1) scan.ambiguous.add(name);
        seen.add(name);
        const base = { name: member.key, section: section.name, indirect: false, dev: section.dev };
        if (member.value.t !== "str") {
          scan.entries.push({
            ...base,
            spec: "",
            start: 0,
            end: 0,
            compose: (s) => s,
            refusal: "unsupported-source",
          });
        } else {
          scan.entries.push({
            ...base,
            spec: member.value.value,
            start: member.value.start,
            end: member.value.end,
            compose: (spec) => JSON.stringify(spec),
          });
        }
        if (scan.entries.length > MAX_ENTRIES) return null;
      }
    }
  }
  return scan;
}

/* ---- Python requirements ---- */

interface TextLine {
  text: string;
  start: number;
}

/** Lines with their offsets; the line ending stays out of `text` and is never touched. */
function linesOf(source: string): TextLine[] {
  const lines: TextLine[] = [];
  let start = 0;
  while (start <= source.length) {
    let end = start;
    while (end < source.length && source.charCodeAt(end) !== 0x0a && source.charCodeAt(end) !== 0x0d) end++;
    lines.push({ text: source.slice(start, end), start });
    if (end >= source.length) break;
    start = end + (source.charCodeAt(end) === 0x0d && source.charCodeAt(end + 1) === 0x0a ? 2 : 1);
    if (lines.length > 200_000) break;
  }
  return lines;
}

/** One requirement line: the name and the range of its version specifier, or null if the line is not a requirement. */
function parseRequirement(text: string): { name: string; spec: string; start: number } | null {
  let code = text;
  const comment = /(^|\s)#/.exec(code);
  if (comment) code = code.slice(0, comment.index);
  code = code.trimEnd();
  const head = /^\s*([A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?)\s*(?:\[[^\]]*\])?\s*/.exec(code);
  if (!head) return null;
  const rest = code.slice(head[0].length);
  if (rest !== "" && !/^[<>=!~;@]/.test(rest)) return null;
  const marker = rest.indexOf(";");
  const spec = (marker < 0 ? rest : rest.slice(0, marker)).trimEnd();
  return { name: head[1] as string, spec, start: head[0].length };
}

function scanRequirements(text: string): Scan | null {
  if (text.includes("\0")) return null;
  const scan = emptyScan();
  const lines = linesOf(text);
  const counts = new Map<string, number>();
  for (let n = 0; n < lines.length; n++) {
    const line = lines[n] as TextLine;
    if (line.text.length > MAX_LINE) continue;
    const trimmed = line.text.trim();
    if (trimmed === "" || trimmed.startsWith("#") || trimmed.startsWith("-")) continue;
    const parsed = parseRequirement(line.text);
    if (!parsed) continue;
    const name = normalizeName("pypi", parsed.name);
    counts.set(name, (counts.get(name) ?? 0) + 1);
    // Hash-pinned requirements (pip --require-hashes) cannot be bumped without new hashes.
    if (
      trimmed.endsWith("\\") ||
      /--hash=/.test(trimmed) ||
      /^--hash=/.test(lines[n + 1]?.text.trim() ?? "")
    ) {
      scan.hashed.add(name);
    }
    scan.entries.push({
      name: parsed.name,
      section: "requirements",
      spec: parsed.spec,
      indirect: false,
      dev: false,
      start: line.start + parsed.start,
      end: line.start + parsed.start + parsed.spec.length,
      compose: (s) => s,
      ...(parsed.spec === ""
        ? { refusal: "complex-range" as const }
        : parsed.spec.startsWith("@")
          ? { refusal: "unsupported-source" as const }
          : {}),
    });
    if (scan.entries.length > MAX_ENTRIES) return null;
  }
  for (const [name, count] of counts) if (count > 1) scan.ambiguous.add(name);
  return scan;
}

/* ---- go.mod ---- */

function stripGoComment(line: string): { code: string; indirect: boolean } {
  const index = line.indexOf("//");
  if (index < 0) return { code: line, indirect: false };
  return { code: line.slice(0, index), indirect: /^\s*indirect(?:\s|$)/.test(line.slice(index + 2)) };
}

function scanGoMod(text: string): Scan | null {
  if (text.includes("\0")) return null;
  const scan = emptyScan();
  const counts = new Map<string, number>();
  let block: "require" | "replace" | "other" | null = null;
  for (const line of linesOf(text)) {
    if (line.text.length > MAX_LINE) continue;
    const { code, indirect } = stripGoComment(line.text);
    const tokens = code.trim().split(/\s+/).filter(Boolean);
    if (tokens.length === 0) continue;
    let args = tokens;
    if (block === null) {
      const directive = tokens[0] as string;
      if (tokens[1] === "(" && tokens.length === 2) {
        block = directive === "require" ? "require" : directive === "replace" ? "replace" : "other";
        continue;
      }
      if (directive !== "require" && directive !== "replace") continue;
      args = tokens.slice(1);
      block = null;
      handleGoLine(directive, args, line, code, indirect, scan, counts);
      continue;
    }
    if (tokens[0] === ")") {
      block = null;
      continue;
    }
    if (block === "other") continue;
    handleGoLine(block, args, line, code, indirect, scan, counts);
    if (scan.entries.length > MAX_ENTRIES) return null;
  }
  for (const [name, count] of counts) if (count > 1) scan.ambiguous.add(name);
  return scan;
}

function handleGoLine(
  directive: "require" | "replace",
  args: string[],
  line: TextLine,
  code: string,
  indirect: boolean,
  scan: Scan,
  counts: Map<string, number>,
) {
  const path = args[0];
  if (!path || path.startsWith('"') || path.startsWith("`")) return;
  if (directive === "replace") {
    scan.replaced.add(path);
    return;
  }
  const version = args[1];
  if (!version || args.length !== 2) return;
  counts.set(path, (counts.get(path) ?? 0) + 1);
  // The version token's own range within the line.
  const from = code.indexOf(version, code.indexOf(path) + path.length);
  scan.entries.push({
    name: path,
    section: "require",
    spec: version,
    indirect,
    dev: false,
    start: line.start + from,
    end: line.start + from + version.length,
    compose: (s) => s,
  });
}

/* ---- Cargo.toml ---- */

const CARGO_DEP_TABLES = new Set(["dependencies", "dev-dependencies", "build-dependencies"]);

/** Keys of a TOML header or dotted key: bare or quoted, up to the first character that ends them. */
function tomlKeyPath(source: string, from: number): { parts: string[]; end: number } | null {
  const parts: string[] = [];
  let i = from;
  for (;;) {
    while (source[i] === " " || source[i] === "\t") i++;
    const c = source[i];
    if (c === '"' || c === "'") {
      const close = source.indexOf(c, i + 1);
      if (close < 0) return null;
      const part = source.slice(i + 1, close);
      if (c === '"' && part.includes("\\")) return null;
      parts.push(part);
      i = close + 1;
    } else {
      const m = /^[A-Za-z0-9_-]+/.exec(source.slice(i, i + 300));
      if (!m) return null;
      parts.push(m[0]);
      i += m[0].length;
    }
    while (source[i] === " " || source[i] === "\t") i++;
    if (source[i] === ".") {
      i++;
      continue;
    }
    return { parts, end: i };
  }
}

/** Updates string, comment and bracket state for one line; the returned code has comments cut off. */
function tomlLineState(line: string, state: { depth: number; multi: string | null }): { code: string } {
  let out = "";
  let i = 0;
  while (i < line.length) {
    if (state.multi) {
      const close = line.indexOf(state.multi, i);
      if (close < 0) return { code: out + line.slice(i) };
      out += line.slice(i, close + 3);
      i = close + 3;
      state.multi = null;
      continue;
    }
    const c = line[i] as string;
    if (c === "#") break;
    if (c === '"' || c === "'") {
      if (line.startsWith(c.repeat(3), i)) {
        state.multi = c.repeat(3);
        out += c.repeat(3);
        i += 3;
        continue;
      }
      let j = i + 1;
      while (j < line.length && line[j] !== c) j += c === '"' && line[j] === "\\" ? 2 : 1;
      out += line.slice(i, j + 1);
      i = j + 1;
      continue;
    }
    if (c === "[" || c === "{") state.depth++;
    if (c === "]" || c === "}") state.depth = Math.max(0, state.depth - 1);
    out += c;
    i++;
  }
  return { code: out };
}

interface InlineMember {
  key: string;
  valueStart: number;
  valueEnd: number;
}

/** Reads one value starting at `i` (string, number, array, inline table); returns where it ends, or -1. */
function tomlValueEnd(source: string, i: number): number {
  const c = source[i];
  if (c === '"' || c === "'") {
    if (source.startsWith(c.repeat(3), i)) return -1;
    let j = i + 1;
    while (j < source.length && source[j] !== c) j += c === '"' && source[j] === "\\" ? 2 : 1;
    return j < source.length ? j + 1 : -1;
  }
  if (c === "[" || c === "{") {
    const close = c === "[" ? "]" : "}";
    let j = i + 1;
    for (;;) {
      while (j < source.length && /[\s,]/.test(source[j] as string)) j++;
      if (source[j] === close) return j + 1;
      if (c === "{") {
        const k = tomlKeyPath(source, j);
        if (!k || source[k.end] !== "=") return -1;
        j = k.end + 1;
        while (source[j] === " " || source[j] === "\t") j++;
      }
      const end = tomlValueEnd(source, j);
      if (end < 0) return -1;
      j = end;
    }
  }
  const m = /^[^\s,\]}#]+/.exec(source.slice(i, i + 200));
  return m ? i + m[0].length : -1;
}

function inlineTableMembers(source: string, open: number): { members: InlineMember[]; end: number } | null {
  const members: InlineMember[] = [];
  let j = open + 1;
  for (;;) {
    while (j < source.length && /[\s,]/.test(source[j] as string)) j++;
    if (source[j] === "}") return { members, end: j + 1 };
    const k = tomlKeyPath(source, j);
    if (!k || source[k.end] !== "=") return null;
    let v = k.end + 1;
    while (source[v] === " " || source[v] === "\t") v++;
    const end = tomlValueEnd(source, v);
    if (end < 0) return null;
    members.push({ key: k.parts.join("."), valueStart: v, valueEnd: end });
    j = end;
    if (members.length > 200) return null;
  }
}

/** The inside of a simple one-line string value at [start, end), or null. */
function plainStringInside(
  source: string,
  start: number,
  end: number,
): { start: number; end: number } | null {
  const q = source[start];
  if ((q !== '"' && q !== "'") || source[end - 1] !== q || end - start < 2) return null;
  const inner = source.slice(start + 1, end - 1);
  if (inner.includes("\\") || inner.includes(q)) return null;
  return { start: start + 1, end: end - 1 };
}

function scanCargo(text: string): Scan | null {
  if (text.includes("\0")) return null;
  const scan = emptyScan();
  const state = { depth: 0, multi: null as string | null };
  /** Current table: kind "deps" (name = requirement), or "dep" (a table for one dependency). */
  let table: { kind: "deps" | "dep" | "other"; section: string; dev: boolean; name?: string } = {
    kind: "other",
    section: "",
    dev: false,
  };
  const singles: {
    name: string;
    section: string;
    dev: boolean;
    version: Entry | null;
    refusal: Refusal | null;
  }[] = [];
  const counts = new Map<string, number>();

  for (const line of linesOf(text)) {
    if (line.text.length > MAX_LINE) continue;
    const continuation = state.depth > 0 || state.multi !== null;
    const { code } = tomlLineState(line.text, state);
    if (continuation) continue;
    const trimmed = code.trim();
    if (trimmed === "") continue;
    const lead = line.text.length - line.text.trimStart().length;

    if (trimmed.startsWith("[")) {
      const array = trimmed.startsWith("[[");
      const path = tomlKeyPath(line.text, lead + (array ? 2 : 1));
      if (!path || array) {
        table = { kind: "other", section: "", dev: false };
        continue;
      }
      const p = path.parts;
      const last = p[p.length - 1] as string;
      const beforeLast = p[p.length - 2];
      const isDepsTable = (parts: string[]) =>
        CARGO_DEP_TABLES.has(parts[parts.length - 1] as string) &&
        (parts.length === 1 ||
          (parts.length === 2 && parts[0] === "workspace") ||
          (parts.length === 3 && parts[0] === "target"));
      if (isDepsTable(p)) {
        table = { kind: "deps", section: p.join("."), dev: last === "dev-dependencies" };
      } else if (beforeLast !== undefined && isDepsTable(p.slice(0, -1))) {
        const section = p.slice(0, -1).join(".");
        table = { kind: "dep", section, dev: p[p.length - 2] === "dev-dependencies", name: last };
        counts.set(`${section}|${last}`, (counts.get(`${section}|${last}`) ?? 0) + 1);
        singles.push({ name: last, section, dev: table.dev, version: null, refusal: null });
      } else {
        table = { kind: "other", section: "", dev: false };
      }
      continue;
    }

    if (table.kind === "other") continue;
    const key = tomlKeyPath(line.text, lead);
    if (!key) continue;
    let eq = key.end;
    while (line.text[eq] === " " || line.text[eq] === "\t") eq++;
    if (line.text[eq] !== "=") continue;
    let v = eq + 1;
    while (line.text[v] === " " || line.text[v] === "\t") v++;

    if (table.kind === "dep") {
      const current = singles[singles.length - 1];
      if (!current) continue;
      const k = key.parts.join(".");
      if (k === "version") {
        const end = tomlValueEnd(line.text, v);
        const inside = end > 0 ? plainStringInside(line.text, v, end) : null;
        if (!inside) {
          current.refusal = "complex-range";
          continue;
        }
        if (current.version) scan.ambiguous.add(normalizeName("cargo", current.name));
        current.version = {
          name: current.name,
          section: current.section,
          spec: line.text.slice(inside.start, inside.end),
          indirect: false,
          dev: current.dev,
          start: line.start + inside.start,
          end: line.start + inside.end,
          compose: (s) => s,
        };
      } else if (["git", "path", "workspace", "registry", "package", "branch", "tag", "rev"].includes(k)) {
        current.refusal = "unsupported-source";
      }
      continue;
    }

    // A dependencies table: `name = "1"`, `name = { version = "1", … }`, `name.version = "1"`, `name.workspace = true`.
    const name = key.parts[0] as string;
    const rest = key.parts.slice(1).join(".");
    counts.set(`${table.section}|${name}`, (counts.get(`${table.section}|${name}`) ?? 0) + 1);
    const base = { name, section: table.section, indirect: false, dev: table.dev };
    const c = line.text[v];
    if (rest === "") {
      if (c === "{") {
        const table_ = inlineTableMembers(line.text, v);
        if (!table_) {
          scan.entries.push({
            ...base,
            spec: "",
            start: 0,
            end: 0,
            compose: (s) => s,
            refusal: "complex-range",
          });
          continue;
        }
        const keys = new Set(table_.members.map((m) => m.key));
        const version = table_.members.find((m) => m.key === "version");
        const blocked = ["git", "path", "workspace", "package", "registry"].some((k) => keys.has(k));
        const inside = version ? plainStringInside(line.text, version.valueStart, version.valueEnd) : null;
        if (!inside || blocked) {
          scan.entries.push({
            ...base,
            spec: "",
            start: 0,
            end: 0,
            compose: (s) => s,
            refusal: blocked || !version ? "unsupported-source" : "complex-range",
          });
          continue;
        }
        scan.entries.push({
          ...base,
          spec: line.text.slice(inside.start, inside.end),
          start: line.start + inside.start,
          end: line.start + inside.end,
          compose: (s) => s,
        });
      } else {
        const end = tomlValueEnd(line.text, v);
        const inside = end > 0 ? plainStringInside(line.text, v, end) : null;
        if (!inside) {
          scan.entries.push({
            ...base,
            spec: "",
            start: 0,
            end: 0,
            compose: (s) => s,
            refusal: "complex-range",
          });
          continue;
        }
        scan.entries.push({
          ...base,
          spec: line.text.slice(inside.start, inside.end),
          start: line.start + inside.start,
          end: line.start + inside.end,
          compose: (s) => s,
        });
      }
    } else if (rest === "version") {
      const end = tomlValueEnd(line.text, v);
      const inside = end > 0 ? plainStringInside(line.text, v, end) : null;
      scan.entries.push({
        ...base,
        spec: inside ? line.text.slice(inside.start, inside.end) : "",
        start: inside ? line.start + inside.start : 0,
        end: inside ? line.start + inside.end : 0,
        compose: (s) => s,
        ...(inside ? {} : { refusal: "complex-range" as const }),
      });
    } else {
      scan.entries.push({
        ...base,
        spec: "",
        start: 0,
        end: 0,
        compose: (s) => s,
        refusal: "unsupported-source",
      });
    }
    if (scan.entries.length > MAX_ENTRIES) return null;
  }
  for (const s of singles) {
    if (s.version) scan.entries.push({ ...s.version, ...(s.refusal ? { refusal: s.refusal } : {}) });
    else
      scan.entries.push({
        name: s.name,
        section: s.section,
        spec: "",
        indirect: false,
        dev: s.dev,
        start: 0,
        end: 0,
        compose: (x) => x,
        refusal: s.refusal ?? "unsupported-source",
      });
  }
  for (const [key, count] of counts)
    if (count > 1) scan.ambiguous.add(normalizeName("cargo", key.split("|")[1] as string));
  return scan;
}

/* -------------------------------------------------------------------------- */
/* Public API                                                                  */
/* -------------------------------------------------------------------------- */

function scanManifest(kind: ManifestKind, text: string): Scan | null {
  if (text.length > MAX_MANIFEST_BYTES) return null;
  switch (kind) {
    case "npm":
    case "composer":
      return scanJson(kind, text);
    case "pypi":
      return scanRequirements(text);
    case "go":
      return scanGoMod(text);
    case "cargo":
      return scanCargo(text);
  }
}

/**
 * The dependencies a manifest declares, or null if it cannot be read (too large, invalid,
 * not text). Occurrences GarnetOps could not read a requirement from are listed with an
 * empty requirement, so they still count as declared.
 */
export function listDependencies(kind: ManifestKind, text: string): Dependency[] | null {
  const scan = scanManifest(kind, text);
  if (!scan) return null;
  return scan.entries.map(({ name, section, spec, indirect, dev, refusal }) => {
    const normal = normalizeName(kind, name);
    const blocked: Refusal | undefined =
      refusal ??
      (scan.ambiguous.has(normal)
        ? "ambiguous"
        : scan.replaced.has(name)
          ? "replaced"
          : scan.hashed.has(normal)
            ? "hashes"
            : kind === "go" && indirect
              ? "indirect"
              : undefined);
    return { name, section, spec, indirect, dev, ...(blocked ? { blocked } : {}) };
  });
}

export interface ManifestChange {
  section: string;
  from: string;
  to: string;
  /** The replaced range in the original text. */
  start: number;
  end: number;
}

export type EditResult =
  | { ok: true; text: string; changes: ManifestChange[]; unchanged: number }
  | { ok: false; reason: Refusal };

/**
 * Bumps one dependency to `target` in every place the manifest declares it (for npm,
 * `dependencies`, `devDependencies` and `optionalDependencies`). All or nothing: if any
 * occurrence cannot be edited safely the whole edit is refused. The text outside the
 * replaced requirements is returned byte for byte.
 */
export function editManifest(
  kind: ManifestKind,
  text: string,
  change: { name: string; target: string },
): EditResult {
  if (text.length > MAX_MANIFEST_BYTES) return refuse("too-large");
  if (text.includes("\0")) return refuse("invalid");
  const scan = scanManifest(kind, text);
  if (!scan) return refuse("invalid");
  const wanted = normalizeName(kind, change.name);
  const entries = scan.entries.filter((e) => normalizeName(kind, e.name) === wanted);
  if (entries.length === 0) return refuse("not-found");
  if (scan.ambiguous.has(wanted)) return refuse("ambiguous");
  if (scan.replaced.has(change.name)) return refuse("replaced");
  if (scan.hashed.has(wanted)) return refuse("hashes");
  const edits: ManifestChange[] = [];
  let unchanged = 0;
  for (const entry of entries) {
    if (entry.refusal) return refuse(entry.refusal);
    if (kind === "go" && entry.indirect) return refuse("indirect");
    const bumped = bumpSpec(kind, entry.spec, change.target);
    if (!bumped.ok) {
      if (bumped.reason === "already-satisfied") {
        unchanged++;
        continue;
      }
      return refuse(bumped.reason);
    }
    edits.push({
      section: entry.section,
      from: entry.spec,
      to: bumped.spec,
      start: entry.start,
      end: entry.end,
    });
    // Remember how to write it.
    (edits[edits.length - 1] as ManifestChange & { compose?: (s: string) => string }).compose = entry.compose;
  }
  if (edits.length === 0) return refuse("already-satisfied");
  const ordered = [...edits].sort((a, b) => b.start - a.start);
  for (let i = 1; i < ordered.length; i++) {
    if ((ordered[i] as ManifestChange).end > (ordered[i - 1] as ManifestChange).start)
      return refuse("ambiguous");
  }
  let out = text;
  for (const e of ordered) {
    const compose = (e as ManifestChange & { compose?: (s: string) => string }).compose ?? ((s: string) => s);
    out = out.slice(0, e.start) + compose(e.to) + out.slice(e.end);
  }
  const clean = edits.map(({ section, from, to, start, end }) => ({ section, from, to, start, end }));
  return { ok: true, text: out, changes: clean, unchanged };
}
