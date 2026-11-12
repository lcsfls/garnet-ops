/**
 * Reading code from a clone for the code viewer (ADR 0048). Regular files only: symbolic links (the hardened clone writes them as
 * plain files anyway), devices and anything outside the clone are never opened. Text up to 1 MB per file; the search for usages
 * stops after a fixed number of files or seconds. Nothing is executed.
 */
import { lstat, open, readdir, realpath } from "node:fs/promises";
import { join, sep } from "node:path";
import {
  CODE_VIEW_LIMITS,
  type CodeExcerpt,
  type CodeView,
  cleanRepoPath,
  declarationLines,
  type Ecosystem,
  excerpt,
  languageOf,
  looksLikeText,
  SKIPPED_DIRS,
  SOURCE_FILES,
  usagePattern,
} from "@garnetops/core/code-view";

/** A file of the clone as text, or null when it is not a regular text file inside the clone within the size limit. */
export async function readCloneText(root: string, relativePath: string): Promise<string | null> {
  const clean = cleanRepoPath(relativePath);
  if (!clean) return null;
  const full = join(root, ...clean.split("/"));
  const info = await lstat(full).catch(() => null);
  if (!info?.isFile() || info.size > CODE_VIEW_LIMITS.maxFileBytes) return null;
  // No folder on the way may lead out of the clone.
  const [real, base] = await Promise.all([realpath(full).catch(() => null), realpath(root)]);
  if (!real?.startsWith(base + sep)) return null;
  const handle = await open(full, "r");
  try {
    const bytes = await handle.readFile();
    if (!looksLikeText(bytes)) return null;
    return new TextDecoder("utf-8", { fatal: false }).decode(bytes);
  } finally {
    await handle.close();
  }
}

/** The places of one package in the declaring files: manifests first, then lockfiles, each with the lines naming the package. */
export async function readDeclarations(
  root: string,
  packageName: string,
  files: { path: string; role: "manifest" | "lockfile" }[],
): Promise<CodeExcerpt[]> {
  const out: CodeExcerpt[] = [];
  const seen = new Set<string>();
  for (const file of files) {
    if (out.length >= CODE_VIEW_LIMITS.maxDeclarationFiles) break;
    const path = cleanRepoPath(file.path);
    if (!path || seen.has(path)) continue;
    seen.add(path);
    const text = await readCloneText(root, path);
    if (text === null) continue;
    const marks = declarationLines(text, packageName);
    if (marks.length === 0) continue;
    out.push({
      path,
      role: file.role,
      language: languageOf(path),
      lines: excerpt(text, marks, CODE_VIEW_LIMITS.declarationContext),
      marks,
    });
  }
  return out;
}

/** Where the code imports the package: a walk of the clone's own source files, bounded in files and time. */
export async function searchUsages(
  root: string,
  ecosystem: Ecosystem,
  packageName: string,
  now: () => number = () => performance.now(),
): Promise<Pick<CodeView, "usages" | "usageCount" | "usageFileCount" | "search">> {
  const pattern = usagePattern(ecosystem, packageName);
  const sources = SOURCE_FILES[ecosystem];
  if (!pattern || !sources) {
    return { usages: [], usageCount: 0, usageFileCount: 0, search: { ran: false, files: 0, stopped: null } };
  }
  const started = now();
  const usages: CodeExcerpt[] = [];
  let usageCount = 0;
  let usageFileCount = 0;
  let files = 0;
  let stopped: "files" | "time" | null = null;
  const queue: string[] = [""];
  while (queue.length > 0 && !stopped) {
    const dir = queue.shift() as string;
    const entries = await readdir(join(root, dir), { withFileTypes: true }).catch(() => []);
    entries.sort((a, b) => a.name.localeCompare(b.name));
    for (const entry of entries) {
      const path = dir ? `${dir}/${entry.name}` : entry.name;
      // Dirent says what the entry itself is: a symbolic link is neither a directory nor a file here.
      if (entry.isDirectory()) {
        if (!SKIPPED_DIRS.has(entry.name)) queue.push(path);
        continue;
      }
      if (!entry.isFile() || !sources.test(entry.name)) continue;
      if (files >= CODE_VIEW_LIMITS.maxFiles) {
        stopped = "files";
        break;
      }
      if (now() - started > CODE_VIEW_LIMITS.maxSearchMs) {
        stopped = "time";
        break;
      }
      files += 1;
      const text = await readCloneText(root, path);
      if (text === null) continue;
      const lines = text.split(/\r?\n/);
      const marks: number[] = [];
      for (let i = 0; i < lines.length; i += 1) {
        if (pattern.test(lines[i] as string)) marks.push(i + 1);
      }
      if (marks.length === 0) continue;
      usageCount += marks.length;
      usageFileCount += 1;
      const room = CODE_VIEW_LIMITS.maxUsages - usages.reduce((sum, u) => sum + u.marks.length, 0);
      if (usages.length < CODE_VIEW_LIMITS.maxUsageFiles && room > 0) {
        const kept = marks.slice(0, room);
        usages.push({
          path,
          role: "usage",
          language: languageOf(path),
          lines: excerpt(text, kept, CODE_VIEW_LIMITS.usageContext),
          marks: kept,
        });
      }
    }
  }
  return { usages, usageCount, usageFileCount, search: { ran: true, files, stopped } };
}
