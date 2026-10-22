/**
 * Reads the dependency manifests of a freshly cloned repository (ADR 0014) for the Fix
 * proposals page. The clone is hostile input: file names are checked, symlinks and submodules
 * are skipped, sizes are capped, the files are read as data only and parsed by the pure
 * scanners in packages/core. Nothing from the repository is executed, and no package manager
 * is started.
 *
 * Each manifest is recorded with the git blob id from the repository's own tree, which is what
 * the forge's contents API reports as the file's `sha`. A pull request later refuses to edit
 * a file whose id differs.
 */
import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { readdir } from "node:fs/promises";
import { platform } from "node:os";
import { join } from "node:path";
import {
  listDependencies,
  MAX_MANIFEST_BYTES,
  type ManifestKind,
  manifestKindOfPath,
  safeRepoPath,
} from "@garnetops/core/manifests";

export interface CollectedManifest {
  path: string;
  kind: ManifestKind;
  blobSha: string;
  size: number;
  dependencies: NonNullable<ReturnType<typeof listDependencies>>;
}

const MAX_MANIFESTS = 300;
const MAX_DEPENDENCIES = 5000;
const MAX_VISITED = 200_000;
const MAX_DEPTH = 12;
const SKIP_DIRECTORIES = new Set([
  ".git",
  "node_modules",
  "vendor",
  "target",
  "dist",
  "build",
  ".venv",
  "venv",
  "env",
  "__pycache__",
  "site-packages",
  ".next",
  ".tox",
  ".cache",
]);

/**
 * Environment for read-only git commands (ls-tree, cat-file) inside a clone: no user or system
 * configuration, no prompts, paths taken literally and never as pathspec patterns.
 */
function readOnlyGitEnv(home: string): NodeJS.ProcessEnv {
  return {
    PATH: process.env.PATH,
    SystemRoot: process.env.SystemRoot,
    HOME: home,
    USERPROFILE: home,
    GIT_TERMINAL_PROMPT: "0",
    GIT_CONFIG_NOSYSTEM: "1",
    GIT_CONFIG_GLOBAL: platform() === "win32" ? "NUL" : "/dev/null",
    GIT_LITERAL_PATHSPECS: "1",
    GIT_ASKPASS: "",
  };
}

/** Runs git and returns up to `max` bytes of stdout as a Buffer; more is an error. */
function git(args: string[], env: NodeJS.ProcessEnv, dir: string, max: number): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const child = spawn("git", ["-C", dir, ...args], {
      env,
      shell: false,
      stdio: ["ignore", "pipe", "ignore"],
    });
    const chunks: Buffer[] = [];
    let size = 0;
    const timer = setTimeout(() => child.kill("SIGKILL"), 30_000);
    child.stdout.on("data", (chunk: Buffer) => {
      size += chunk.length;
      if (size > max) child.kill("SIGKILL");
      else chunks.push(chunk);
    });
    child.on("error", (error) => {
      clearTimeout(timer);
      reject(error);
    });
    child.on("close", (code) => {
      clearTimeout(timer);
      if (code !== 0 || size > max) return reject(new Error("git failed"));
      resolve(Buffer.concat(chunks));
    });
  });
}

/** Candidate manifest paths in the working tree, by file name only. */
async function findCandidates(root: string): Promise<string[]> {
  const found: string[] = [];
  let visited = 0;
  const walk = async (relative: string, depth: number): Promise<void> => {
    if (depth > MAX_DEPTH || found.length >= MAX_MANIFESTS) return;
    let entries: import("node:fs").Dirent[];
    try {
      entries = await readdir(join(root, relative), { withFileTypes: true });
    } catch {
      return;
    }
    entries.sort((a, b) => a.name.localeCompare(b.name));
    for (const entry of entries) {
      if (++visited > MAX_VISITED || found.length >= MAX_MANIFESTS) return;
      const path = relative ? `${relative}/${entry.name}` : entry.name;
      if (entry.isDirectory()) {
        if (!SKIP_DIRECTORIES.has(entry.name)) await walk(path, depth + 1);
      } else if (entry.isFile() && manifestKindOfPath(path)) {
        found.push(path);
      }
    }
  };
  await walk("", 0);
  return found;
}

/** The blob id git stores for these bytes. */
export function gitBlobId(bytes: Buffer): string {
  return createHash("sha1").update(`blob ${bytes.length}\0`).update(bytes).digest("hex");
}

/**
 * Manifests of the checked-out commit. Files that cannot be used (a symlink, not UTF-8, too
 * large, not readable by the scanner) are left out; they have no proposals, which is the
 * safe outcome.
 */
export async function collectManifests(dir: string, home: string): Promise<CollectedManifest[]> {
  const gitEnv = readOnlyGitEnv(home);
  const out: CollectedManifest[] = [];
  for (const candidate of await findCandidates(dir)) {
    const path = safeRepoPath(candidate);
    const kind = path ? manifestKindOfPath(path) : null;
    if (!path || !kind) continue;
    try {
      // The tree entry says what the commit holds: a regular file, and which blob.
      const entry = (await git(["ls-tree", "-z", "HEAD", "--", path], gitEnv, dir, 4096)).toString("utf8");
      const match = /^(100644|100755) blob ([0-9a-f]{40})\t/.exec(entry);
      if (!match) continue;
      const bytes = await git(["cat-file", "blob", match[2] as string], gitEnv, dir, MAX_MANIFEST_BYTES);
      if (gitBlobId(bytes) !== match[2]) continue;
      const text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
      const dependencies = listDependencies(kind, text);
      if (!dependencies) continue;
      out.push({
        path,
        kind,
        blobSha: match[2] as string,
        size: bytes.length,
        dependencies: dependencies.slice(0, MAX_DEPENDENCIES),
      });
    } catch {
      // Not UTF-8, too large, git could not read it: no proposals for this file.
    }
  }
  return out;
}
