/**
 * Collecting manifests from a cloned repository (ADR 0014): real git, a throw-away repository
 * with hostile content. Needs git.
 */
import { execFileSync } from "node:child_process";
import { mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { blobSha } from "../test/fake-forge.ts";
import { collectManifests, gitBlobId } from "./manifests.ts";

let git = true;
try {
  execFileSync("git", ["--version"], { stdio: "ignore" });
} catch {
  git = false;
}

const work = mkdtempSync(join(tmpdir(), "garnetops-manifests-test-"));
const repo = join(work, "repo");
const home = join(work, "home");

const PACKAGE = '{"dependencies":{"lodash":"^4.17.20"},"devDependencies":{"mocha":"9.0.0"}}\n';

function run(...args: string[]) {
  execFileSync("git", ["-C", repo, ...args], {
    env: {
      PATH: process.env.PATH,
      HOME: home,
      GIT_CONFIG_GLOBAL: "/dev/null",
      GIT_CONFIG_NOSYSTEM: "1",
      GIT_AUTHOR_NAME: "t",
      GIT_AUTHOR_EMAIL: "t@example.test",
      GIT_COMMITTER_NAME: "t",
      GIT_COMMITTER_EMAIL: "t@example.test",
    },
    stdio: "ignore",
  });
}

afterAll(() => rmSync(work, { recursive: true, force: true }));

describe.skipIf(!git)("collectManifests", () => {
  beforeAll(() => {
    mkdirSync(repo, { recursive: true });
    mkdirSync(home, { recursive: true });
    run("init", "--quiet");
    const put = (path: string, content: string | Buffer) => {
      mkdirSync(join(repo, path, ".."), { recursive: true });
      writeFileSync(join(repo, path), content);
    };
    put("package.json", PACKAGE);
    put("web/package.json", '{"dependencies":{"a":"1.0.0"}}');
    put("requirements.txt", "requests==2.25.0\n");
    put("go.mod", "module m\nrequire a.example/b v1.0.0\n");
    put("node_modules/x/package.json", '{"dependencies":{"evil":"1.0.0"}}');
    put("vendor/y/composer.json", '{"require":{"evil/evil":"1.0.0"}}');
    put("bin/package.json", Buffer.from([0x7b, 0xff, 0xfe, 0x7d]));
    put("broken/package.json", "{ not json");
    put("big/package.json", `{"dependencies":{"a":"1.0.0"},"pad":"${"x".repeat(1_100_000)}"}`);
    put("requirements-dev.txt", "pytest==7.0.0\n");
    put("literal/:(glob)*/package.json", '{"dependencies":{"lit":"1.0.0"}}');
    put("literal/other/package.json", '{"dependencies":{"other":"1.0.0"}}');
    // A symlink named like a manifest: committed as a link, not as a file.
    symlinkSync("/etc/passwd", join(repo, "link-package.json"));
    mkdirSync(join(repo, "sym"), { recursive: true });
    symlinkSync("../package.json", join(repo, "sym", "package.json"));
    run("add", "-A", "-f");
    run("commit", "--quiet", "-m", "x");
  });

  it("records manifests with the blob id git stores, and what they declare", async () => {
    const found = await collectManifests(repo, home);
    const byPath = new Map(found.map((m) => [m.path, m]));
    expect(byPath.get("package.json")).toMatchObject({
      kind: "npm",
      blobSha: blobSha(PACKAGE),
      size: PACKAGE.length,
    });
    expect(byPath.get("package.json")?.dependencies.map((d) => [d.name, d.spec, d.dev])).toEqual([
      ["lodash", "^4.17.20", false],
      ["mocha", "9.0.0", true],
    ]);
    expect(blobSha(PACKAGE)).toBe(gitBlobId(Buffer.from(PACKAGE)));
    expect(byPath.get("requirements.txt")?.kind).toBe("pypi");
    expect(byPath.get("requirements-dev.txt")?.kind).toBe("pypi");
    expect(byPath.get("go.mod")?.kind).toBe("go");
    expect(byPath.get("web/package.json")?.kind).toBe("npm");
  });

  it("leaves out installed copies, symlinks, non-UTF-8 files, unreadable and oversized files", async () => {
    const paths = (await collectManifests(repo, home)).map((m) => m.path);
    expect(paths).not.toContain("node_modules/x/package.json");
    expect(paths).not.toContain("vendor/y/composer.json");
    expect(paths).not.toContain("sym/package.json");
    expect(paths).not.toContain("bin/package.json");
    expect(paths).not.toContain("broken/package.json");
    expect(paths).not.toContain("big/package.json");
  });

  it("takes a path literally, never as a git pathspec", async () => {
    const found = await collectManifests(repo, home);
    const literal = found.filter((m) => m.path.startsWith("literal/"));
    expect(literal.map((m) => m.path).sort()).toEqual([
      "literal/:(glob)*/package.json",
      "literal/other/package.json",
    ]);
    expect(literal.find((m) => m.path.includes(":(glob)"))?.dependencies.map((d) => d.name)).toEqual(["lit"]);
  });

  it("an empty or missing directory gives nothing, not an error", async () => {
    expect(await collectManifests(join(work, "nowhere"), home)).toEqual([]);
  });
});
