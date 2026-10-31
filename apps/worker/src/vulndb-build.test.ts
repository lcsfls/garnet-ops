/**
 * Our own vulnerability database (ADR 0044), the worker's side: a stand-in builder on a Unix socket, a fake grype and a
 * throw-away PostgreSQL database. The keys reach the builder only in the build request, the archive is checked by name,
 * size and SHA-256 before grype imports it, and every outcome is reported as a code. Skipped without the development
 * PostgreSQL or a POSIX shell.
 */
import { createHash } from "node:crypto";
import {
  chmodSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { createServer, type Server } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { vulnDbBuildReportSchema, vulnDbUpdateReportSchema } from "@garnetops/core/system-status";
import { schema } from "@garnetops/db";
import { devDatabaseUrl, type TestDatabase } from "@garnetops/db/testing";
import { eq } from "drizzle-orm";
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";

const adminUrl = devDatabaseUrl();
const posix = process.platform !== "win32";
const work = mkdtempSync(join(tmpdir(), "garnetops-vulndb-build-test-"));
afterAll(() => rmSync(work, { recursive: true, force: true }));

const held = vi.hoisted(() => ({
  t: null as unknown,
  env: {} as Record<string, string | undefined>,
  keys: { github: null as string | null, nvd: null as string | null },
}));

vi.mock("./db.ts", async () => {
  const { createTestDatabase: create, devDatabaseUrl: url } = await import("@garnetops/db/testing");
  const target = url();
  if (!target) return { db: null, pool: null };
  const t = await create(target, "worker_vulndb_build");
  held.t = t;
  return { db: t.db, pool: t.pool };
});
vi.mock("./env.ts", () => ({ env: held.env }));
vi.mock("./vault-secrets.ts", () => ({
  openSecretText: async (_id: string | null, _org: string, purpose: string) =>
    purpose === "vulndb-github-token"
      ? held.keys.github
      : purpose === "vulndb-nvd-api-key"
        ? held.keys.nvd
        : null,
}));

const ARCHIVE = "vulnerability-db_v6.1.10_2026-10-31T18:42:10Z_1793472135.tar.zst";
const builds = join(work, "builds");
const socket = join(work, "builder.sock");
const imported = join(work, "imported.txt");

/** A fake grype: records what it imports, and answers `db status` with the build time of the last import. */
function fakeGrype(): string {
  const file = join(work, "grype");
  writeFileSync(
    file,
    `#!/bin/sh
case "$1 $2" in
  "db import") [ "$GRYPE_DB_AUTO_UPDATE" = "false" ] || exit 3; echo "$3" > "${imported}" ;;
  "db status") if [ -f "${imported}" ]; then echo '{"schemaVersion":"v6.1.10","built":"2026-10-31T18:42:15Z","path":"","valid":true}'; else echo 'database does not exist' >&2; exit 1; fi ;;
  "db providers") echo '[]' ;;
  *) exit 2 ;;
esac
`,
  );
  chmodSync(file, 0o755);
  return file;
}

type Answer = Record<string, unknown>;

/** The stand-in builder: answers POST /v1/build with `startCode` and GET /v1/build with the queued answers in turn. */
function builder(answers: Answer[], startCode = 202) {
  const posted: unknown[] = [];
  const server: Server = createServer((req, res) => {
    let body = "";
    req.on("data", (c) => {
      body += c;
    });
    req.on("end", () => {
      res.setHeader("content-type", "application/json");
      if (req.method === "POST") {
        posted.push(JSON.parse(body));
        res.statusCode = startCode;
        res.end(JSON.stringify({ state: "running" }));
        return;
      }
      res.end(JSON.stringify(answers.length > 1 ? answers.shift() : answers[0]));
    });
  });
  rmSync(socket, { force: true });
  return new Promise<{ posted: unknown[]; close: () => Promise<void> }>((resolve) =>
    server.listen(socket, () =>
      resolve({ posted, close: () => new Promise<void>((done) => server.close(() => done())) }),
    ),
  );
}

const provider = (name: string, result: "ok" | "failed" | "skipped", reason: string | null = null) => ({
  name,
  lastRunAt: "2026-10-31T18:00:00Z",
  result,
  records: result === "ok" ? 12 : null,
  durationMs: 1000,
  reason,
});

function archiveOf(content: string) {
  mkdirSync(builds, { recursive: true });
  writeFileSync(join(builds, ARCHIVE), content);
  return {
    file: ARCHIVE,
    sha256: createHash("sha256").update(content).digest("hex"),
    size: Buffer.byteLength(content),
    built: "2026-10-31T18:42:15Z",
    schemaVersion: "v6.1.10",
  };
}

const done = (archive: unknown, state = "succeeded", reason: string | null = null) => ({
  state,
  startedAt: "2026-10-31T18:00:00Z",
  finishedAt: "2026-10-31T18:43:00Z",
  reason,
  providers: [
    provider("alpine", "ok"),
    provider("github", "skipped", "no_key"),
    provider("nvd", "failed", "rate_limited"),
  ],
  archive,
});
const running = { ...done(null, "running"), finishedAt: null };

describe("pure parts", () => {
  it("plans the first build after a start", async () => {
    const { firstBuildPlan } = await import("./vulndb-build.ts");
    const now = Date.parse("2026-10-31T20:43:00Z");
    expect(firstBuildPlan(null, now)).toEqual({ follow: false, waitMs: 0 });
    expect(firstBuildPlan({ ...done(null), state: "running" } as never, now)).toEqual({
      follow: true,
      waitMs: 0,
    });
    // Finished two hours ago: take it over, the next build 22 hours later.
    expect(firstBuildPlan(done(null) as never, now)).toEqual({ follow: true, waitMs: 22 * 3600_000 });
    expect(firstBuildPlan(done(null) as never, now + 30 * 3600_000)).toEqual({ follow: false, waitMs: 0 });
    expect(firstBuildPlan(done(null, "failed", "no_data") as never, now)).toEqual({
      follow: false,
      waitMs: 0,
    });
  });

  it("accepts only codes and plain names from the builder", async () => {
    const { builderStatusSchema } = await import("./vulndb-build.ts");
    expect(builderStatusSchema.safeParse(done(null)).success).toBe(true);
    expect(
      builderStatusSchema.safeParse({ ...done(null), reason: "HTTPError: 429 for https://feed.example.com" })
        .success,
    ).toBe(false);
    expect(
      builderStatusSchema.safeParse({ ...done(null), providers: [provider("../etc", "ok")] }).success,
    ).toBe(false);
    expect(
      builderStatusSchema.safeParse({
        ...done(null),
        archive: { ...archiveOf("x"), file: "../../etc/passwd" },
      }).success,
    ).toBe(false);
  });

  it("maps the builder's codes", async () => {
    const { reasonOfBuild } = await import("./vulndb-build.ts");
    expect(reasonOfBuild("no_data")).toBe("no_data");
    expect(reasonOfBuild("interrupted")).toBe("not_started");
    expect(reasonOfBuild("package_failed")).toBe("build_failed");
  });

  it("checks the archive by place, size and SHA-256", async () => {
    const { verifiedArchive } = await import("./vulndb-build.ts");
    const good = archiveOf("a database");
    expect(await verifiedArchive(good, builds)).toBe(join(builds, ARCHIVE));
    expect(await verifiedArchive({ ...good, sha256: "0".repeat(64) }, builds)).toBeNull();
    expect(await verifiedArchive({ ...good, size: good.size + 1 }, builds)).toBeNull();
    const outside = join(work, "outside.tar.zst");
    writeFileSync(outside, "a database");
    rmSync(join(builds, ARCHIVE));
    symlinkSync(outside, join(builds, ARCHIVE));
    expect(await verifiedArchive(good, builds)).toBeNull();
    rmSync(join(builds, ARCHIVE));
  });
});

describe.skipIf(!adminUrl || !posix)("a build", () => {
  let t: TestDatabase;
  let mod: typeof import("./vulndb-build.ts");
  const signal = new AbortController().signal;

  beforeAll(async () => {
    mod = await import("./vulndb-build.ts");
    t = held.t as TestDatabase;
    Object.assign(held.env, {
      GARNETOPS_GRYPE_DB_UPDATE: "build",
      GARNETOPS_WORK_DIR: work,
      GARNETOPS_GRYPE_DB_DIR: join(work, "db"),
      GARNETOPS_GRYPE_BIN: fakeGrype(),
      GARNETOPS_VULNDB_BUILDER_SOCKET: socket,
      GARNETOPS_VULNDB_BUILDS_DIR: builds,
    });
  }, 60_000);
  afterAll(async () => {
    await t?.drop();
  });
  beforeEach(async () => {
    await t.db.delete(schema.systemReport);
    await t.db.delete(schema.vulnDbBuildSettings);
    rmSync(imported, { force: true });
    held.keys = { github: null, nvd: null };
  });

  const reportOf = async (key: string) =>
    (await t.db.select().from(schema.systemReport).where(eq(schema.systemReport.key, key)))[0]?.data;

  it("hands over the keys, checks the archive, imports it and reports each provider", async () => {
    const [org] = await t.db.insert(schema.organization).values({ id: "org-1", name: "Example" }).returning();
    await t.db.insert(schema.vulnDbBuildSettings).values({
      id: "installation",
      githubSecretId: "s1",
      githubOrganizationId: org?.id,
      nvdSecretId: "s2",
      nvdOrganizationId: org?.id,
    });
    held.keys = { github: `ghp_${"a".repeat(36)}`, nvd: "nvd-key" };
    const fake = await builder([running, done(archiveOf("a database"))]);
    try {
      await mod.buildOnce(signal, { pollMs: 5 });
    } finally {
      await fake.close();
    }
    expect(fake.posted).toEqual([{ githubToken: `ghp_${"a".repeat(36)}`, nvdApiKey: "nvd-key" }]);
    expect(readFileSync(imported, "utf8").trim()).toBe(join(builds, ARCHIVE));
    expect(vulnDbUpdateReportSchema.parse(await reportOf("vulndb_update"))).toMatchObject({
      mode: "build",
      lastResult: "ok",
      reason: null,
    });
    const report = vulnDbBuildReportSchema.parse(await reportOf("vulndb_build"));
    expect(report).toMatchObject({ enabled: true, lastBuildAt: "2026-10-31T18:43:00Z" });
    expect(report.providers.map((p) => [p.name, p.result, p.reason])).toEqual([
      ["alpine", "ok", null],
      ["github", "skipped", "no_key"],
      ["nvd", "failed", "rate_limited"],
    ]);
    expect(JSON.stringify(await t.db.select().from(schema.systemReport))).not.toContain("nvd-key");
    await t.db.delete(schema.vulnDbBuildSettings);
    await t.db.delete(schema.organization).where(eq(schema.organization.id, "org-1"));
  });

  it("sends no keys when none are set", async () => {
    const fake = await builder([done(archiveOf("a database"))]);
    try {
      await mod.buildOnce(signal, { pollMs: 5 });
    } finally {
      await fake.close();
    }
    expect(fake.posted).toEqual([{ githubToken: null, nvdApiKey: null }]);
  });

  it("refuses an archive that does not match what the builder announced", async () => {
    const fake = await builder([done({ ...archiveOf("a database"), sha256: "f".repeat(64) })]);
    try {
      await mod.buildOnce(signal, { pollMs: 5 });
    } finally {
      await fake.close();
    }
    expect(existsSync(imported)).toBe(false);
    expect(vulnDbUpdateReportSchema.parse(await reportOf("vulndb_update"))).toMatchObject({
      lastResult: "failed",
      reason: "archive_rejected",
    });
  });

  it("keeps the database when the build fails, and says why", async () => {
    const fake = await builder([done(null, "failed", "no_data")]);
    try {
      await mod.buildOnce(signal, { pollMs: 5 });
    } finally {
      await fake.close();
    }
    expect(existsSync(imported)).toBe(false);
    expect(vulnDbUpdateReportSchema.parse(await reportOf("vulndb_update"))).toMatchObject({
      reason: "no_data",
    });
  });

  it("says so when the builder does not answer", async () => {
    rmSync(socket, { force: true });
    await mod.buildOnce(signal, { pollMs: 5 });
    expect(vulnDbUpdateReportSchema.parse(await reportOf("vulndb_update"))).toMatchObject({
      lastResult: "failed",
      reason: "builder_unreachable",
    });
  });

  it("follows a build that already runs, and does not import the same build twice", async () => {
    const fake = await builder([done(archiveOf("a database"))], 409);
    try {
      await mod.buildOnce(signal, { pollMs: 5 });
      expect(existsSync(imported)).toBe(true);
      rmSync(imported);
      // The probe recorded the build time; taking the same build over again imports nothing.
      writeFileSync(imported, "kept");
      await mod.buildOnce(signal, { start: false, pollMs: 5 });
      expect(readFileSync(imported, "utf8")).toBe("kept");
    } finally {
      await fake.close();
    }
  });
});
