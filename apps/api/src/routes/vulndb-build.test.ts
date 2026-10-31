/**
 * The keys of the own vulnerability database build against a throw-away PostgreSQL database on the development server: who may
 * read and change them, the recent sign-in and acknowledgement they need, the key shapes, that a key is sealed at once and never
 * returned, that replacing and removing delete the old secret, and the audit trail. Sessions are replaced by a header-driven
 * actor. Skipped without the development PostgreSQL.
 */

import { loadVaultPrivateKey, open as openSecret } from "@garnetops/core/vault";
import { schema } from "@garnetops/db";
import { devDatabaseUrl, type TestDatabase } from "@garnetops/db/testing";
import { eq } from "drizzle-orm";
import { Hono } from "hono";
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";

const adminUrl = devDatabaseUrl();

const shared = vi.hoisted(() => ({ db: null as unknown, privateKeyPem: "" }));

vi.mock("../db.ts", async () => {
  const { createTestDatabase: create, devDatabaseUrl: url } = await import("@garnetops/db/testing");
  const target = url();
  if (!target) return { db: null, pool: null, boss: null, QUEUES: {} };
  const t = await create(target, "api_vulndb_build");
  shared.db = t;
  return { db: t.db, pool: t.pool, boss: null, QUEUES: {} };
});
vi.mock("../env.ts", async () => {
  const { generateVaultKeyPair: gen, loadVaultPublicKey: load } = await import("@garnetops/core/vault");
  const pair = gen();
  shared.privateKeyPem = pair.privateKeyPem;
  return { env: {}, isProduction: false, vaultPublicKey: load(pair.publicKeyPem) };
});
vi.mock("../auth.ts", () => ({ auth: { api: {} } }));

// biome-ignore lint/suspicious/noExplicitAny: test helper for arbitrary response bodies
type Json = Record<string, any>;
type Role = "owner" | "admin" | "member" | "viewer";
const ORG = "org_vdb_a";
const OTHER = "org_vdb_b";
const STALE = 11 * 60;
// Built at run time, so no scanner mistakes them for real tokens.
const GITHUB_TOKEN = `ghp_${"Ab3".repeat(12)}`;
const GITHUB_TOKEN_2 = `github_pat_${"x9_".repeat(10)}`;
const NVD_KEY = ["0f1e2d3c", "4b5a", "6978", "8796", "a5b4c3d2e1f0"].join("-");
const NVD_KEY_2 = ["11111111", "2222", "3333", "4444", "555555555555"].join("-");

describe.skipIf(!adminUrl)("Vulnerability database build keys API", () => {
  let t: TestDatabase;
  let app: Hono;

  async function call(
    method: string,
    path: string,
    options: { role?: Role; org?: string; user?: string; age?: number; body?: unknown } = {},
  ) {
    const headers: Record<string, string> = {
      "x-role": options.role ?? "admin",
      "x-org": options.org ?? ORG,
      "x-user": options.user ?? "user_vdb_a",
      "x-age": String(options.age ?? 0),
      "x-ip": "198.51.100.7",
    };
    if (options.body !== undefined) headers["content-type"] = "application/json";
    const res = await app.request(`/api/v1/vulndb-build${path === "/" ? "" : path}`, {
      method,
      headers,
      body: options.body === undefined ? undefined : JSON.stringify(options.body),
    });
    const text = await res.text();
    let json: unknown = null;
    try {
      json = text ? JSON.parse(text) : null;
    } catch {
      // not JSON
    }
    return { status: res.status, json: json as Json | null, text };
  }
  const problemCode = (r: { json: Record<string, unknown> | null }) =>
    String(r.json?.type ?? "")
      .split("/")
      .pop();
  const audits = async (action: string) =>
    (await t.db.select().from(schema.auditLog)).filter((row) => row.action === action);
  const secrets = (purpose: "vulndb-github-token" | "vulndb-nvd-api-key") =>
    t.db.select().from(schema.secret).where(eq(schema.secret.purpose, purpose));
  const settings = async () =>
    (await t.db.select().from(schema.vulnDbBuildSettings))[0] as
      | typeof schema.vulnDbBuildSettings.$inferSelect
      | undefined;

  beforeAll(async () => {
    const { handleError } = await import("../lib/problem.ts");
    const { vulnDbBuildRoutes } = await import("./vulndb-build.ts");
    t = shared.db as TestDatabase;
    await t.db.insert(schema.organization).values([
      { id: ORG, name: "A" },
      { id: OTHER, name: "B" },
    ]);
    await t.db.insert(schema.user).values([
      { id: "user_vdb_a", name: "Erika", email: "erika@example.test" },
      { id: "user_vdb_b", name: "Max", email: "max@example.test" },
    ]);
    const v1 = new Hono().use("*", async (c, next) => {
      c.set(
        "actor" as never,
        {
          userId: c.req.header("x-user"),
          email: "someone@example.test",
          name: "Someone",
          organizationId: c.req.header("x-org"),
          role: c.req.header("x-role"),
          ip: c.req.header("x-ip") ?? null,
          strongAuthAt: new Date(Date.now() - Number(c.req.header("x-age") ?? 0) * 1000),
        } as never,
      );
      await next();
    });
    v1.route("/vulndb-build", vulnDbBuildRoutes as never);
    app = new Hono().onError(handleError).route("/api/v1", v1) as unknown as Hono;
  }, 60_000);

  afterAll(async () => {
    await t?.drop();
  });
  beforeEach(async () => {
    await t.db.delete(schema.vulnDbBuildSettings);
    await t.db.delete(schema.secret);
    await t.db.delete(schema.auditLog);
  });

  it("shows neither key as set at first, and only to owners and admins", async () => {
    const r = await call("GET", "/");
    expect(r.status).toBe(200);
    expect(r.json).toEqual({
      github: { configured: false, setAt: null, setBy: null },
      nvd: { configured: false, setAt: null, setBy: null },
    });
    expect((await call("GET", "/", { role: "owner" })).status).toBe(200);
    for (const role of ["member", "viewer"] as const) {
      const refused = await call("GET", "/", { role });
      expect(refused.status, role).toBe(403);
      expect(problemCode(refused)).toBe("forbidden");
    }
  });

  it("refuses members and viewers before anything is stored", async () => {
    for (const role of ["member", "viewer"] as const) {
      expect(
        (await call("PUT", "/github-token", { role, body: { token: GITHUB_TOKEN, acknowledged: true } }))
          .status,
      ).toBe(403);
      expect(
        (await call("PUT", "/nvd-api-key", { role, body: { key: NVD_KEY, acknowledged: true } })).status,
      ).toBe(403);
      expect((await call("DELETE", "/github-token", { role })).status).toBe(403);
      expect((await call("DELETE", "/nvd-api-key", { role })).status).toBe(403);
    }
    expect(await t.db.select().from(schema.secret)).toEqual([]);
    expect(await settings()).toBeUndefined();
  });

  it("needs a recent sign-in and the acknowledgement, and refuses keys of the wrong shape", async () => {
    const stale = await call("PUT", "/github-token", {
      age: STALE,
      body: { token: GITHUB_TOKEN, acknowledged: true },
    });
    expect(stale.status).toBe(403);
    expect(problemCode(stale)).toBe("step-up-required");
    expect(
      problemCode(
        await call("PUT", "/nvd-api-key", { age: STALE, body: { key: NVD_KEY, acknowledged: true } }),
      ),
    ).toBe("step-up-required");

    for (const body of [
      { token: GITHUB_TOKEN },
      { token: GITHUB_TOKEN, acknowledged: false },
      { token: "not-a-token", acknowledged: true },
      { token: NVD_KEY, acknowledged: true },
      { token: `${GITHUB_TOKEN}x`, acknowledged: true },
      { key: GITHUB_TOKEN, acknowledged: true },
    ]) {
      const r = await call("PUT", "/github-token", { body });
      expect(r.status, JSON.stringify(body)).toBe(422);
      expect(r.text).not.toContain(GITHUB_TOKEN);
    }
    for (const body of [
      { key: NVD_KEY },
      { key: "aaaaaaaabbbbccccddddeeeeeeeeeeee", acknowledged: true },
      { key: GITHUB_TOKEN, acknowledged: true },
      { token: NVD_KEY, acknowledged: true },
    ]) {
      const r = await call("PUT", "/nvd-api-key", { body });
      expect(r.status, JSON.stringify(body)).toBe(422);
    }
    expect(await t.db.select().from(schema.secret)).toEqual([]);
    expect(await t.db.select().from(schema.auditLog)).toEqual([]);
  });

  it("seals each key at once for the worker, never returns it, and audits without it", async () => {
    expect(
      (await call("PUT", "/github-token", { body: { token: ` ${GITHUB_TOKEN} `, acknowledged: true } }))
        .status,
    ).toBe(200);
    expect(
      (await call("PUT", "/nvd-api-key", { role: "owner", body: { key: NVD_KEY, acknowledged: true } }))
        .status,
    ).toBe(200);

    const view = await call("GET", "/");
    expect(view.json?.github).toMatchObject({ configured: true, setBy: "Erika" });
    expect(view.json?.nvd).toMatchObject({ configured: true, setBy: "Erika" });
    expect(Date.parse(view.json?.github.setAt)).not.toBeNaN();
    expect(view.text).not.toContain(GITHUB_TOKEN);
    expect(view.text).not.toContain(NVD_KEY);

    const row = await settings();
    expect(row).toMatchObject({
      id: "installation",
      githubOrganizationId: ORG,
      githubSetBy: "user_vdb_a",
      nvdOrganizationId: ORG,
      nvdSetBy: "user_vdb_a",
    });
    const [github] = await secrets("vulndb-github-token");
    const [nvd] = await secrets("vulndb-nvd-api-key");
    expect(github?.id).toBe(row?.githubSecretId);
    expect(nvd?.id).toBe(row?.nvdSecretId);
    expect(github?.organizationId).toBe(ORG);
    expect(JSON.stringify(github?.sealed)).not.toContain(GITHUB_TOKEN);
    expect(JSON.stringify(nvd?.sealed)).not.toContain(NVD_KEY);

    // Only the vault private key (the worker) opens it, bound to this record and purpose; surrounding blanks are gone.
    const privateKey = loadVaultPrivateKey(shared.privateKeyPem);
    expect(
      openSecret(
        github?.sealed,
        { organizationId: ORG, recordId: github?.id as string, purpose: "vulndb-github-token" },
        privateKey,
      ).toString("utf8"),
    ).toBe(GITHUB_TOKEN);
    expect(
      openSecret(
        nvd?.sealed,
        { organizationId: ORG, recordId: nvd?.id as string, purpose: "vulndb-nvd-api-key" },
        privateKey,
      ).toString("utf8"),
    ).toBe(NVD_KEY);

    const [setGithub] = await audits("vulndb.github_token_set");
    const [setNvd] = await audits("vulndb.nvd_key_set");
    expect(setGithub).toMatchObject({
      organizationId: ORG,
      actorUserId: "user_vdb_a",
      targetType: "vulndb_build",
      targetId: "installation",
      data: { host: "api.github.com" },
    });
    expect(setNvd?.data).toEqual({ host: "services.nvd.nist.gov" });
    const log = JSON.stringify(await t.db.select().from(schema.auditLog));
    expect(log).not.toContain(GITHUB_TOKEN);
    expect(log).not.toContain(NVD_KEY);
  });

  it("is installation-wide: other organisations see that a key is set, but not who set it", async () => {
    await call("PUT", "/nvd-api-key", { body: { key: NVD_KEY, acknowledged: true } });
    const other = await call("GET", "/", { org: OTHER, user: "user_vdb_b" });
    expect(other.json?.nvd).toMatchObject({ configured: true, setBy: null });
    expect(other.json?.nvd.setAt).not.toBeNull();
    expect(other.json?.github.configured).toBe(false);
  });

  it("replacing a key deletes the old secret; removing it deletes the secret and clears the columns", async () => {
    await call("PUT", "/github-token", { body: { token: GITHUB_TOKEN, acknowledged: true } });
    await call("PUT", "/nvd-api-key", { body: { key: NVD_KEY, acknowledged: true } });
    const first = (await secrets("vulndb-github-token"))[0]?.id;

    expect(
      (
        await call("PUT", "/github-token", {
          org: OTHER,
          user: "user_vdb_b",
          body: { token: GITHUB_TOKEN_2, acknowledged: true },
        })
      ).status,
    ).toBe(200);
    const replaced = await secrets("vulndb-github-token");
    expect(replaced).toHaveLength(1);
    expect(replaced[0]?.id).not.toBe(first);
    expect(replaced[0]?.organizationId).toBe(OTHER);
    expect(await settings()).toMatchObject({
      githubSecretId: replaced[0]?.id,
      githubOrganizationId: OTHER,
      githubSetBy: "user_vdb_b",
    });
    expect(await audits("vulndb.github_token_replaced")).toHaveLength(1);
    expect((await call("GET", "/", { org: OTHER, user: "user_vdb_b" })).json?.github.setBy).toBe("Max");

    await call("PUT", "/nvd-api-key", { body: { key: NVD_KEY_2, acknowledged: true } });
    expect(await secrets("vulndb-nvd-api-key")).toHaveLength(1);
    expect(await audits("vulndb.nvd_key_replaced")).toHaveLength(1);

    // Removing one key leaves the other alone.
    expect((await call("DELETE", "/github-token")).status).toBe(204);
    expect(await secrets("vulndb-github-token")).toEqual([]);
    expect(await secrets("vulndb-nvd-api-key")).toHaveLength(1);
    expect(await settings()).toMatchObject({
      githubSecretId: null,
      githubOrganizationId: null,
      githubSetBy: null,
      githubSetAt: null,
    });
    expect(await audits("vulndb.github_token_removed")).toEqual([
      expect.objectContaining({ organizationId: ORG, data: { host: "api.github.com" } }),
    ]);
    const view = await call("GET", "/");
    expect(view.json?.github).toEqual({ configured: false, setAt: null, setBy: null });
    expect(view.json?.nvd.configured).toBe(true);

    expect((await call("DELETE", "/nvd-api-key")).status).toBe(204);
    expect(await t.db.select().from(schema.secret)).toEqual([]);
    expect(await audits("vulndb.nvd_key_removed")).toHaveLength(1);

    // Removing what is not set changes nothing and writes no audit entry.
    expect((await call("DELETE", "/nvd-api-key")).status).toBe(204);
    expect(await audits("vulndb.nvd_key_removed")).toHaveLength(1);
  });

  it("forgets a key whose organisation is deleted (its secret goes with it)", async () => {
    await t.db.insert(schema.organization).values({ id: "org_vdb_gone", name: "Gone" });
    await call("PUT", "/github-token", {
      org: "org_vdb_gone",
      body: { token: GITHUB_TOKEN, acknowledged: true },
    });
    await t.db.delete(schema.organization).where(eq(schema.organization.id, "org_vdb_gone"));
    expect(await secrets("vulndb-github-token")).toEqual([]);
    expect((await call("GET", "/")).json?.github).toEqual({ configured: false, setAt: null, setBy: null });
    // Setting it again is a fresh set, not a replacement.
    await call("PUT", "/github-token", { body: { token: GITHUB_TOKEN, acknowledged: true } });
    expect(await audits("vulndb.github_token_set")).toHaveLength(2);
    expect(await audits("vulndb.github_token_replaced")).toEqual([]);
  });
});
