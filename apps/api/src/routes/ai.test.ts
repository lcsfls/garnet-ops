/**
 * The AI routes (ADR 0013) against a throw-away PostgreSQL database on the development server:
 * who may configure and ask, step-up for settings, the address rules, sealing of the API key,
 * limits and the audit log (never the prompt), the notes, and the event stream including a
 * reconnect in the middle of an answer. Sessions are replaced by a header-driven actor; the job
 * queue is a recorder; the worker's part is played by writing rows and NOTIFY, exactly what the
 * real worker does. Skipped without the development PostgreSQL.
 */
import { schema } from "@garnetops/db";
import { devDatabaseUrl, type TestDatabase } from "@garnetops/db/testing";
import { eq } from "drizzle-orm";
import { Hono } from "hono";
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";

const adminUrl = devDatabaseUrl();

const queue = vi.hoisted(() => ({
  sent: [] as { name: string; data: Record<string, unknown>; options: Record<string, unknown> }[],
  db: null as unknown,
  failSend: false,
}));

vi.mock("../db.ts", async () => {
  const { createTestDatabase: create, devDatabaseUrl: url } = await import("@garnetops/db/testing");
  const target = url();
  if (!target) return { db: null, pool: null, boss: null, QUEUES: {} };
  const t = await create(target, "api_ai");
  queue.db = t;
  return {
    db: t.db,
    pool: t.pool,
    boss: {
      send: async (name: string, data: Record<string, unknown>, options: Record<string, unknown>) => {
        if (queue.failSend) throw new Error("queue down");
        queue.sent.push({ name, data, options });
        return "job";
      },
    },
    QUEUES: { aiGenerate: "ai.generate", aiProbe: "ai.probe" },
  };
});
vi.mock("../env.ts", async () => {
  const { generateVaultKeyPair: gen, loadVaultPublicKey: load } = await import("@garnetops/core/vault");
  return {
    env: { PUBLIC_URL: "https://garnetops.example.test/" },
    isProduction: false,
    vaultPublicKey: load(gen().publicKeyPem),
  };
});
vi.mock("../auth.ts", () => ({ auth: { api: {} } }));
// Host names resolve here, so the rules can be tested without a network.
vi.mock("node:dns/promises", () => ({
  lookup: async (host: string) => {
    const table: Record<string, string[]> = {
      "llm.example.lan": ["192.168.1.20"],
      "vpn.example.lan": ["100.64.0.20"],
      "mapped.example.lan": ["::ffff:100.64.0.20"],
      "ula.example.lan": ["fd00::5"],
      "public.example.com": ["8.8.8.8"],
      "sneaky.example.lan": ["192.168.1.20", "127.0.0.1"],
    };
    const found = table[host];
    if (!found) throw Object.assign(new Error("not found"), { code: "ENOTFOUND" });
    return found.map((address) => ({ address, family: address.includes(":") ? 6 : 4 }));
  },
}));

// biome-ignore lint/suspicious/noExplicitAny: test helper for arbitrary response bodies
type Json = Record<string, any>;
type Role = "owner" | "admin" | "member" | "viewer";
const ORG = "org_a";
const OTHER = "org_b";
const STALE = 11 * 60;

describe.skipIf(!adminUrl)("AI routes", () => {
  let t: TestDatabase;
  let app: Hono;
  let counter = 0;

  async function call(
    method: string,
    path: string,
    options: { role?: Role; org?: string; age?: number; body?: unknown; user?: string } = {},
  ) {
    const headers: Record<string, string> = {
      "x-role": options.role ?? "admin",
      "x-org": options.org ?? ORG,
      "x-age": String(options.age ?? 0),
      "x-user": options.user ?? "user_a",
    };
    if (options.body !== undefined) headers["content-type"] = "application/json";
    const res = await app.request(path, {
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

  const code = (r: { json: Json | null }) =>
    String(r.json?.type ?? "")
      .split("/")
      .pop();
  const audits = async (action: string) =>
    (await t.db.select().from(schema.auditLog)).filter((a) => a.action === action);

  const GOOD = {
    enabled: true,
    baseUrl: "http://100.64.0.20:8000/v1",
    model: "qwen3-coder-30b",
    maxTokens: 1024,
    temperature: 0.2,
    timeoutSeconds: 120,
    maxConcurrent: 2,
  };
  const put = (body: Record<string, unknown>, options: Parameters<typeof call>[2] = {}) =>
    call("PUT", "/api/v1/ai/settings", { ...options, body: { ...GOOD, ...body } });

  async function configure(over: Partial<typeof schema.aiSettings.$inferInsert> = {}, org = ORG) {
    const values = {
      organizationId: org,
      baseUrl: "http://100.64.0.20:8000/v1",
      model: "qwen3-coder-30b",
      contextPolicy: "metadata" as const,
      enabled: true,
      endpointScope: "private" as const,
      ...over,
    };
    await t.db
      .insert(schema.aiSettings)
      .values(values)
      .onConflictDoUpdate({ target: schema.aiSettings.organizationId, set: values });
  }

  async function seedFinding(org = ORG) {
    const n = ++counter;
    const vulnerabilityId = `CVE-2099-${String(n).padStart(4, "0")}`;
    await t.db.insert(schema.vulnerability).values({ id: vulnerabilityId, severity: "high" });
    const repositoryId = `repo_${n}`;
    await t.db.insert(schema.repository).values({
      id: repositoryId,
      organizationId: org,
      name: `r${n}`,
      url: `https://git.example.test/r${n}.git`,
      authKind: "none",
    });
    const id = `fnd_${n}`;
    await t.db.insert(schema.finding).values({
      id,
      organizationId: org,
      repositoryId,
      vulnerabilityId,
      dedupKey: `${repositoryId}|${vulnerabilityId}`,
      packageName: "lodash",
      packageVersion: "4.17.20",
      packageType: "npm",
      severity: "high",
      severityRank: 4,
      state: "open",
      firstSeenScanId: "scan_x",
      lastSeenScanId: "scan_x",
      firstSeenAt: new Date(),
      lastSeenAt: new Date(),
    });
    return id;
  }

  /** A thread with messages as the worker would leave them. */
  async function seedThread(
    findingId: string,
    messages: Partial<typeof schema.chatMessage.$inferInsert>[],
    org = ORG,
  ) {
    const id = `thr_${String(++counter).padStart(20, "0")}`;
    await t.db.insert(schema.chatThread).values({ id, organizationId: org, findingId, createdBy: "user_a" });
    const ids: string[] = [];
    for (const m of messages) {
      const mid = `msg_${++counter}`;
      ids.push(mid);
      await t.db.insert(schema.chatMessage).values({
        id: mid,
        threadId: id,
        role: "assistant",
        kind: "chat",
        content: "",
        status: "complete",
        createdBy: "user_a",
        ...m,
      });
    }
    return { id, ids };
  }

  beforeAll(async () => {
    const { handleError } = await import("../lib/problem.ts");
    const { aiRoutes } = await import("./ai.ts");
    const { findingRoutes } = await import("./findings.ts");
    t = queue.db as TestDatabase;
    await t.db.insert(schema.organization).values([
      { id: ORG, name: "A" },
      { id: OTHER, name: "B" },
    ]);
    for (const [id, name] of [
      ["user_a", "Erika"],
      ["user_b", "Bruno"],
      ["user_c", "Carla"],
    ] as const) {
      await t.db.insert(schema.user).values({ id, name, email: `${id}@example.test` });
    }
    const v1 = new Hono().use("*", async (c, next) => {
      c.set(
        "actor" as never,
        {
          userId: c.req.header("x-user"),
          email: "x@example.test",
          name: "Erika",
          organizationId: c.req.header("x-org"),
          role: c.req.header("x-role"),
          ip: "198.51.100.7",
          strongAuthAt: new Date(Date.now() - Number(c.req.header("x-age") ?? 0) * 1000),
        } as never,
      );
      await next();
    });
    v1.route("/ai", aiRoutes as never);
    v1.route("/findings", findingRoutes as never);
    app = new Hono().onError(handleError).route("/api/v1", v1) as unknown as Hono;
  }, 60_000);

  afterAll(async () => {
    const { aiBus } = await import("../lib/ai-bus.ts");
    await aiBus.close();
    await t?.drop();
  });

  beforeEach(async () => {
    queue.sent.length = 0;
    queue.failSend = false;
    await t.pool.query(
      "truncate rate_limit, audit_log, ai_probe, finding_note, chat_message, chat_thread, ai_settings restart identity",
    );
    await t.pool.query("delete from secret");
  });

  describe("settings", () => {
    it("are for owners and admins only, and a change needs a recent sign-in", async () => {
      for (const role of ["viewer", "member"] as Role[]) {
        expect((await call("GET", "/api/v1/ai/settings", { role })).status, role).toBe(403);
        expect((await put({}, { role })).status, role).toBe(403);
        expect(
          (await call("POST", "/api/v1/ai/probe", { role, body: { kind: "models", baseUrl: GOOD.baseUrl } }))
            .status,
          role,
        ).toBe(403);
        expect((await call("DELETE", "/api/v1/ai/settings", { role })).status, role).toBe(403);
      }
      const stale = await put({}, { age: STALE });
      expect(stale.status).toBe(403);
      expect(code(stale)).toBe("step-up-required");
      expect((await call("DELETE", "/api/v1/ai/settings", { age: STALE })).status).toBe(403);
      expect(
        (
          await call("POST", "/api/v1/ai/probe", {
            age: STALE,
            body: { kind: "models", baseUrl: GOOD.baseUrl },
          })
        ).status,
      ).toBe(403);
      expect(
        await t.db.select().from(schema.aiSettings).where(eq(schema.aiSettings.organizationId, ORG)),
      ).toHaveLength(0);
    });

    it("start empty and store a configuration that sends nothing until it is switched on", async () => {
      expect((await call("GET", "/api/v1/ai/settings")).json).toEqual({ configured: false });
      const saved = await put({ enabled: false, apiKey: ["sk-test-", "0123456789abcdef"].join("") });
      expect(saved.status).toBe(200);
      expect(saved.json).toMatchObject({
        configured: true,
        enabled: false,
        baseUrl: "http://100.64.0.20:8000/v1",
        model: "qwen3-coder-30b",
        hasApiKey: true,
        scope: "private",
        insecureTransport: true,
      });
      expect(JSON.stringify(saved.json)).not.toContain("0123456789abcdef");
      expect((await call("GET", `/api/v1/ai/findings/${await seedFinding()}/thread`)).json).toMatchObject({
        state: "disabled",
        canAsk: false,
      });
    });

    it("seal the API key, never return it, and never write it to the audit log", async () => {
      await put({ apiKey: ["sk-test-", "0123456789abcdef"].join("") });
      const [settings] = await t.db
        .select()
        .from(schema.aiSettings)
        .where(eq(schema.aiSettings.organizationId, ORG));
      const [secret] = await t.db
        .select()
        .from(schema.secret)
        .where(eq(schema.secret.id, settings?.apiKeySecretId as string));
      expect(secret).toMatchObject({ purpose: "ai-api-key", organizationId: ORG });
      expect(JSON.stringify(secret?.sealed)).not.toContain("0123456789abcdef");
      expect(JSON.stringify(settings)).not.toContain("0123456789abcdef");
      expect(JSON.stringify(await t.db.select().from(schema.auditLog))).not.toContain("0123456789abcdef");
      const entry = (await audits("ai.settings_changed")).at(-1);
      expect(entry?.data).toMatchObject({
        host: "100.64.0.20:8000",
        scope: "private",
        scheme: "http",
        apiKey: "set",
        model: "qwen3-coder-30b",
      });
    });

    it("replace and remove the key without leaving old secrets behind", async () => {
      await put({ apiKey: "first-key-value" });
      const first = (await t.db.select().from(schema.aiSettings))[0]?.apiKeySecretId;
      await put({ apiKey: "second-key-value" });
      const second = (await t.db.select().from(schema.aiSettings))[0]?.apiKeySecretId;
      expect(second).not.toBe(first);
      expect(
        await t.db
          .select()
          .from(schema.secret)
          .where(eq(schema.secret.id, first as string)),
      ).toHaveLength(0);
      // Saving without a key keeps the stored one.
      await put({ maxTokens: 2048 });
      expect((await t.db.select().from(schema.aiSettings))[0]?.apiKeySecretId).toBe(second);
      const removed = await put({ clearApiKey: true });
      expect(removed.json).toMatchObject({ hasApiKey: false });
      expect(
        await t.db
          .select()
          .from(schema.secret)
          .where(eq(schema.secret.id, second as string)),
      ).toHaveLength(0);
      expect((await audits("ai.settings_changed")).map((a) => (a.data as Json).apiKey)).toEqual(
        expect.arrayContaining(["set", "unchanged", "removed"]),
      );
    });

    it("refuse addresses that can never be right", async () => {
      for (const baseUrl of [
        "http://localhost:11434/v1",
        "http://127.0.0.1:8000/v1",
        "http://[::1]:8000/v1",
        "http://[::ffff:7f00:1]/v1",
        "http://169.254.169.254/latest/meta-data",
        "http://0.0.0.0/v1",
        "http://224.0.0.1/v1",
        "http://user:secret@192.168.1.20/v1",
        "http://192.168.1.20/v1?token=abc",
        "ftp://192.168.1.20/v1",
        "not a url",
        "http://sneaky.example.lan/v1",
      ]) {
        const r = await put({ baseUrl });
        expect(r.status, baseUrl).toBe(422);
        expect(r.json?.errors?.[0]?.path, baseUrl).toBe("baseUrl");
      }
      expect(await t.db.select().from(schema.aiSettings)).toHaveLength(0);
    });

    it("allow plain http only inside a VPN overlay, by address or by name", async () => {
      expect((await put({ baseUrl: "http://vpn.example.lan:8000/v1/" })).json).toMatchObject({
        baseUrl: "http://vpn.example.lan:8000/v1",
        scope: "private",
      });
      expect((await put({ baseUrl: "http://100.64.1.2:8000/v1" })).json).toMatchObject({ scope: "private" });
      expect((await put({ baseUrl: "http://[::ffff:100.64.1.2]:8000/v1" })).json).toMatchObject({
        scope: "private",
      });
      expect((await put({ baseUrl: "http://mapped.example.lan/v1" })).json).toMatchObject({
        scope: "private",
      });
    });

    it("allow private addresses over https", async () => {
      expect((await put({ baseUrl: "https://llm.example.lan/v1" })).json).toMatchObject({
        scope: "private",
        insecureTransport: false,
      });
      expect((await put({ baseUrl: "https://[fd00::5]:1234/v1" })).json).toMatchObject({ scope: "private" });
      expect((await put({ baseUrl: "https://192.168.1.20/v1" })).json).toMatchObject({ scope: "private" });
    });

    it("leave plain http to another private address to the worker, which knows its own networks", async () => {
      // The API cannot tell whether the address is a service on the worker's Docker network.
      for (const baseUrl of [
        "http://192.168.1.20:8000/v1",
        "http://llm.example.lan:8000/v1",
        "http://[fd00::5]:1234/v1",
        "http://ula.example.lan/v1",
      ]) {
        const r = await put({ baseUrl });
        expect(r.status, baseUrl).toBe(200);
        expect(r.json, baseUrl).toMatchObject({ scope: "unknown", insecureTransport: true });
      }
      const [row] = await t.db.select().from(schema.aiSettings);
      expect(row).toMatchObject({ endpointScope: "unknown", externalAckHost: null });
      const probe = await call("POST", "/api/v1/ai/probe", {
        body: { kind: "models", baseUrl: "http://192.168.1.20:8000/v1" },
      });
      expect(probe.status).toBe(202);
      const [stored] = await t.db.select().from(schema.aiProbe).where(eq(schema.aiProbe.id, probe.json?.id));
      expect(stored).toMatchObject({ ackHost: null });
      expect((await audits("ai.endpoint_tested")).at(-1)?.data).toMatchObject({ scope: "unknown" });
      // A public address with http stays refused here: that does not depend on the worker's networks.
      expect((await put({ baseUrl: "http://public.example.com/v1" })).status).toBe(422);
    });

    it("keep a name this server cannot resolve as not checked yet; the worker decides on every connection", async () => {
      const r = await put({ baseUrl: "http://nowhere.example.lan/v1" });
      expect(r.status).toBe(200);
      expect(r.json).toMatchObject({ scope: "unknown", externalAcknowledged: false });
      // An explicit confirmation is kept for that host, in case it turns out to be outside the network.
      const confirmed = await put({ baseUrl: "https://nowhere.example.lan/v1", acknowledgeExternal: true });
      expect(confirmed.json).toMatchObject({ scope: "unknown", externalAcknowledged: true });
      expect((await audits("ai.external_acknowledged"))[0]?.data).toEqual({ host: "nowhere.example.lan" });
      const probe = await call("POST", "/api/v1/ai/probe", {
        body: { kind: "models", baseUrl: "https://nowhere.example.lan/v1" },
      });
      const [row] = await t.db.select().from(schema.aiProbe).where(eq(schema.aiProbe.id, probe.json?.id));
      expect(row?.ackHost).toBe("nowhere.example.lan");
    });

    it("need https and an explicit acknowledgement for an address outside the network, per host", async () => {
      const http = await put({ baseUrl: "http://public.example.com/v1", acknowledgeExternal: true });
      expect(http.status).toBe(422);
      expect(http.json?.errors?.[0]?.path).toBe("baseUrl");
      const open = await put({ baseUrl: "https://public.example.com/v1" });
      expect(open.status).toBe(422);
      expect(code(open)).toBe("external-not-acknowledged");
      expect(open.json?.host).toBe("public.example.com");
      expect(await audits("ai.external_acknowledged")).toHaveLength(0);

      const ok = await put({ baseUrl: "https://public.example.com/v1", acknowledgeExternal: true });
      expect(ok.status).toBe(200);
      expect(ok.json).toMatchObject({
        scope: "external",
        externalAcknowledged: true,
        insecureTransport: false,
      });
      expect((await audits("ai.external_acknowledged"))[0]?.data).toEqual({ host: "public.example.com" });
      // Saving again for the same host needs no new acknowledgement and is not logged twice.
      expect((await put({ baseUrl: "https://public.example.com/v1", maxTokens: 512 })).status).toBe(200);
      expect(await audits("ai.external_acknowledged")).toHaveLength(1);
      // Another host asks again.
      expect(code(await put({ baseUrl: "https://8.8.4.4/v1" }))).toBe("external-not-acknowledged");
      // Moving back into the network forgets the acknowledgement.
      await put({ baseUrl: "https://llm.example.lan/v1" });
      const [row] = await t.db.select().from(schema.aiSettings);
      expect(row).toMatchObject({ endpointScope: "private", externalAckHost: null, externalAckBy: null });
    });

    it("keep their limits within bounds", async () => {
      for (const bad of [
        { maxTokens: 10 },
        { maxTokens: 100000 },
        { temperature: 5 },
        { timeoutSeconds: 1 },
        { timeoutSeconds: 9999 },
        { maxConcurrent: 0 },
        { maxConcurrent: 99 },
        { model: "bad\nname" },
        { model: "" },
      ]) {
        expect((await put(bad)).status, JSON.stringify(bad)).toBe(422);
      }
    });

    it("can be deleted together with their key", async () => {
      await put({ apiKey: "key-to-delete" });
      const id = (await t.db.select().from(schema.aiSettings))[0]?.apiKeySecretId as string;
      expect((await call("DELETE", "/api/v1/ai/settings")).status).toBe(204);
      expect(await t.db.select().from(schema.aiSettings)).toHaveLength(0);
      expect(await t.db.select().from(schema.secret).where(eq(schema.secret.id, id))).toHaveLength(0);
      expect(await audits("ai.settings_deleted")).toHaveLength(1);
    });
  });

  describe("probes", () => {
    it("queue a job for the worker, seal a typed key for it, and are audited without the key", async () => {
      const r = await call("POST", "/api/v1/ai/probe", {
        body: { kind: "models", baseUrl: "http://100.64.0.20:8000/v1/", apiKey: "typed-key-123456" },
      });
      expect(r.status).toBe(202);
      const id = r.json?.id as string;
      expect(queue.sent).toEqual([
        { name: "ai.probe", data: { probeId: id }, options: expect.objectContaining({ retryLimit: 0 }) },
      ]);
      const [probe] = await t.db.select().from(schema.aiProbe).where(eq(schema.aiProbe.id, id));
      expect(probe).toMatchObject({
        kind: "models",
        baseUrl: "http://100.64.0.20:8000/v1",
        tempSecret: true,
        status: "pending",
      });
      const [secret] = await t.db
        .select()
        .from(schema.secret)
        .where(eq(schema.secret.id, probe?.secretId as string));
      expect(secret?.purpose).toBe("ai-api-key");
      expect(JSON.stringify(await t.db.select().from(schema.auditLog))).not.toContain("typed-key-123456");
      expect((await audits("ai.endpoint_tested")).at(-1)?.data).toEqual({
        kind: "models",
        host: "100.64.0.20:8000",
        scope: "private",
      });
    });

    it("use the stored key when asked, apply the address rules, and return the worker's result to their own organisation only", async () => {
      await put({ apiKey: "stored-key-123456" });
      const stored = (await t.db.select().from(schema.aiSettings))[0]?.apiKeySecretId;
      const r = await call("POST", "/api/v1/ai/probe", {
        body: { kind: "test", model: "m", baseUrl: GOOD.baseUrl, useStoredKey: true },
      });
      const [probe] = await t.db.select().from(schema.aiProbe).where(eq(schema.aiProbe.id, r.json?.id));
      expect(probe).toMatchObject({ secretId: stored, tempSecret: false });
      expect(
        (
          await call("POST", "/api/v1/ai/probe", {
            body: { kind: "models", baseUrl: "http://169.254.169.254/v1" },
          })
        ).status,
      ).toBe(422);
      expect(
        (await call("POST", "/api/v1/ai/probe", { body: { kind: "test", baseUrl: GOOD.baseUrl } })).status,
      ).toBe(422);
      expect(
        code(
          await call("POST", "/api/v1/ai/probe", {
            body: { kind: "models", baseUrl: "https://public.example.com/v1" },
          }),
        ),
      ).toBe("external-not-acknowledged");

      await t.db
        .update(schema.aiProbe)
        .set({ status: "done", result: { ok: true, models: ["a"] } })
        .where(eq(schema.aiProbe.id, probe?.id as string));
      expect((await call("GET", `/api/v1/ai/probe/${probe?.id}`)).json).toEqual({
        status: "done",
        kind: "test",
        result: { ok: true, models: ["a"] },
      });
      expect((await call("GET", `/api/v1/ai/probe/${probe?.id}`, { org: OTHER })).status).toBe(404);
    });

    it("are rate limited", async () => {
      let last = 0;
      for (let i = 0; i < 12; i++)
        last = (await call("POST", "/api/v1/ai/probe", { body: { kind: "models", baseUrl: GOOD.baseUrl } }))
          .status;
      expect(last).toBe(429);
    });
  });

  describe("asking", () => {
    it("shows every member whether and how the model can be used, and lets viewers read only", async () => {
      const finding = await seedFinding();
      const path = `/api/v1/ai/findings/${finding}/thread`;
      for (const role of ["viewer", "member"] as Role[]) {
        expect((await call("GET", path, { role })).json).toMatchObject({
          state: "not-configured",
          canAsk: false,
          threadId: null,
          messages: [],
        });
      }
      await configure();
      expect((await call("GET", path, { role: "member" })).json).toMatchObject({
        state: "ready",
        model: "qwen3-coder-30b",
        scope: "private",
        insecureTransport: true,
        canAsk: true,
      });
      expect((await call("GET", path, { role: "viewer" })).json).toMatchObject({
        state: "ready",
        canAsk: false,
      });
      expect(JSON.stringify((await call("GET", path)).json)).not.toContain("100.64.0.20");
      expect((await call("GET", path, { org: OTHER })).status).toBe(404);
    });

    it("starts a triage once, queues it for the worker and audits finding and model but not the prompt", async () => {
      await configure();
      const finding = await seedFinding();
      expect(
        (await call("POST", `/api/v1/ai/findings/${finding}/triage`, { role: "viewer", body: {} })).status,
      ).toBe(403);
      const r = await call("POST", `/api/v1/ai/findings/${finding}/triage`, {
        role: "member",
        body: { language: "de" },
      });
      expect(r.status).toBe(202);
      const messageId = r.json?.messageId as string;
      const [message] = await t.db
        .select()
        .from(schema.chatMessage)
        .where(eq(schema.chatMessage.id, messageId));
      expect(message).toMatchObject({
        role: "assistant",
        kind: "triage",
        status: "pending",
        content: "",
        context: { language: "de" },
        createdBy: "user_a",
      });
      expect(queue.sent).toEqual([
        { name: "ai.generate", data: { messageId }, options: expect.objectContaining({ retryLimit: 0 }) },
      ]);
      const entry = (await audits("ai.request")).at(-1);
      expect(entry).toMatchObject({ actorUserId: "user_a", targetType: "finding", targetId: finding });
      expect(entry?.data).toEqual({
        findingId: finding,
        model: "qwen3-coder-30b",
        kind: "triage",
        messageId,
      });

      // Asking again changes nothing and queues nothing.
      const again = await call("POST", `/api/v1/ai/findings/${finding}/triage`, { body: {} });
      expect(again.json).toMatchObject({ threadId: r.json?.threadId, messageId, queued: false });
      expect(queue.sent).toHaveLength(1);
      expect(
        await t.db.select().from(schema.chatThread).where(eq(schema.chatThread.findingId, finding)),
      ).toHaveLength(1);
    });

    it("refuses to ask when it is not set up, and for findings of another organisation", async () => {
      const finding = await seedFinding();
      const r = await call("POST", `/api/v1/ai/findings/${finding}/triage`, { body: {} });
      expect(r.status).toBe(409);
      expect(code(r)).toBe("ai-not-ready");
      expect(r.json?.state).toBe("not-configured");
      await configure({ enabled: false });
      expect((await call("POST", `/api/v1/ai/findings/${finding}/triage`, { body: {} })).json?.state).toBe(
        "disabled",
      );
      await configure();
      expect(
        (await call("POST", `/api/v1/ai/findings/${finding}/triage`, { org: OTHER, body: {} })).status,
      ).toBe(404);
      expect(queue.sent).toHaveLength(0);
    });

    it("limits requests per person and per organisation, and generations that run at once", async () => {
      await configure({ maxConcurrent: 2 });
      // Per person: 12 a minute.
      const finding = await seedFinding();
      const thread = await seedThread(finding, [
        { role: "assistant", kind: "triage", status: "complete", content: "{}" },
      ]);
      const statuses: number[] = [];
      for (let i = 0; i < 13; i++) {
        const r = await call("POST", `/api/v1/ai/threads/${thread.id}/messages`, {
          user: "user_b",
          body: { content: `Q${i}` },
        });
        statuses.push(r.status);
        if (r.status === 202)
          await t.db
            .update(schema.chatMessage)
            .set({ status: "complete" })
            .where(eq(schema.chatMessage.id, r.json?.messageId));
      }
      expect(statuses.slice(0, 12).every((s) => s === 202)).toBe(true);
      expect(statuses[12]).toBe(429);
      // Another person is not affected.
      expect(
        (
          await call("POST", `/api/v1/ai/threads/${thread.id}/messages`, {
            user: "user_c",
            body: { content: "Q" },
          })
        ).status,
      ).toBe(202);

      // Concurrency: two running generations in the organisation fill the slots.
      await t.pool.query("delete from rate_limit");
      await t.pool.query("update chat_message set status = 'complete'");
      const other = await seedFinding();
      const busy = await seedThread(other, [{ status: "streaming" }, { status: "pending" }]);
      const target = await seedFinding();
      const r = await call("POST", `/api/v1/ai/findings/${target}/triage`, { body: {} });
      expect(r.status).toBe(429);
      expect(code(r)).toBe("ai-busy");
      expect(busy.ids).toHaveLength(2);
      // A stuck generation older than its timeout does not block for ever.
      await t.pool.query(
        "update chat_message set created_at = now() - interval '1 hour' where status in ('pending', 'streaming')",
      );
      expect((await call("POST", `/api/v1/ai/findings/${target}/triage`, { body: {} })).status).toBe(202);
    });

    it("limits the whole organisation per minute", async () => {
      await configure({ maxConcurrent: 8 });
      const finding = await seedFinding();
      const thread = await seedThread(finding, [{ status: "complete", content: "{}" }]);
      let limited = 0;
      for (let i = 0; i < 45; i++) {
        const user = ["user_a", "user_b", "user_c"][i % 3] as string;
        const r = await call("POST", `/api/v1/ai/threads/${thread.id}/messages`, {
          user,
          body: { content: `Q${i}` },
        });
        if (r.status === 202)
          await t.db
            .update(schema.chatMessage)
            .set({ status: "complete" })
            .where(eq(schema.chatMessage.id, r.json?.messageId));
        if (r.status === 429) limited++;
      }
      expect(limited).toBeGreaterThan(0);
    });

    it("takes a follow-up question as a user message and a pending answer, one at a time", async () => {
      await configure();
      const finding = await seedFinding();
      const thread = await seedThread(finding, [
        { role: "assistant", kind: "triage", status: "complete", content: "{}" },
      ]);
      const path = `/api/v1/ai/threads/${thread.id}/messages`;
      expect((await call("POST", path, { role: "viewer", body: { content: "Q" } })).status).toBe(403);
      expect((await call("POST", path, { body: { content: "" } })).status).toBe(422);
      expect((await call("POST", path, { body: { content: "x".repeat(2001) } })).status).toBe(422);
      expect((await call("POST", path, { org: OTHER, body: { content: "Q" } })).status).toBe(404);
      const r = await call("POST", path, {
        user: "user_b",
        body: { content: "Does the update break anything?", language: "de" },
      });
      expect(r.status).toBe(202);
      const rows = await t.db
        .select()
        .from(schema.chatMessage)
        .where(eq(schema.chatMessage.threadId, thread.id))
        .orderBy(schema.chatMessage.seq);
      expect(rows.map((m) => [m.role, m.kind, m.status, m.createdBy])).toEqual([
        ["assistant", "triage", "complete", "user_a"],
        ["user", "chat", "complete", "user_b"],
        ["assistant", "chat", "pending", "user_b"],
      ]);
      expect(rows[1]?.content).toBe("Does the update break anything?");
      expect(queue.sent[0]).toMatchObject({ name: "ai.generate", data: { messageId: r.json?.messageId } });
      const busy = await call("POST", path, { body: { content: "And another?" } });
      expect(busy.status).toBe(409);
      expect(code(busy)).toBe("ai-thread-busy");
      // The thread shows who asked, by name, never by email.
      const shown = await call("GET", `/api/v1/ai/findings/${finding}/thread`);
      expect(shown.json?.messages.map((m: Json) => [m.role, m.author])).toEqual([
        ["assistant", null],
        ["user", "Bruno"],
        ["assistant", null],
      ]);
      expect(JSON.stringify(shown.json)).not.toContain("example.test");
      expect(shown.json?.messages[0]).not.toHaveProperty("context");
    });

    it("marks the answer failed when the queue is down", async () => {
      await configure();
      const finding = await seedFinding();
      queue.failSend = true;
      const r = await call("POST", `/api/v1/ai/findings/${finding}/triage`, { body: {} });
      expect(r.status).toBe(500);
      const [row] = await t.db.select().from(schema.chatMessage).where(eq(schema.chatMessage.kind, "triage"));
      expect(row).toMatchObject({ status: "failed", error: "internal" });
    });

    it("stops a pending or running answer, once", async () => {
      await configure();
      const finding = await seedFinding();
      const thread = await seedThread(finding, [
        { status: "streaming", content: "Hel" },
        { status: "complete" },
      ]);
      const [running, done] = thread.ids as [string, string];
      expect((await call("POST", `/api/v1/ai/messages/${running}/stop`, { role: "viewer" })).status).toBe(
        403,
      );
      expect((await call("POST", `/api/v1/ai/messages/${running}/stop`, { org: OTHER })).status).toBe(404);
      expect((await call("POST", `/api/v1/ai/messages/${running}/stop`)).status).toBe(204);
      expect(
        (await t.db.select().from(schema.chatMessage).where(eq(schema.chatMessage.id, running)))[0],
      ).toMatchObject({ status: "stopped", content: "Hel" });
      expect((await call("POST", `/api/v1/ai/messages/${done}/stop`)).status).toBe(204);
      expect(
        (await t.db.select().from(schema.chatMessage).where(eq(schema.chatMessage.id, done)))[0]?.status,
      ).toBe("complete");
      expect(await audits("ai.stopped")).toHaveLength(1);
    });

    it("regenerates only the last answer, replacing it", async () => {
      await configure();
      const finding = await seedFinding();
      const thread = await seedThread(finding, [
        { role: "assistant", kind: "triage", status: "complete", content: "{}" },
        { role: "user", content: "Q" },
        { role: "assistant", status: "failed", error: "timeout", content: "part" },
      ]);
      const [triage, , last] = thread.ids as [string, string, string];
      expect((await call("POST", `/api/v1/ai/messages/${triage}/regenerate`, { body: {} })).status).toBe(409);
      expect(
        (await call("POST", `/api/v1/ai/messages/${last}/regenerate`, { role: "viewer", body: {} })).status,
      ).toBe(403);
      const r = await call("POST", `/api/v1/ai/messages/${last}/regenerate`, { body: { language: "de" } });
      expect(r.status).toBe(202);
      const rows = await t.db
        .select()
        .from(schema.chatMessage)
        .where(eq(schema.chatMessage.threadId, thread.id))
        .orderBy(schema.chatMessage.seq);
      expect(rows.map((m) => [m.role, m.status])).toEqual([
        ["assistant", "complete"],
        ["user", "complete"],
        ["assistant", "pending"],
      ]);
      expect(rows[2]?.id).toBe(r.json?.messageId);
      expect(rows.some((m) => m.id === last)).toBe(false);
      expect((await audits("ai.request")).at(-1)?.data).toMatchObject({ kind: "regenerate" });
      // Not while an answer is being written.
      expect(
        (await call("POST", `/api/v1/ai/messages/${r.json?.messageId}/regenerate`, { body: {} })).status,
      ).toBe(409);
    });

    it("shows what the model saw", async () => {
      await configure();
      const finding = await seedFinding();
      const thread = await seedThread(finding, [
        {
          role: "assistant",
          kind: "triage",
          status: "complete",
          content: "{}",
          context: { prompt: "THE PROMPT", language: "en" },
        },
        { role: "assistant", status: "complete", context: { language: "en" } },
      ]);
      const [triage, chat] = thread.ids as [string, string];
      for (const id of [triage, chat]) {
        const r = await call("GET", `/api/v1/ai/messages/${id}/context`, { role: "viewer" });
        expect(r.json).toMatchObject({ prompt: "THE PROMPT" });
        expect(r.json?.system).toContain("You cannot change anything");
      }
      expect((await call("GET", `/api/v1/ai/messages/${triage}/context`, { org: OTHER })).status).toBe(404);
    });
  });

  describe("notes", () => {
    it("a human takes over a suggestion as a note; nothing else changes", async () => {
      await configure();
      const finding = await seedFinding();
      const structured = {
        exploitability: "likely",
        reachable: "yes",
        confidence: "high",
        summary: "It is reachable.",
        recommendation: "Update.",
        upgradeTo: "4.17.21",
        references: [],
      };
      const thread = await seedThread(finding, [
        {
          role: "assistant",
          kind: "triage",
          status: "complete",
          content: JSON.stringify(structured),
          structured,
        },
        { role: "assistant", status: "streaming", content: "x" },
      ]);
      const [triage, running] = thread.ids as [string, string];
      const before = await t.db.select().from(schema.finding).where(eq(schema.finding.id, finding));
      expect(
        (await call("POST", `/api/v1/ai/messages/${triage}/accept-note`, { role: "viewer" })).status,
      ).toBe(403);
      expect((await call("POST", `/api/v1/ai/messages/${running}/accept-note`)).status).toBe(409);
      expect((await call("POST", `/api/v1/ai/messages/${triage}/accept-note`, { org: OTHER })).status).toBe(
        404,
      );
      const r = await call("POST", `/api/v1/ai/messages/${triage}/accept-note`, {
        role: "member",
        user: "user_b",
      });
      expect(r.status).toBe(201);
      const again = await call("POST", `/api/v1/ai/messages/${triage}/accept-note`);
      expect(again.status).toBe(409);
      expect(code(again)).toBe("already-noted");

      const notes = await call("GET", `/api/v1/findings/${finding}/notes`, { role: "viewer" });
      expect(notes.json).toEqual([
        expect.objectContaining({
          body: "It is reachable.\n\nUpdate.",
          source: "ai",
          author: "Bruno",
          meta: { exploitability: "likely", reachable: "yes", confidence: "high", upgradeTo: "4.17.21" },
        }),
      ]);
      expect((await call("GET", `/api/v1/findings/${finding}/notes`, { org: OTHER })).status).toBe(404);
      expect((await audits("ai.note_accepted"))[0]).toMatchObject({
        actorUserId: "user_b",
        targetId: finding,
      });
      expect(await t.db.select().from(schema.finding).where(eq(schema.finding.id, finding))).toEqual(before);
      expect((await call("GET", `/api/v1/ai/findings/${finding}/thread`)).json?.messages[0]).toMatchObject({
        noted: true,
      });
    });

    it("takes over a plain-text answer as text", async () => {
      const finding = await seedFinding();
      const thread = await seedThread(finding, [
        { role: "assistant", status: "complete", content: "<b>Plain</b> answer" },
      ]);
      expect((await call("POST", `/api/v1/ai/messages/${thread.ids[0]}/accept-note`)).status).toBe(201);
      expect((await call("GET", `/api/v1/findings/${finding}/notes`)).json?.[0]).toMatchObject({
        body: "<b>Plain</b> answer",
        meta: null,
      });
    });
  });

  describe("event stream", () => {
    /** Reads server-sent events from a response as they come. */
    function reader(res: Response) {
      const decoder = new TextDecoder();
      const body = (res.body as ReadableStream<Uint8Array>).getReader();
      let buffer = "";
      return {
        async next(timeout = 3000): Promise<{ event: string; data: Json } | null> {
          const deadline = Date.now() + timeout;
          for (;;) {
            const end = buffer.indexOf("\n\n");
            if (end >= 0) {
              const block = buffer.slice(0, end);
              buffer = buffer.slice(end + 2);
              if (block.startsWith(":")) continue;
              const event = /^event: (.*)$/m.exec(block)?.[1] ?? "message";
              const data = /^data: (.*)$/m.exec(block)?.[1];
              return { event, data: data ? JSON.parse(data) : {} };
            }
            const left = deadline - Date.now();
            if (left <= 0) return null;
            const chunk = await Promise.race([
              body.read(),
              new Promise<null>((r) => setTimeout(() => r(null), left)),
            ]);
            if (chunk === null) return null;
            if (chunk.done) return null;
            buffer += decoder.decode(chunk.value, { stream: true });
          }
        },
        cancel: () => body.cancel().catch(() => {}),
      };
    }
    const open = (threadId: string, options: { org?: string; user?: string } = {}) =>
      app.request(`/api/v1/ai/threads/${threadId}/stream`, {
        headers: {
          "x-role": "viewer",
          "x-org": options.org ?? ORG,
          "x-age": "0",
          "x-user": options.user ?? "user_a",
        },
      });
    /** What the worker does for one step: append, and announce in the same statement. */
    const workerWrites = (threadId: string, messageId: string, text: string) =>
      t.pool.query(
        `with u as (update chat_message set content = content || $2::text where id = $1 returning id, octet_length(content) as len)
         select pg_notify($3, json_build_object('e', 'delta', 'm', id, 'from', len - $4::int, 'd', $2::text)::text) from u`,
        [messageId, text, `ai_${threadId}`, Buffer.byteLength(text)],
      );
    const workerFinishes = async (threadId: string, messageId: string, status = "complete") => {
      await t.pool.query("update chat_message set status = $2 where id = $1", [messageId, status]);
      await t.pool.query("select pg_notify($1, json_build_object('e', 'state', 'm', $2::text)::text)", [
        `ai_${threadId}`,
        messageId,
      ]);
    };

    it("is for members of the organisation only", async () => {
      const finding = await seedFinding();
      const thread = await seedThread(finding, [{ status: "streaming" }]);
      expect((await open(thread.id, { org: OTHER })).status).toBe(404);
      expect((await open("thr_00000000000000000000")).status).toBe(404);
      expect((await open('thr_x"; drop table x;--')).status).toBe(404);
      const res = await open(thread.id);
      expect(res.status).toBe(200);
      expect(res.headers.get("content-type")).toContain("text/event-stream");
      expect(res.headers.get("cache-control")).toContain("no-store");
      await reader(res).cancel();
    });

    it("sends a snapshot first, then the text as the worker writes it, then the final message and done", async () => {
      const finding = await seedFinding();
      const thread = await seedThread(finding, [{ status: "streaming" }]);
      const id = thread.ids[0] as string;
      const stream = reader(await open(thread.id));
      const snapshot = await stream.next();
      expect(snapshot?.event).toBe("snapshot");
      expect(snapshot?.data.messages).toHaveLength(1);
      expect(snapshot?.data.messages[0]).toMatchObject({ id, status: "streaming", content: "" });

      await workerWrites(thread.id, id, "Hello ");
      await workerWrites(thread.id, id, "wörld 😀");
      expect(await stream.next()).toEqual({ event: "delta", data: { id, from: 0, text: "Hello " } });
      expect(await stream.next()).toEqual({ event: "delta", data: { id, from: 6, text: "wörld 😀" } });

      await workerFinishes(thread.id, id);
      const final = await stream.next();
      expect(final?.event).toBe("message");
      expect(final?.data).toMatchObject({ id, status: "complete", content: "Hello wörld 😀" });
      expect((await stream.next())?.event).toBe("done");
      expect(await stream.next()).toBeNull(); // the server ended the stream
    });

    it("resumes from the stored text when a client reconnects in the middle of an answer", async () => {
      const finding = await seedFinding();
      const thread = await seedThread(finding, [{ status: "streaming" }]);
      const id = thread.ids[0] as string;
      const first = reader(await open(thread.id));
      await first.next();
      await workerWrites(thread.id, id, "Hello ");
      expect((await first.next())?.event).toBe("delta");
      await first.cancel(); // the connection drops
      await workerWrites(thread.id, id, "while you were away, ");

      const second = reader(await open(thread.id));
      const snapshot = await second.next();
      expect(snapshot?.event).toBe("snapshot");
      expect(snapshot?.data.messages[0]).toMatchObject({
        status: "streaming",
        content: "Hello while you were away, ",
      });
      await workerWrites(thread.id, id, "and now more.");
      expect(await second.next()).toEqual({ event: "delta", data: { id, from: 27, text: "and now more." } });
      await workerFinishes(thread.id, id);
      expect((await second.next())?.data).toMatchObject({
        status: "complete",
        content: "Hello while you were away, and now more.",
      });
    });

    it("ignores notices a snapshot already contains and starts over after a gap", async () => {
      const finding = await seedFinding();
      const thread = await seedThread(finding, [{ status: "streaming", content: "abc" }]);
      const id = thread.ids[0] as string;
      const stream = reader(await open(thread.id));
      expect((await stream.next())?.data.messages[0].content).toBe("abc");
      const notify = (payload: unknown) =>
        t.pool.query("select pg_notify($1, $2)", [`ai_${thread.id}`, JSON.stringify(payload)]);
      await notify({ e: "delta", m: id, from: 0, d: "abc" }); // duplicate
      await notify({ e: "delta", m: id, from: 3, d: "def" });
      await t.pool.query("update chat_message set content = 'abcdef' where id = $1", [id]);
      expect(await stream.next()).toEqual({ event: "delta", data: { id, from: 3, text: "def" } });
      await t.pool.query("update chat_message set content = 'abcdefXYZ-missed' where id = $1", [id]);
      await notify({ e: "delta", m: id, from: 40, d: "gap" }); // something was missed
      const again = await stream.next();
      expect(again?.event).toBe("snapshot");
      expect(again?.data.messages[0].content).toBe("abcdefXYZ-missed");
      // Garbage and notices for other messages are ignored.
      await notify("not an object");
      await notify({ e: "delta", m: 5 });
      await t.pool.query("select pg_notify($1, 'not json')", [`ai_${thread.id}`]);
      await workerFinishes(thread.id, id, "stopped");
      expect((await stream.next())?.data).toMatchObject({ status: "stopped" });
      await stream.cancel();
    });

    it("says done at once when nothing is running", async () => {
      const finding = await seedFinding();
      const thread = await seedThread(finding, [{ status: "complete", content: "x" }]);
      const stream = reader(await open(thread.id));
      expect((await stream.next())?.event).toBe("snapshot");
      expect((await stream.next())?.event).toBe("done");
    });

    it("never shows one thread's text to a stream of another", async () => {
      const finding = await seedFinding();
      const mine = await seedThread(finding, [{ status: "streaming" }]);
      const otherFinding = await seedFinding(OTHER);
      const theirs = await seedThread(otherFinding, [{ status: "streaming" }], OTHER);
      const stream = reader(await open(mine.id));
      await stream.next();
      await workerWrites(theirs.id, theirs.ids[0] as string, "SECRET OF ANOTHER ORGANISATION");
      expect(await stream.next(400)).toBeNull();
      await stream.cancel();
    });

    it("limits open streams per person", async () => {
      const finding = await seedFinding();
      const thread = await seedThread(finding, [{ status: "streaming" }]);
      const open1 = [];
      for (let i = 0; i < 6; i++) open1.push(await open(thread.id, { user: "user_c" }));
      expect((await open(thread.id, { user: "user_c" })).status).toBe(429);
      for (const r of open1) await reader(r).cancel();
    });
  });
});
