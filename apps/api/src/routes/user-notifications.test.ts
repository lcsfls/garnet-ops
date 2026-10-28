/**
 * Personal notifications over the API (ADR 0019) against a throw-away PostgreSQL database on the
 * development server: the list and its cursor, marking as read, isolation between people and
 * organisations, the event stream (new notifications, resuming with the last id, too much to
 * replay, the connection limit) and the preference matrix (roles, mail channel, validation).
 * Sessions are replaced by a header-driven actor. Skipped without the development PostgreSQL.
 */
import { schema } from "@garnetops/db";
import { devDatabaseUrl, type TestDatabase } from "@garnetops/db/testing";
import { Hono } from "hono";
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";

const adminUrl = devDatabaseUrl();
const holder = vi.hoisted(() => ({ db: null as unknown }));

vi.mock("../db.ts", async () => {
  const { createTestDatabase: create, devDatabaseUrl: url } = await import("@garnetops/db/testing");
  const target = url();
  if (!target) return { db: null, pool: null, boss: null, QUEUES: {} };
  const t = await create(target, "api_user_notifications");
  holder.db = t;
  return { db: t.db, pool: t.pool, boss: null, QUEUES: {} };
});
vi.mock("../env.ts", () => ({ env: { PUBLIC_URL: "https://garnetops.example.test/" } }));
vi.mock("../auth.ts", () => ({ auth: { api: {} } }));

// biome-ignore lint/suspicious/noExplicitAny: test helper for arbitrary response bodies
type Json = Record<string, any>;
type Role = "owner" | "admin" | "member" | "viewer";
const ORG = "org_a";
const OTHER = "org_b";

describe.skipIf(!adminUrl)("personal notifications", () => {
  let t: TestDatabase;
  let app: Hono;
  let notifyUsers: typeof import("@garnetops/db").notifyUsers;

  const as = (user: string, role: Role = "member", org = ORG) => ({
    "x-user": user,
    "x-role": role,
    "x-org": org,
    "x-age": "0",
  });

  async function call(
    method: string,
    path: string,
    options: { user?: string; role?: Role; org?: string; body?: unknown } = {},
  ) {
    const headers: Record<string, string> = as(
      options.user ?? "u_member",
      options.role ?? "member",
      options.org ?? ORG,
    );
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
    return { status: res.status, json: json as Json | null };
  }

  /** A gate-blocked notification for everyone in ORG who is told about it. */
  const gateBlocked = (name = "billing") =>
    notifyUsers(t.db, {
      organizationId: ORG,
      titleKey: "gateBlocked",
      params: { repository: name, rules: 1 },
      link: "/repositories/repo_1",
    });
  const rowsOf = (user: string) =>
    t.db
      .select()
      .from(schema.userNotification)
      .orderBy(schema.userNotification.id)
      .then((all) => all.filter((r) => r.userId === user));

  beforeAll(async () => {
    ({ notifyUsers } = await import("@garnetops/db"));
    const { handleError } = await import("../lib/problem.ts");
    const { userNotificationRoutes } = await import("./user-notifications.ts");
    t = holder.db as TestDatabase; // set when the routes imported the mocked database module
    await t.db.insert(schema.organization).values([
      { id: ORG, name: "A" },
      { id: OTHER, name: "B" },
    ]);
    for (const [id, role, org] of [
      ["u_owner", "owner", ORG],
      ["u_admin", "admin", ORG],
      ["u_member", "member", ORG],
      ["u_viewer", "viewer", ORG],
      ["u_other", "owner", OTHER],
    ] as const) {
      await t.db.insert(schema.user).values({ id, name: id, email: `${id}@example.test` });
      await t.db.insert(schema.membership).values({ organizationId: org, userId: id, role });
    }
    const v1 = new Hono().use("*", async (c, next) => {
      c.set(
        "actor" as never,
        {
          userId: c.req.header("x-user"),
          email: `${c.req.header("x-user")}@example.test`,
          name: "Test",
          organizationId: c.req.header("x-org"),
          role: c.req.header("x-role"),
          ip: "198.51.100.7",
          strongAuthAt: new Date(),
        } as never,
      );
      await next();
    });
    v1.route("/me", userNotificationRoutes as never);
    app = new Hono().onError(handleError).route("/api/v1", v1) as unknown as Hono;
  }, 60_000);

  afterAll(async () => {
    const { listenBus } = await import("../lib/listen-bus.ts");
    const { userNotificationBus } = await import("../lib/user-notification-bus.ts");
    userNotificationBus.reset();
    await listenBus.close();
    await t?.drop();
  });

  beforeEach(async () => {
    await t.pool.query(
      "truncate user_notification, notification_preference, notification_channel, rate_limit restart identity cascade",
    );
  });

  describe("list", () => {
    it("shows only the person's own notifications, newest first, with the unread count", async () => {
      await gateBlocked("one");
      await gateBlocked("two");
      await notifyUsers(t.db, {
        organizationId: OTHER,
        titleKey: "gateBlocked",
        params: { repository: "other-org" },
        link: "/gates",
      });
      const mine = await call("GET", "/api/v1/me/notifications");
      expect(mine.status).toBe(200);
      expect(mine.json?.items.map((i: Json) => i.params.repository)).toEqual(["two", "one"]);
      expect(mine.json?.unread).toBe(2);
      expect(mine.json?.next).toBeNull();
      expect(mine.json?.items[0]).toMatchObject({
        event: "gate.blocked",
        titleKey: "gateBlocked",
        link: "/repositories/repo_1",
        readAt: null,
      });
      // The other organisation's owner sees only theirs, and the headers cannot ask for anyone else's.
      const theirs = await call("GET", "/api/v1/me/notifications", {
        user: "u_other",
        role: "owner",
        org: OTHER,
      });
      expect(theirs.json?.items.map((i: Json) => i.params.repository)).toEqual(["other-org"]);
    });

    it("hides a person's rows that belong to another organisation, and mail-only copies", async () => {
      await t.db.insert(schema.userNotification).values([
        {
          userId: "u_member",
          organizationId: OTHER,
          event: "gate.blocked",
          titleKey: "gateBlocked",
          link: "/",
        },
        {
          userId: "u_member",
          organizationId: ORG,
          event: "gate.blocked",
          titleKey: "gateBlocked",
          link: "/",
          inApp: false,
        },
      ]);
      const res = await call("GET", "/api/v1/me/notifications");
      expect(res.json).toMatchObject({ items: [], unread: 0 });
    });

    it("pages with a cursor and can filter to unread", async () => {
      for (let i = 0; i < 7; i++) await gateBlocked(`r${i}`);
      const first = await call("GET", "/api/v1/me/notifications?limit=3");
      expect(first.json?.items).toHaveLength(3);
      expect(first.json?.next).toBe(first.json?.items[2].id);
      const second = await call("GET", `/api/v1/me/notifications?limit=3&before=${first.json?.next}`);
      expect(second.json?.items.map((i: Json) => i.params.repository)).toEqual(["r3", "r2", "r1"]);
      const last = await call("GET", `/api/v1/me/notifications?limit=3&before=${second.json?.next}`);
      expect(last.json?.items.map((i: Json) => i.params.repository)).toEqual(["r0"]);
      expect(last.json?.next).toBeNull();
      await call("POST", `/api/v1/me/notifications/${first.json?.items[0].id}/read`);
      const unread = await call("GET", "/api/v1/me/notifications?unread=1&limit=100");
      expect(unread.json?.items).toHaveLength(6);
      expect((await call("GET", "/api/v1/me/notifications?limit=1000")).status).toBe(422);
      expect((await call("GET", "/api/v1/me/notifications?before=abc")).status).toBe(422);
    });
  });

  describe("marking as read", () => {
    it("marks one, idempotently, and lowers the count", async () => {
      await gateBlocked();
      await gateBlocked();
      const [a] = (await call("GET", "/api/v1/me/notifications")).json?.items ?? [];
      expect((await call("POST", `/api/v1/me/notifications/${a.id}/read`)).status).toBe(204);
      expect((await call("POST", `/api/v1/me/notifications/${a.id}/read`)).status).toBe(204);
      const after = await call("GET", "/api/v1/me/notifications");
      expect(after.json?.unread).toBe(1);
      expect(after.json?.items[0].readAt).not.toBeNull();
    });

    it("never touches someone else's notification, and treats it like a missing one", async () => {
      await gateBlocked();
      const [mine] = await rowsOf("u_member");
      expect(
        (
          await call("POST", `/api/v1/me/notifications/${mine?.id}/read`, {
            user: "u_viewer",
            role: "viewer",
          })
        ).status,
      ).toBe(404);
      expect(
        (
          await call("POST", `/api/v1/me/notifications/${mine?.id}/read`, {
            user: "u_other",
            role: "owner",
            org: OTHER,
          })
        ).status,
      ).toBe(404);
      expect((await call("POST", "/api/v1/me/notifications/999999/read")).status).toBe(404);
      expect((await call("POST", "/api/v1/me/notifications/abc/read")).status).toBe(404);
      expect((await rowsOf("u_member"))[0]?.readAt).toBeNull();
    });

    it("marks all up to the newest one the person has seen", async () => {
      await gateBlocked("seen");
      const seen = (await rowsOf("u_member"))[0]?.id as number;
      await gateBlocked("later");
      const some = await call("POST", "/api/v1/me/notifications/read-all", { body: { upTo: seen } });
      expect(some.json).toEqual({ updated: 1 });
      expect((await call("GET", "/api/v1/me/notifications")).json?.unread).toBe(1);
      const all = await call("POST", "/api/v1/me/notifications/read-all");
      expect(all.json).toEqual({ updated: 1 });
      expect((await call("GET", "/api/v1/me/notifications")).json?.unread).toBe(0);
      // Other people's notifications stay unread.
      expect((await rowsOf("u_viewer")).every((r) => r.readAt === null)).toBe(true);
    });
  });

  describe("event stream", () => {
    /** Reads server-sent events from a response as they come. */
    function reader(res: Response) {
      const decoder = new TextDecoder();
      const body = (res.body as ReadableStream<Uint8Array>).getReader();
      let buffer = "";
      // A read that timed out stays pending; the next call waits for the same read, so no chunk is lost.
      let pending: ReturnType<typeof body.read> | null = null;
      return {
        async next(timeout = 3000): Promise<{ event: string; id?: string; data: Json } | null> {
          const deadline = Date.now() + timeout;
          for (;;) {
            const end = buffer.indexOf("\n\n");
            if (end >= 0) {
              const block = buffer.slice(0, end);
              buffer = buffer.slice(end + 2);
              if (block.startsWith(":")) continue;
              const event = /^event: (.*)$/m.exec(block)?.[1] ?? "message";
              const id = /^id: (.*)$/m.exec(block)?.[1];
              const data = /^data: (.*)$/m.exec(block)?.[1];
              return { event, ...(id ? { id } : {}), data: data ? JSON.parse(data) : {} };
            }
            const left = deadline - Date.now();
            if (left <= 0) return null;
            pending ??= body.read();
            const chunk = await Promise.race([
              pending,
              new Promise<null>((r) => setTimeout(() => r(null), left)),
            ]);
            if (chunk === null) return null;
            pending = null;
            if (chunk.done) return null;
            buffer += decoder.decode(chunk.value, { stream: true });
          }
        },
        cancel: () => body.cancel().catch(() => {}),
      };
    }
    const open = (options: { user?: string; role?: Role; org?: string; lastEventId?: number } = {}) =>
      app.request("/api/v1/me/notifications/stream", {
        headers: {
          ...as(options.user ?? "u_member", options.role ?? "member", options.org ?? ORG),
          ...(options.lastEventId !== undefined ? { "last-event-id": String(options.lastEventId) } : {}),
        },
      });

    it("says ready with the unread count, then delivers new notifications as they are written", async () => {
      await gateBlocked("before");
      const res = await open();
      expect(res.status).toBe(200);
      expect(res.headers.get("content-type")).toContain("text/event-stream");
      expect(res.headers.get("cache-control")).toContain("no-store");
      const stream = reader(res);
      const ready = await stream.next();
      expect(ready).toMatchObject({ event: "ready", data: { unread: 1 } });
      expect(ready?.data.latestId).toBeGreaterThan(0);
      await gateBlocked("live");
      const live = await stream.next();
      expect(live?.event).toBe("notification");
      expect(live?.data).toMatchObject({
        titleKey: "gateBlocked",
        params: { repository: "live" },
        readAt: null,
      });
      expect(live?.id).toBe(String(live?.data.id));
      await stream.cancel();
    });

    it("resumes from the last id and sends what was missed, in order", async () => {
      await gateBlocked("one");
      const first = (await rowsOf("u_member"))[0]?.id as number;
      await gateBlocked("two");
      await gateBlocked("three");
      const stream = reader(await open({ lastEventId: first }));
      expect((await stream.next())?.event).toBe("ready");
      const two = await stream.next();
      const three = await stream.next();
      expect([two?.data.params.repository, three?.data.params.repository]).toEqual(["two", "three"]);
      expect(await stream.next(300)).toBeNull();
      await stream.cancel();
    });

    it("asks the browser to reload the list when too much was missed", async () => {
      const bulk = Array.from({ length: 60 }, () => ({
        userId: "u_member",
        organizationId: ORG,
        event: "gate.blocked",
        titleKey: "gateBlocked",
        link: "/",
      }));
      await t.db.insert(schema.userNotification).values(bulk);
      const stream = reader(await open({ lastEventId: 1 }));
      expect((await stream.next())?.event).toBe("ready");
      expect((await stream.next())?.event).toBe("resync");
      expect(await stream.next(300)).toBeNull();
      await stream.cancel();
    });

    it("never delivers another person's or another organisation's notification", async () => {
      const mine = reader(await open({ user: "u_viewer", role: "viewer" }));
      const theirs = reader(await open({ user: "u_other", role: "owner", org: OTHER }));
      expect((await mine.next())?.event).toBe("ready");
      expect((await theirs.next())?.event).toBe("ready");
      // A role-limited event: only owners and admins of ORG are told.
      await notifyUsers(t.db, {
        organizationId: ORG,
        titleKey: "certificateChangedDirectory",
        params: { name: "ldaps://dc.example.lan" },
        link: "/settings",
      });
      expect(await mine.next(500)).toBeNull();
      expect(await theirs.next(500)).toBeNull();
      const admin = reader(await open({ user: "u_admin", role: "admin" }));
      expect((await admin.next())?.event).toBe("ready");
      // The admin was told of the certificate before the stream opened; that is not replayed.
      await gateBlocked("for all in A");
      expect((await mine.next())?.data.params.repository).toBe("for all in A");
      expect((await admin.next())?.data.params.repository).toBe("for all in A");
      expect(await theirs.next(300)).toBeNull();
      await Promise.all([mine.cancel(), theirs.cancel(), admin.cancel()]);
    });

    it("limits open streams per person", async () => {
      const opened = [];
      for (let i = 0; i < 4; i++) {
        const res = await open({ user: "u_owner", role: "owner" });
        expect(res.status).toBe(200);
        opened.push(res);
      }
      const refused = await open({ user: "u_owner", role: "owner" });
      expect(refused.status).toBe(429);
      expect(((await refused.json()) as Json).type).toContain("too-many-streams");
      // Another person is not affected.
      const other = await open({ user: "u_admin", role: "admin" });
      expect(other.status).toBe(200);
      for (const r of [...opened, other]) await reader(r).cancel();
      // Closing frees the slots (give the server a moment to notice the abort).
      await new Promise((resolve) => setTimeout(resolve, 300));
      const again = await open({ user: "u_owner", role: "owner" });
      expect(again.status).toBe(200);
      await reader(again).cancel();
    });
  });

  describe("preferences", () => {
    const get = (options: Parameters<typeof call>[2] = {}) =>
      call("GET", "/api/v1/me/notification-preferences", options);
    const put = (preferences: unknown, options: Parameters<typeof call>[2] = {}) =>
      call("PUT", "/api/v1/me/notification-preferences", { ...options, body: { preferences } });
    const addMailChannel = () =>
      t.db.insert(schema.notificationChannel).values({
        id: "nch_mail",
        organizationId: ORG,
        name: "Mail",
        kind: "smtp",
        events: ["scan.failed"],
        config: {
          host: "smtp.example.test",
          port: 465,
          security: "tls",
          from: "noreply@example.test",
          to: [],
        },
      });

    it("lists the events a role can receive, grouped, with the defaults", async () => {
      const viewer = await get({ user: "u_viewer", role: "viewer" });
      expect(viewer.json).toMatchObject({
        email: "u_viewer@example.test",
        mailAvailable: false,
        canManageChannels: false,
      });
      expect(viewer.json?.events.map((e: Json) => e.event)).toEqual([
        "finding.new_critical",
        "gate.blocked",
        "team.role_changed",
      ]);
      expect(viewer.json?.events[0]).toMatchObject({
        group: "code",
        scoped: true,
        scopeKind: "repositories",
        preference: { inApp: true, email: false, scope: "all" },
      });
      const admin = await get({ user: "u_admin", role: "admin" });
      expect(admin.json?.canManageChannels).toBe(true);
      expect(admin.json?.events).toHaveLength(9);
      expect(admin.json?.events.map((e: Json) => e.group)).toEqual([
        ...Array(5).fill("code"),
        // The directory's certificate, an accepted invitation and a changed role.
        ...Array(3).fill("account"),
        "system",
      ]);
      const fix = admin.json?.events.find((e: Json) => e.event === "fix_pr.merged");
      expect(fix).toMatchObject({ scopeKind: "requests", preference: { scope: "mine" } });
    });

    it("stores a choice and shows it again, per person", async () => {
      const saved = await put(
        [
          { event: "gate.blocked", inApp: false, email: false, scope: "all" },
          { event: "finding.new_critical", inApp: true, email: false, scope: "mine" },
        ],
        { user: "u_member" },
      );
      expect(saved.status).toBe(204);
      const mine = await get({ user: "u_member" });
      const byEvent = Object.fromEntries(mine.json?.events.map((e: Json) => [e.event, e.preference]));
      expect(byEvent["gate.blocked"]).toEqual({ inApp: false, email: false, scope: "all" });
      expect(byEvent["finding.new_critical"]).toEqual({ inApp: true, email: false, scope: "mine" });
      // Someone else is untouched; an untouched event keeps its default.
      const other = await get({ user: "u_viewer", role: "viewer" });
      expect(other.json?.events[1].preference.inApp).toBe(true);
      expect(byEvent["scan.failed"]).toEqual({ inApp: true, email: false, scope: "all" });
      // The choice decides who is told.
      await gateBlocked();
      expect(await rowsOf("u_member")).toHaveLength(0);
      expect(await rowsOf("u_viewer")).toHaveLength(1);
    });

    it("refuses events the role cannot receive, repeats, and unknown names", async () => {
      const wrongRole = await put(
        [{ event: "infra.certificate_changed", inApp: true, email: false, scope: "all" }],
        {
          user: "u_member",
        },
      );
      expect(wrongRole.status).toBe(422);
      const twice = await put(
        [
          { event: "gate.blocked", inApp: true, email: false, scope: "all" },
          { event: "gate.blocked", inApp: false, email: false, scope: "all" },
        ],
        { user: "u_member" },
      );
      expect(twice.status).toBe(422);
      for (const bad of [
        [{ event: "nope", inApp: true, email: false, scope: "all" }],
        [{ event: "gate.blocked", inApp: "yes", email: false, scope: "all" }],
        [{ event: "gate.blocked", inApp: true, email: false, scope: "everyone" }],
        [],
      ]) {
        expect((await put(bad)).status).toBe(422);
      }
      expect(await t.db.select().from(schema.notificationPreference)).toHaveLength(0);
    });

    it("accepts email only while the organisation has a mail channel, and stops showing it when it is gone", async () => {
      const wish = [{ event: "scan.failed", inApp: true, email: true, scope: "all" }];
      const refused = await put(wish);
      expect(refused.status).toBe(422);
      expect(JSON.stringify(refused.json)).toContain("mail channel");

      await addMailChannel();
      expect((await get()).json?.mailAvailable).toBe(true);
      expect((await put(wish)).status).toBe(204);
      expect((await get()).json?.events.find((e: Json) => e.event === "scan.failed").preference.email).toBe(
        true,
      );

      await t.pool.query("delete from notification_channel");
      const gone = await get();
      expect(gone.json?.mailAvailable).toBe(false);
      expect(gone.json?.events.find((e: Json) => e.event === "scan.failed").preference.email).toBe(false);
    });

    it("keeps events that cannot be limited at 'all'", async () => {
      await put([{ event: "team.role_changed", inApp: true, email: false, scope: "mine" }]);
      const [row] = await t.db.select().from(schema.notificationPreference);
      expect(row).toMatchObject({ event: "team.role_changed", scope: "all" });
    });

    it("is rate-limited", async () => {
      const ok = [{ event: "gate.blocked", inApp: true, email: false, scope: "all" }];
      for (let i = 0; i < 30; i++) expect((await put(ok)).status).toBe(204);
      expect((await put(ok)).status).toBe(429);
    });
  });
});
