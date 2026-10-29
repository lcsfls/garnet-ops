/**
 * Creating personal notifications (ADR 0019) against a throw-away database on the development
 * PostgreSQL: recipients by role and by each person's choices, the scope, the mail queue, the
 * live NOTIFY, retention, and that a link outside the app is refused. Skipped without the
 * development PostgreSQL.
 */
import { RETENTION, USER_NOTIFICATION_CHANNEL } from "@garnetops/core/user-notifications";
import { eq } from "drizzle-orm";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { schema } from "./index.ts";
import { createTestDatabase, devDatabaseUrl, type TestDatabase } from "./testing.ts";
import { mailChannelAvailable, notifyUsers, pruneUserNotifications } from "./user-notifications.ts";

const adminUrl = devDatabaseUrl();
const ORG = "org_un";
const OTHER = "org_other_un";

describe.skipIf(!adminUrl)("notifyUsers", () => {
  let t: TestDatabase;

  const rows = () => t.db.select().from(schema.userNotification).orderBy(schema.userNotification.id);
  const told = async () => [...new Set((await rows()).map((r) => r.userId))].sort();

  beforeAll(async () => {
    t = await createTestDatabase(adminUrl as string, "db_user_notifications");
    await t.db.insert(schema.organization).values([
      { id: ORG, name: "Example Org" },
      { id: OTHER, name: "Other Org" },
    ]);
    for (const [id, role, org] of [
      ["u_owner", "owner", ORG],
      ["u_admin", "admin", ORG],
      ["u_member", "member", ORG],
      ["u_viewer", "viewer", ORG],
      ["u_stranger", "owner", OTHER],
    ] as const) {
      await t.db.insert(schema.user).values({ id, name: id, email: `${id}@example.test` });
      await t.db.insert(schema.membership).values({ organizationId: org, userId: id, role });
    }
  }, 60_000);

  afterAll(async () => {
    await t?.drop();
  });

  beforeEach(async () => {
    await t.pool.query(
      "truncate user_notification, notification_preference, notification_channel restart identity cascade",
    );
  });

  it("tells the people the role allows, in one organisation only", async () => {
    const result = await notifyUsers(t.db, {
      organizationId: ORG,
      titleKey: "certificateChangedDirectory",
      params: { name: "Example directory" },
      link: "/settings?section=directory",
    });
    expect(result).toEqual({ inApp: 2, mail: 0 });
    expect(await told()).toEqual(["u_admin", "u_owner"]);
    const [row] = await rows();
    expect(row).toMatchObject({
      event: "infra.certificate_changed",
      titleKey: "certificateChangedDirectory",
      params: { name: "Example directory" },
      link: "/settings?section=directory",
      inApp: true,
      readAt: null,
      mailState: "none",
    });
  });

  it("tells only the owner about a private repository (ADR 0030), and everyone once it is shared", async () => {
    await t.db.insert(schema.repository).values({
      id: "repo_un_private",
      organizationId: ORG,
      name: "secret-app",
      url: "https://git.example.lan/t/secret-app.git",
      authKind: "none",
      visibility: "private",
      ownerUserId: "u_member",
    });
    const input = {
      organizationId: ORG,
      titleKey: "gateBlocked" as const,
      params: { repository: "secret-app", rules: 1 },
      link: "/repositories/repo_un_private",
      repositoryId: "repo_un_private",
    };
    await notifyUsers(t.db, input);
    expect(await told()).toEqual(["u_member"]);
    await t.pool.query("truncate user_notification restart identity cascade");
    await t.pool.query("update repository set visibility = 'organization' where id = 'repo_un_private'");
    await notifyUsers(t.db, input);
    expect(await told()).toEqual(["u_admin", "u_member", "u_owner", "u_viewer"]);
    // A repository of another organisation, or one that is gone, tells nobody.
    await t.pool.query("truncate user_notification restart identity cascade");
    expect(await notifyUsers(t.db, { ...input, repositoryId: "repo_missing" })).toEqual({
      inApp: 0,
      mail: 0,
    });
  });

  it("follows each person's own choices", async () => {
    await t.db.insert(schema.notificationPreference).values([
      { organizationId: ORG, userId: "u_member", event: "gate.blocked", inApp: false, email: false },
      {
        organizationId: ORG,
        userId: "u_viewer",
        event: "gate.blocked",
        inApp: true,
        email: false,
        scope: "mine",
      },
    ]);
    await notifyUsers(t.db, {
      organizationId: ORG,
      titleKey: "gateBlocked",
      params: { repository: "billing", rules: 1 },
      link: "/repositories/repo_1",
      context: { ownerUserId: "u_admin" },
    });
    // The member switched it off; the viewer only wants their own repositories.
    expect(await told()).toEqual(["u_admin", "u_owner"]);
  });

  it("targets a role change at the person it is about", async () => {
    await notifyUsers(t.db, {
      organizationId: ORG,
      titleKey: "roleChanged",
      params: { role: "admin" },
      link: "/account",
      context: { targetUserId: "u_viewer" },
    });
    expect(await told()).toEqual(["u_viewer"]);
  });

  it("queues a personal mail only when the organisation has a mail channel and the person wants it", async () => {
    await t.db.insert(schema.notificationPreference).values([
      { organizationId: ORG, userId: "u_admin", event: "scan.failed", inApp: true, email: true },
      { organizationId: ORG, userId: "u_member", event: "scan.failed", inApp: false, email: true },
    ]);
    const input = {
      organizationId: ORG,
      titleKey: "scanFailed" as const,
      params: { repository: "billing" },
      link: "/repositories/repo_1",
    };
    expect(await mailChannelAvailable(t.db, ORG)).toBe(false);
    await notifyUsers(t.db, input);
    expect((await rows()).every((r) => r.mailState === "none")).toBe(true);
    // The member turned the in-app copy off and has no mail: nobody to tell.
    expect(await told()).toEqual(["u_admin", "u_owner"]);

    await t.pool.query("truncate user_notification restart identity");
    await t.db.insert(schema.notificationChannel).values({
      id: "nch_smtp",
      organizationId: ORG,
      name: "Mail",
      kind: "smtp",
      events: ["scan.failed"],
      config: { host: "smtp.example.test", port: 465, security: "tls", from: "noreply@example.test", to: [] },
    });
    expect(await mailChannelAvailable(t.db, ORG)).toBe(true);
    expect(await mailChannelAvailable(t.db, OTHER)).toBe(false);
    expect(await notifyUsers(t.db, input)).toEqual({ inApp: 2, mail: 2 });
    const all = await rows();
    const byUser = Object.fromEntries(all.map((r) => [r.userId, r]));
    expect(byUser.u_admin).toMatchObject({ inApp: true, mailState: "pending", readAt: null });
    // A mail-only copy is hidden from the app: it counts as read from the start.
    expect(byUser.u_member).toMatchObject({ inApp: false, mailState: "pending" });
    expect(byUser.u_member?.readAt).not.toBeNull();
    expect(byUser.u_owner).toMatchObject({ inApp: true, mailState: "none" });

    // A disabled channel is no mail channel.
    await t.db
      .update(schema.notificationChannel)
      .set({ enabled: false })
      .where(eq(schema.notificationChannel.id, "nch_smtp"));
    expect(await mailChannelAvailable(t.db, ORG)).toBe(false);
  });

  it("announces each in-app row on the PostgreSQL channel, to nobody else's id", async () => {
    const listener = await t.pool.connect();
    const heard: string[] = [];
    listener.on("notification", (m) => heard.push(m.payload ?? ""));
    await listener.query(`LISTEN ${USER_NOTIFICATION_CHANNEL}`);
    try {
      await notifyUsers(t.db, {
        organizationId: ORG,
        titleKey: "invitationAccepted",
        params: { person: "Pat Example" },
        link: "/team",
      });
      await new Promise((resolve) => setTimeout(resolve, 200));
      const ids = (await rows()).map((r) => ({ u: r.userId, id: r.id }));
      expect(heard.map((h) => JSON.parse(h)).sort((a, b) => a.id - b.id)).toEqual(ids);
      expect(heard.join()).not.toContain("Pat");
    } finally {
      await listener.query(`UNLISTEN ${USER_NOTIFICATION_CHANNEL}`);
      listener.release();
    }
  });

  it("refuses a link that leaves the app and an unknown title", async () => {
    for (const link of ["https://evil.example/", "//evil.example", "javascript:alert(1)", "/a/../b"]) {
      await expect(
        notifyUsers(t.db, { organizationId: ORG, titleKey: "scanFailed", link }),
        link,
      ).rejects.toThrow(RangeError);
    }
    await expect(
      notifyUsers(t.db, { organizationId: ORG, titleKey: "nope" as never, link: "/" }),
    ).rejects.toThrow(RangeError);
    expect(await rows()).toHaveLength(0);
  });

  it("keeps each person's newest notifications only, and drops old ones", async () => {
    const bulk = Array.from({ length: RETENTION.maxPerUser + 20 }, (_, i) => ({
      userId: "u_viewer",
      organizationId: ORG,
      event: "gate.blocked",
      titleKey: "gateBlocked",
      params: { n: i },
      link: "/",
    }));
    await t.db.insert(schema.userNotification).values(bulk);
    await notifyUsers(t.db, { organizationId: ORG, titleKey: "gateBlocked", link: "/gates" });
    const mine = (await rows()).filter((r) => r.userId === "u_viewer");
    expect(mine).toHaveLength(RETENTION.maxPerUser);
    // The newest survive: the one just created is the last.
    expect(mine.at(-1)?.link).toBe("/gates");
    expect(mine[0]?.params).toEqual({ n: 21 });

    await t.pool.query(
      `update user_notification set created_at = now() - interval '${RETENTION.days + 1} days' where user_id = 'u_viewer' and link = '/'`,
    );
    const removed = await pruneUserNotifications(t.db);
    expect(removed).toBe(RETENTION.maxPerUser - 1);
    expect((await rows()).filter((r) => r.userId === "u_viewer")).toHaveLength(1);
  });
});
