/**
 * The end of an update tells owners and admins once (ADR 0019): the notification is written when
 * the journal entry is first copied into the audit log, never again for a repeat. Against a
 * throw-away PostgreSQL database on the development server; skipped without it.
 */
import { schema } from "@garnetops/db";
import { createTestDatabase, devDatabaseUrl, type TestDatabase } from "@garnetops/db/testing";
import type { JournalEvent } from "@restow-backup/cicd-updater";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { journalStore } from "./journal.ts";

const adminUrl = devDatabaseUrl();
const ORG = "org_j";

const event = (action: JournalEvent["action"], id: string, target: string): JournalEvent => ({
  id,
  at: "2026-10-22T10:00:00.000Z",
  action,
  runId: "run_1",
  actor: { id: null, label: "system", via: "system" },
  target,
  details: {},
});

describe.skipIf(!adminUrl)("update journal notifications", () => {
  let t: TestDatabase;

  beforeAll(async () => {
    t = await createTestDatabase(adminUrl as string, "api_journal_notifications");
    await t.db.insert(schema.organization).values({ id: ORG, name: "Example Org" });
    for (const [id, role] of [
      ["u_owner", "owner"],
      ["u_admin", "admin"],
      ["u_member", "member"],
    ] as const) {
      await t.db.insert(schema.user).values({ id, name: id, email: `${id}@example.test` });
      await t.db.insert(schema.membership).values({ organizationId: ORG, userId: id, role });
    }
  }, 60_000);

  afterAll(async () => {
    await t?.drop();
  });

  const notifications = () => t.db.select().from(schema.userNotification).orderBy(schema.userNotification.id);

  it("tells owners and admins once when an update succeeded, and not for other steps", async () => {
    const store = journalStore(t.db);
    await store.ingest(event("update.started", "e1", "0.0.2"));
    expect(await notifications()).toHaveLength(0);
    await store.ingest(event("update.succeeded", "e2", "0.0.2"));
    await store.ingest(event("update.succeeded", "e2", "0.0.2")); // a repeat after a restart
    const rows = await notifications();
    expect(rows.map((r) => r.userId).sort()).toEqual(["u_admin", "u_owner"]);
    expect(rows[0]).toMatchObject({
      event: "system.update_finished",
      titleKey: "updateSucceeded",
      params: { version: "0.0.2" },
      link: "/settings?section=updates",
    });
  });

  it("tells them when it failed, and shows an odd version name as a question mark", async () => {
    const store = journalStore(t.db);
    await store.ingest(event("update.failed", "e3", "<script>alert(1)</script>"));
    const failed = (await notifications()).filter((r) => r.titleKey === "updateFailed");
    expect(failed).toHaveLength(2);
    expect(failed[0]?.params).toEqual({ version: "?" });
  });
});
