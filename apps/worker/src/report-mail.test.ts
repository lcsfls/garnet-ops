/**
 * The report mail in the worker (ADR 0047) against a throw-away PostgreSQL database on the development server: each person's
 * report is built with that person's visibility (another member's private repository is in nobody else's mail or PDF), it goes
 * to the person's own address only, it is due from 07:00 in the person's own zone, a period is sent once however often the
 * tick runs, nothing is sent without a mail channel or to someone who left. Mail goes to a recording sender; nothing leaves
 * the machine. Skipped without the development PostgreSQL.
 */

import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { inflateSync } from "node:zlib";
import { generateVaultKeyPair } from "@garnetops/core/vault";
import { schema } from "@garnetops/db";
import { createTestDatabase, devDatabaseUrl, type TestDatabase } from "@garnetops/db/testing";
import { eq } from "drizzle-orm";
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import type { MailAttachment } from "./notify.ts";

const adminUrl = devDatabaseUrl();
const work = mkdtempSync(join(tmpdir(), "garnetops-report-mail-test-"));
afterAll(() => rmSync(work, { recursive: true, force: true }));

const ORG = "org_rm";
/** Monday 2 November 2026: 06:30 UTC is 07:30 in Berlin and 01:30 in New York. */
const MONDAY = new Date("2026-11-02T06:30:00.000Z");

interface Sent {
  to: string[];
  subject: string;
  text: string;
  attachments: MailAttachment[];
}

/** The text operators of a PDF, inflated. */
function pdfText(pdf: Buffer): string {
  const raw = pdf.toString("latin1");
  const out: string[] = [];
  const re = />>\nstream\n/g;
  let match: RegExpExecArray | null = re.exec(raw);
  while (match) {
    const start = match.index + match[0].length;
    out.push(inflateSync(pdf.subarray(start, raw.indexOf("\nendstream", start))).toString("latin1"));
    match = re.exec(raw);
  }
  return out.join("\n");
}

describe.skipIf(!adminUrl)("report mail in the worker", () => {
  let t: TestDatabase;
  let mod: typeof import("./report-mail.ts");
  let sent: Sent[] = [];
  const send: import("./report-mail.ts").ReportMailSender = async (
    _channel,
    subject,
    text,
    to,
    attachments,
  ) => {
    sent.push({ to, subject, text, attachments });
  };
  const tick = (now: Date) => mod.sendDueReportMails({ now: () => now, send });

  async function subscribe(userId: string, frequency: "daily" | "weekly" | "monthly", attachPdf = true) {
    await t.db
      .insert(schema.reportSubscription)
      .values({ organizationId: ORG, userId, frequency, attachPdf, since: new Date("2026-10-01T00:00:00Z") })
      .onConflictDoUpdate({
        target: [schema.reportSubscription.organizationId, schema.reportSubscription.userId],
        set: { frequency, attachPdf },
      });
  }

  beforeAll(async () => {
    const vaultKey = join(work, "vault.pem");
    writeFileSync(vaultKey, generateVaultKeyPair().privateKeyPem, { mode: 0o600 });
    t = await createTestDatabase(adminUrl as string, "worker_report_mail");
    Object.assign(process.env, {
      DATABASE_URL: t.url,
      GARNETOPS_VAULT_PRIVATE_KEY_FILE: vaultKey,
      GARNETOPS_GRYPE_BIN: "unused",
      GARNETOPS_GRYPE_DB_DIR: work,
      PUBLIC_URL: "https://garnetops.example.test/",
    });
    await t.db
      .insert(schema.organization)
      .values({ id: ORG, name: "Example Org", scanTimeZone: "Europe/Berlin" });
    for (const [id, zone, locale] of [
      ["u_alex", "Europe/Berlin", null],
      ["u_sam", "Europe/Berlin", "de"],
      ["u_ny", "America/New_York", null],
    ] as const) {
      await t.db
        .insert(schema.user)
        .values({ id, name: id, email: `${id}@example.test`, timeZone: zone, locale });
      await t.db.insert(schema.membership).values({ organizationId: ORG, userId: id, role: "member" });
    }
    await t.db.insert(schema.vulnerability).values({ id: "CVE-2099-0301", severity: "critical" });
    for (const [id, name, visibility] of [
      ["repo_rm_shared", "shared-portal", "organization"],
      ["repo_rm_private", "alex-secret-tool", "private"],
    ] as const) {
      await t.db.insert(schema.repository).values({
        id,
        organizationId: ORG,
        name,
        url: `https://git.example.lan/${name}.git`,
        authKind: "none",
        visibility,
        ownerUserId: "u_alex",
      });
      await t.db.insert(schema.finding).values({
        id: `fnd_${id}`,
        organizationId: ORG,
        repositoryId: id,
        vulnerabilityId: "CVE-2099-0301",
        dedupKey: id,
        packageName: "lib",
        packageVersion: "1.0.0",
        packageType: "npm",
        severity: "critical",
        severityRank: 5,
        state: "open",
        firstSeenScanId: "scan_x",
        lastSeenScanId: "scan_x",
        firstSeenAt: new Date("2026-10-28T10:00:00Z"),
        lastSeenAt: new Date("2026-10-28T10:00:00Z"),
      });
    }
    mod = await import("./report-mail.ts");
    for (const level of ["error", "warn"] as const) vi.spyOn(console, level).mockImplementation(() => {});
  }, 60_000);

  afterAll(async () => {
    vi.restoreAllMocks();
    await t?.drop();
  });

  beforeEach(async () => {
    sent = [];
    await t.db.delete(schema.reportMailRun);
    await t.db.delete(schema.reportSubscription);
    await t.db.delete(schema.notificationChannel);
  });

  async function channel() {
    await t.db.insert(schema.notificationChannel).values({
      id: "nch_rm",
      organizationId: ORG,
      name: "Mail",
      kind: "smtp",
      events: [],
      config: {
        host: "mail.example.lan",
        port: 587,
        from: "noreply@example.test",
        to: ["ops-list@example.test"],
      },
    });
  }

  it("each person gets their own report, built with their own visibility, to their own address", async () => {
    await channel();
    await subscribe("u_alex", "weekly");
    await subscribe("u_sam", "weekly");
    expect(await tick(MONDAY)).toBe(2);
    const alex = sent.find((m) => m.to[0] === "u_alex@example.test");
    const sam = sent.find((m) => m.to[0] === "u_sam@example.test");
    expect(sent.every((m) => m.to.length === 1 && !m.to.includes("ops-list@example.test"))).toBe(true);
    expect(alex?.text).toContain("2 open: 2 critical");
    expect(sam?.text).toContain("1 offen: 1 kritisch");
    expect(sam?.subject).toContain("Wöchentlicher Sicherheitsbericht");
    const samPdf = pdfText(sam?.attachments[0]?.content as Buffer);
    expect(samPdf).toContain("shared-portal");
    expect(samPdf).not.toContain("alex-secret-tool");
    expect(pdfText(alex?.attachments[0]?.content as Buffer)).toContain("alex-secret-tool");
    expect(sam?.attachments[0]?.contentType).toBe("application/pdf");
  });

  it("sends a period once, however often the tick runs", async () => {
    await channel();
    await subscribe("u_alex", "daily");
    expect(await tick(MONDAY)).toBe(1);
    expect(await tick(new Date(MONDAY.getTime() + 5 * 60_000))).toBe(0);
    expect(await tick(new Date(MONDAY.getTime() + 3 * 3600_000))).toBe(0);
    const runs = await t.db.select().from(schema.reportMailRun);
    expect(runs).toEqual([expect.objectContaining({ periodKey: "daily:2026-11-01", state: "sent" })]);
  });

  it("waits for 07:00 in the person's own zone", async () => {
    await channel();
    await subscribe("u_ny", "weekly");
    // 01:30 in New York on Monday, before 07:00 there: the latest due week is still 19 to 25 October.
    await tick(MONDAY);
    expect(sent[0]?.subject).toContain("Oct 19, 2026 to Oct 25, 2026");
    sent = [];
    // 07:00 in New York (UTC-5) is 12:00 UTC: now the week that just ended is due.
    await tick(new Date("2026-11-02T12:00:00Z"));
    expect(sent[0]?.subject).toContain("Oct 26, 2026 to Nov 1, 2026");
  });

  it("without the PDF the mail has the summary and a link only", async () => {
    await channel();
    await subscribe("u_alex", "monthly", false);
    await tick(MONDAY);
    expect(sent[0]?.attachments).toEqual([]);
    expect(sent[0]?.subject).toBe("Monthly security report: Example Org, October 2026");
    expect(sent[0]?.text).toContain("https://garnetops.example.test/statistics");
    expect(sent[0]?.text).not.toContain("alex-secret-tool");
  });

  it("records the period as skipped without a mail channel, and sends nothing to someone who left", async () => {
    await subscribe("u_alex", "daily");
    expect(await tick(MONDAY)).toBe(0);
    expect((await t.db.select().from(schema.reportMailRun))[0]?.state).toBe("skipped");
    await channel();
    await subscribe("u_sam", "daily");
    await t.db.delete(schema.membership).where(eq(schema.membership.userId, "u_sam"));
    expect(await tick(MONDAY)).toBe(0);
    expect(sent).toEqual([]);
  });

  it("records a failed delivery with a short code and does not retry it", async () => {
    await channel();
    await subscribe("u_alex", "daily");
    const { DeliveryError } = await import("./notify.ts");
    const failing: import("./report-mail.ts").ReportMailSender = async () => {
      throw new DeliveryError("SMTP 550");
    };
    expect(await mod.sendDueReportMails({ now: () => MONDAY, send: failing })).toBe(0);
    expect((await t.db.select().from(schema.reportMailRun))[0]).toMatchObject({
      state: "failed",
      error: "SMTP 550",
    });
    expect(await tick(MONDAY)).toBe(0);
  });
});
