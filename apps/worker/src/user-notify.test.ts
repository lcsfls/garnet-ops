/**
 * Personal notifications in the worker (ADR 0019) against a throw-away PostgreSQL database on the
 * development server: that the events of scans, fix pull requests and certificate changes create
 * the right rows for the right people (roles, choices, scope), once per change, and that personal
 * mail is batched, rate-limited and sent to the person's own address only, through a local SMTP
 * server with a throw-away certificate. Nothing leaves the machine. Skipped without the
 * development PostgreSQL or openssl.
 */
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createServer, type Server } from "node:tls";
import type { NotifyPayload } from "@garnetops/core/notifications";
import { MAIL_MAX_AGE_MS, MAIL_MIN_INTERVAL_MS } from "@garnetops/core/user-notifications";
import { generateVaultKeyPair } from "@garnetops/core/vault";
import { schema } from "@garnetops/db";
import { createTestDatabase, devDatabaseUrl, type TestDatabase } from "@garnetops/db/testing";
import { eq } from "drizzle-orm";
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";

const adminUrl = devDatabaseUrl();
const work = mkdtempSync(join(tmpdir(), "garnetops-user-notify-test-"));
let openssl = true;
try {
  execFileSync("openssl", ["version"], { stdio: "ignore" });
} catch {
  openssl = false;
}
afterAll(() => rmSync(work, { recursive: true, force: true }));

const ORG = "org_un";
const OTHER = "org_other";
const T0 = new Date("2026-10-22T10:00:00.000Z");

interface Mail {
  from: string;
  to: string[];
  data: string;
}

/** A minimal ESMTP server over TLS from the first byte (port 465 style) that records what it is given. */
function startSmtp(key: string, cert: string): Promise<{ server: Server; port: number; mails: Mail[] }> {
  const mails: Mail[] = [];
  const server = createServer({ key, cert }, (socket) => {
    let buffer = "";
    let inData = false;
    let current: Mail = { from: "", to: [], data: "" };
    socket.write("220 fake ESMTP\r\n");
    socket.on("data", (chunk) => {
      buffer += chunk.toString("latin1");
      for (;;) {
        if (inData) {
          const end = buffer.indexOf("\r\n.\r\n");
          if (end < 0) return;
          current.data = buffer.slice(0, end);
          buffer = buffer.slice(end + 5);
          inData = false;
          mails.push(current);
          current = { from: "", to: [], data: "" };
          socket.write("250 queued\r\n");
          continue;
        }
        const newline = buffer.indexOf("\r\n");
        if (newline < 0) return;
        const line = buffer.slice(0, newline);
        buffer = buffer.slice(newline + 2);
        const command = line.toUpperCase();
        if (command.startsWith("EHLO") || command.startsWith("HELO"))
          socket.write("250-fake\r\n250 8BITMIME\r\n");
        else if (command.startsWith("MAIL FROM")) {
          current.from = line.slice(line.indexOf("<") + 1, line.indexOf(">"));
          socket.write("250 ok\r\n");
        } else if (command.startsWith("RCPT TO")) {
          current.to.push(line.slice(line.indexOf("<") + 1, line.indexOf(">")));
          socket.write("250 ok\r\n");
        } else if (command === "DATA") {
          inData = true;
          socket.write("354 go ahead\r\n");
        } else if (command.startsWith("QUIT")) socket.end("221 bye\r\n");
        else socket.write("250 ok\r\n");
      }
    });
    socket.on("error", () => {});
  });
  return new Promise((resolve) =>
    server.listen(0, "127.0.0.1", () =>
      resolve({ server, port: (server.address() as AddressInfo).port, mails }),
    ),
  );
}

describe.skipIf(!adminUrl || !openssl)("personal notifications in the worker", () => {
  let t: TestDatabase;
  let mod: typeof import("./user-notify.ts");
  let notify: typeof import("./notify.ts");
  let px: typeof import("./proxmox.ts");
  let smtp: Awaited<ReturnType<typeof startSmtp>>;
  let ca = "";

  const rows = () => t.db.select().from(schema.userNotification).orderBy(schema.userNotification.id);
  const forUser = async (userId: string) => (await rows()).filter((r) => r.userId === userId);
  const titles = async (userId: string) => (await forUser(userId)).map((r) => r.titleKey);

  const scanResult = (events: NotifyPayload["event"][], ownerUserId: string | null = "u_member") => ({
    organizationId: ORG,
    ownerUserId,
    payloads: events.map((event) => {
      const payload: NotifyPayload = {
        event,
        organization: "Example Org",
        repository: { id: "repo_1", name: "billing-portal" },
        link: "https://garnetops.example.test/repositories/repo_1",
        at: T0.toISOString(),
      };
      if (event === "finding.new_critical") payload.counts = { critical: 2, knownExploited: 1 };
      if (event === "gate.blocked") payload.gate = { blockingRules: 3 };
      return payload;
    }),
  });

  async function smtpChannel(over: Partial<typeof schema.notificationChannel.$inferInsert> = {}) {
    await t.db.insert(schema.notificationChannel).values({
      id: "nch_mail",
      organizationId: ORG,
      name: "Mail",
      kind: "smtp",
      events: ["scan.failed"],
      config: {
        host: "127.0.0.1",
        port: smtp.port,
        security: "tls",
        username: null,
        from: "noreply@example.test",
        // The organisation's own recipients; personal mail must never go to them.
        to: ["ops-list@example.test"],
      },
      ...over,
    });
  }
  const wantMail = (userId: string, event: string, scope: "all" | "mine" = "all") =>
    t.db
      .insert(schema.notificationPreference)
      .values({ organizationId: ORG, userId, event, inApp: true, email: true, scope });
  /** Delivers through the real SMTP code path to the local server. */
  const viaFakeSmtp: import("./user-notify.ts").MailSender = (channel, title, text, to) =>
    notify.sendMailVia(channel, title, text, to, { ca });

  beforeAll(async () => {
    const keyFile = join(work, "smtp.key");
    const certFile = join(work, "smtp.pem");
    execFileSync(
      "openssl",
      [
        "req",
        "-x509",
        "-newkey",
        "ec",
        "-pkeyopt",
        "ec_paramgen_curve:prime256v1",
        "-nodes",
        "-days",
        "1",
        "-subj",
        "/CN=127.0.0.1",
        "-addext",
        "subjectAltName=IP:127.0.0.1",
        "-keyout",
        keyFile,
        "-out",
        certFile,
      ],
      { stdio: "ignore" },
    );
    ca = readFileSync(certFile, "utf8");
    smtp = await startSmtp(readFileSync(keyFile, "utf8"), ca);
    const vaultKey = join(work, "vault.pem");
    writeFileSync(vaultKey, generateVaultKeyPair().privateKeyPem, { mode: 0o600 });
    t = await createTestDatabase(adminUrl as string, "worker_user_notify");
    Object.assign(process.env, {
      DATABASE_URL: t.url,
      GARNETOPS_VAULT_PRIVATE_KEY_FILE: vaultKey,
      GARNETOPS_GRYPE_BIN: "unused",
      GARNETOPS_GRYPE_DB_DIR: work,
      PUBLIC_URL: "https://garnetops.example.test/",
    });
    await t.db.insert(schema.organization).values([
      { id: ORG, name: "Example Org" },
      { id: OTHER, name: "Other Org" },
    ]);
    for (const [id, role, org, locale] of [
      ["u_owner", "owner", ORG, null],
      ["u_admin", "admin", ORG, "de"],
      ["u_member", "member", ORG, null],
      ["u_viewer", "viewer", ORG, null],
      ["u_stranger", "owner", OTHER, null],
    ] as const) {
      await t.db.insert(schema.user).values({ id, name: id, email: `${id}@example.test`, locale });
      await t.db.insert(schema.membership).values({ organizationId: org, userId: id, role });
    }
    await t.db.insert(schema.repository).values({
      id: "repo_1",
      organizationId: ORG,
      name: "billing-portal",
      url: "https://git.example.test/billing.git",
      authKind: "none",
      ownerUserId: "u_member",
    });
    mod = await import("./user-notify.ts");
    notify = await import("./notify.ts");
    px = await import("./proxmox.ts");
    for (const level of ["error", "warn"] as const) vi.spyOn(console, level).mockImplementation(() => {});
  }, 60_000);

  afterAll(async () => {
    vi.restoreAllMocks();
    smtp?.server.close();
    await (await import("./db.ts")).pool.end().catch(() => {});
    await t?.drop();
  });

  beforeEach(async () => {
    await t.pool.query(
      "truncate user_notification, notification_preference, notification_channel restart identity cascade",
    );
  });

  describe("events", () => {
    it("tell everyone by role: scans and gates reach viewers, failed scans start at the member", async () => {
      await mod.tellAboutScan(scanResult(["finding.new_critical", "gate.blocked", "scan.failed"]));
      expect(await titles("u_viewer")).toEqual(["findingNewCritical", "gateBlocked"]);
      expect(await titles("u_member")).toEqual(["findingNewCritical", "gateBlocked", "scanFailed"]);
      expect(await titles("u_owner")).toEqual(["findingNewCritical", "gateBlocked", "scanFailed"]);
      expect(await titles("u_stranger")).toEqual([]);
      const [critical] = await forUser("u_viewer");
      expect(critical).toMatchObject({
        event: "finding.new_critical",
        params: { repository: "billing-portal", critical: 2, knownExploited: 1 },
        link: "/repositories/repo_1",
        inApp: true,
        mailState: "none",
      });
      // Summary and link only: nothing from the scan's findings can be in a row.
      expect(JSON.stringify(await rows())).not.toMatch(/CVE-|GHSA-|lodash/);
    });

    it("follow the person's choices: off in the app, and only repositories I added", async () => {
      await t.db.insert(schema.notificationPreference).values([
        { organizationId: ORG, userId: "u_viewer", event: "gate.blocked", inApp: false, email: false },
        {
          organizationId: ORG,
          userId: "u_admin",
          event: "gate.blocked",
          inApp: true,
          email: false,
          scope: "mine",
        },
      ]);
      await mod.tellAboutScan(scanResult(["gate.blocked"]));
      expect(await titles("u_viewer")).toEqual([]);
      expect(await titles("u_admin")).toEqual([]); // the repository is the member's
      expect(await titles("u_member")).toEqual(["gateBlocked"]);
      expect(await titles("u_owner")).toEqual(["gateBlocked"]);
      await mod.tellAboutScan(scanResult(["gate.blocked"], "u_admin"));
      expect(await titles("u_admin")).toEqual(["gateBlocked"]);
    });

    it("tell the requester and the repository's owner about a fix pull request, not everyone", async () => {
      await mod.tellAboutFixPr(
        { organizationId: ORG, repositoryId: "repo_1", requestedBy: "u_admin" },
        "fixPrMerged",
      );
      expect((await rows()).map((r) => r.userId).sort()).toEqual(["u_admin", "u_member"]);
      expect((await rows())[0]).toMatchObject({ event: "fix_pr.merged", link: "/fixes?view=prs" });
      await mod.tellAboutFixPr(
        { organizationId: ORG, repositoryId: "repo_1", requestedBy: null },
        "fixPrFailed",
      );
      // A repository of another organisation, or a missing one, tells nobody.
      await mod.tellAboutFixPr(
        { organizationId: OTHER, repositoryId: "repo_1", requestedBy: null },
        "fixPrFailed",
      );
      await mod.tellAboutFixPr(
        { organizationId: ORG, repositoryId: "repo_gone", requestedBy: null },
        "fixPrFailed",
      );
      expect((await rows()).filter((r) => r.titleKey === "fixPrFailed").map((r) => r.userId)).toEqual([
        "u_member",
      ]);
    });

    it("tell owners and admins once when a Proxmox VE certificate changes", async () => {
      await t.db.insert(schema.proxmoxCluster).values({
        id: "pxc_1",
        organizationId: ORG,
        name: "Lab cluster",
        apiUrl: "https://pve.example.lan:8006",
        host: "pve.example.lan",
        tokenId: "garnetops@pve!inventory",
        certStatus: "confirmed",
        certFingerprint: "AA:AA",
      });
      const load = async () => {
        const [row] = await t.db
          .select()
          .from(schema.proxmoxCluster)
          .where(eq(schema.proxmoxCluster.id, "pxc_1"));
        return row as NonNullable<typeof row>;
      };
      const seen = {
        fingerprint: "BB:BB",
        subject: "CN=pve.example.lan",
        issuer: "CN=pve.example.lan",
        validFrom: T0,
        validTo: new Date(T0.getTime() + 86_400_000),
        caTrusted: false,
      };
      await px.applyObservedCertificate(await load(), seen);
      expect((await rows()).map((r) => r.userId).sort()).toEqual(["u_admin", "u_owner"]);
      expect((await rows())[0]).toMatchObject({
        titleKey: "certificateChangedProxmox",
        params: { name: "Lab cluster" },
        link: "/settings?section=proxmox",
      });
      // The same certificate again is not news; another one is.
      await px.applyObservedCertificate(await load(), seen);
      expect(await rows()).toHaveLength(2);
      await px.applyObservedCertificate(await load(), { ...seen, fingerprint: "CC:CC" });
      expect(await rows()).toHaveLength(4);
    });

    it("never fail the work they report", async () => {
      await expect(
        mod.tellUsers({ organizationId: ORG, titleKey: "scanFailed", link: "https://evil.example/" }),
      ).resolves.toBeUndefined();
      await expect(
        mod.tellUsers({ organizationId: ORG, titleKey: "nope" as never, link: "/" }),
      ).resolves.toBeUndefined();
      expect(await rows()).toHaveLength(0);
    });

    it("have a sentence in both languages for every title key", async () => {
      const { TITLE_EVENTS } = await import("@garnetops/core/user-notifications");
      const { renderNotificationItem } = await import("@garnetops/i18n");
      for (const key of Object.keys(TITLE_EVENTS)) {
        for (const language of ["en", "de"] as const) {
          const { title, text } = renderNotificationItem(language, key, {});
          expect(title, `${language} ${key}`).not.toBe(
            language === "en" ? "Notification" : "Benachrichtigung",
          );
          expect(text.length).toBeGreaterThan(0);
        }
      }
    });
  });

  describe("personal mail", () => {
    it("goes to the person's own address only, through the organisation's mail channel, as summary and link", async () => {
      await smtpChannel();
      await wantMail("u_owner", "scan.failed");
      await mod.tellAboutScan(scanResult(["scan.failed"]), viaFakeSmtp);
      expect(smtp.mails).toHaveLength(1);
      const mail = smtp.mails.at(-1) as Mail;
      // Quoted-printable soft line breaks are not part of the text.
      const text = mail.data.replace(/=\r\n/g, "");
      expect(mail.to).toEqual(["u_owner@example.test"]);
      expect(mail.from).toBe("noreply@example.test");
      expect(text).toContain("Subject: Scan failed: billing-portal");
      expect(text).toContain("https://garnetops.example.test/repositories/repo_1");
      expect(text).toContain("Account, Notifications");
      expect(text).not.toContain("ops-list@example.test");
      expect(text).not.toMatch(/CVE-|GHSA-/);
      const [row] = await forUser("u_owner");
      expect(row).toMatchObject({ inApp: true, mailState: "sent" });
      expect(row?.mailedAt).not.toBeNull();
      // Everyone else keeps in-app only.
      expect((await forUser("u_member"))[0]?.mailState).toBe("none");
    });

    it("is written in the person's language", async () => {
      await smtpChannel();
      await wantMail("u_admin", "scan.failed");
      const before = smtp.mails.length;
      await mod.tellAboutScan(scanResult(["scan.failed"]), viaFakeSmtp);
      const mail = smtp.mails.at(-1) as Mail;
      expect(smtp.mails.length).toBe(before + 1);
      expect(mail.to).toEqual(["u_admin@example.test"]);
      expect(mail.data).toContain("Subject: Scan fehlgeschlagen: billing-portal");
    });

    it("sends at most one mail per event type every 15 minutes and a digest afterwards", async () => {
      await smtpChannel();
      await wantMail("u_owner", "scan.failed");
      const sent: { to: string[]; subject: string; text: string }[] = [];
      const send: import("./user-notify.ts").MailSender = async (_channel, subject, text, to) => {
        sent.push({ to, subject, text });
      };
      await mod.tellAboutScan(scanResult(["scan.failed"]), send);
      expect(sent).toHaveLength(1);
      // Three more within the interval: waiting, not sent.
      for (const name of ["a", "b", "c"]) {
        await mod.tellUsers(
          {
            organizationId: ORG,
            titleKey: "scanFailed",
            params: { repository: `repo-${name}` },
            link: "/repositories/repo_1",
          },
          send,
        );
      }
      expect(sent).toHaveLength(1);
      expect((await forUser("u_owner")).filter((r) => r.mailState === "pending")).toHaveLength(3);

      const sentAt = (await forUser("u_owner"))[0]?.mailedAt as Date;
      // Not yet: 14 minutes later.
      expect(
        await mod.sendPersonalMail({
          send,
          now: () => new Date(sentAt.getTime() + MAIL_MIN_INTERVAL_MS - 60_000),
        }),
      ).toBe(0);
      // Then one digest for all three.
      expect(
        await mod.sendPersonalMail({
          send,
          now: () => new Date(sentAt.getTime() + MAIL_MIN_INTERVAL_MS + 1000),
        }),
      ).toBe(1);
      expect(sent).toHaveLength(2);
      expect(sent[1]?.to).toEqual(["u_owner@example.test"]);
      expect(sent[1]?.subject).toBe("GarnetOps: 3 new notifications");
      for (const name of ["a", "b", "c"]) expect(sent[1]?.text).toContain(`- Scan failed: repo-${name}`);
      expect(sent[1]?.text).toContain("https://garnetops.example.test/");
      expect((await forUser("u_owner")).every((r) => r.mailState === "sent")).toBe(true);
      // Nothing is sent twice.
      expect(
        await mod.sendPersonalMail({
          send,
          now: () => new Date(sentAt.getTime() + 10 * MAIL_MIN_INTERVAL_MS),
        }),
      ).toBe(0);
    });

    it("limits per event type, not overall", async () => {
      await smtpChannel();
      await wantMail("u_owner", "scan.failed");
      await wantMail("u_owner", "gate.blocked");
      const sent: string[] = [];
      const send: import("./user-notify.ts").MailSender = async (_c, subject) => {
        sent.push(subject);
      };
      await mod.tellAboutScan(scanResult(["scan.failed", "gate.blocked"]), send);
      expect(sent.sort()).toEqual(["Quality gate blocked: billing-portal", "Scan failed: billing-portal"]);
    });

    it("needs the person to want it: no mail by default", async () => {
      await smtpChannel();
      const send = vi.fn(async () => {});
      await mod.tellAboutScan(scanResult(["scan.failed"]), send);
      expect(send).not.toHaveBeenCalled();
      expect((await rows()).every((r) => r.mailState === "none")).toBe(true);
    });

    it("is dropped without a mail channel, for a person who left, and after a day", async () => {
      const send = vi.fn(async () => {});
      // No channel at all: the choice is not even queued.
      await wantMail("u_owner", "scan.failed");
      await mod.tellAboutScan(scanResult(["scan.failed"]), send);
      expect((await forUser("u_owner"))[0]?.mailState).toBe("none");

      // A channel that disappears after the mail was queued.
      await smtpChannel();
      await mod.tellAboutScan(scanResult(["scan.failed"]), async () => {
        throw new Error("queued only");
      });
      await t.pool.query("update user_notification set mail_state = 'pending', mailed_at = null");
      await t.pool.query("delete from notification_channel");
      expect(await mod.sendPersonalMail({ send })).toBe(0);
      expect((await forUser("u_owner")).every((r) => r.mailState === "skipped")).toBe(true);

      // A person who left the organisation.
      await smtpChannel();
      await t.pool.query("update user_notification set mail_state = 'pending' where user_id = 'u_owner'");
      await t.pool.query("delete from membership where user_id = 'u_owner'");
      expect(await mod.sendPersonalMail({ send })).toBe(0);
      expect((await forUser("u_owner")).every((r) => r.mailState === "skipped")).toBe(true);
      await t.db.insert(schema.membership).values({ organizationId: ORG, userId: "u_owner", role: "owner" });

      // Too old to be of use.
      await t.pool.query(
        "update user_notification set mail_state = 'pending', created_at = now() - interval '25 hours' where user_id = 'u_owner'",
      );
      expect(await mod.sendPersonalMail({ send })).toBe(0);
      expect((await forUser("u_owner")).every((r) => r.mailState === "skipped")).toBe(true);
      expect(send).not.toHaveBeenCalled();
      expect(MAIL_MAX_AGE_MS).toBe(24 * 3600_000);
    });

    it("uses the first enabled mail channel only and ignores webhooks and disabled channels", async () => {
      await wantMail("u_owner", "scan.failed");
      await t.db.insert(schema.notificationChannel).values([
        {
          id: "nch_hook",
          organizationId: ORG,
          name: "Chat",
          kind: "webhook",
          format: "slack",
          events: ["scan.failed"],
          config: { host: "chat.example.test" },
        },
        {
          id: "nch_off",
          organizationId: ORG,
          name: "Off",
          kind: "graph",
          events: ["scan.failed"],
          enabled: false,
          config: { tenantId: "t", clientId: "c", from: "x@example.test", to: [] },
        },
      ]);
      const used: string[] = [];
      const send: import("./user-notify.ts").MailSender = async (channel) => {
        used.push(channel.id);
      };
      await mod.tellAboutScan(scanResult(["scan.failed"]), send);
      expect(used).toEqual([]); // no usable mail channel: nothing queued
      await smtpChannel();
      await mod.tellAboutScan(scanResult(["scan.failed"]), send);
      expect(used).toEqual(["nch_mail"]);
    });

    it("marks a failed mail and keeps the notification in the app", async () => {
      await smtpChannel();
      await wantMail("u_owner", "scan.failed");
      await mod.tellAboutScan(scanResult(["scan.failed"]), async () => {
        throw new notify.DeliveryError("SMTP 421");
      });
      const [row] = await forUser("u_owner");
      expect(row).toMatchObject({ inApp: true, mailState: "failed", mailedAt: null });
      // A failure is not retried by the next sweep.
      const send = vi.fn(async () => {});
      expect(await mod.sendPersonalMail({ send })).toBe(0);
      expect(send).not.toHaveBeenCalled();
    });

    it("keeps a mail-only choice out of the app", async () => {
      await smtpChannel();
      await t.db
        .insert(schema.notificationPreference)
        .values({ organizationId: ORG, userId: "u_owner", event: "scan.failed", inApp: false, email: true });
      const sent: string[] = [];
      await mod.tellAboutScan(scanResult(["scan.failed"]), async (_c, subject) => {
        sent.push(subject);
      });
      expect(sent).toEqual(["Scan failed: billing-portal"]);
      const [row] = await forUser("u_owner");
      expect(row).toMatchObject({ inApp: false, mailState: "sent" });
      expect(row?.readAt).not.toBeNull();
    });
  });

  describe("rendering", () => {
    it("shows names as plain text and keeps digests short", () => {
      const one = mod.renderPersonalMail(
        [
          {
            titleKey: "scanFailed",
            params: { repository: "<b>x</b> {organization}" },
            link: "/repositories/repo_1",
          },
        ],
        "en",
        "Example Org",
        "https://garnetops.example.test",
      );
      expect(one.subject).toBe("Scan failed: <b>x</b> {organization}");
      expect(one.text).toContain("https://garnetops.example.test/repositories/repo_1");
      const many = mod.renderPersonalMail(
        Array.from({ length: 25 }, (_, i) => ({
          titleKey: "scanFailed",
          params: { repository: `r${i}` },
          link: "/",
        })),
        "en",
        "Example Org",
        "https://garnetops.example.test",
      );
      expect(many.subject).toBe("GarnetOps: 25 new notifications");
      expect(many.text.split("\n").filter((l) => l.startsWith("- "))).toHaveLength(20);
      expect(many.text).toContain("… and 5 more");
    });
  });
});
