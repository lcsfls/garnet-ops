/**
 * The migration of ADR 0025 (0024_focus_developer_pipeline) against a real PostgreSQL: it applies every
 * earlier migration, fills the database with data of the removed modules and of the modules that stay,
 * applies 0024 and checks that exactly the data of the removed modules is gone, secrets included.
 */
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { createDb } from "./index.ts";
import { devDatabaseUrl } from "./testing.ts";

const adminUrl = devDatabaseUrl();
const folder = fileURLToPath(new URL("../drizzle/", import.meta.url));
const LAST = "0024_focus_developer_pipeline";

interface Journal {
  entries: { tag: string }[];
}

const statementsOf = (tag: string) =>
  readFileSync(`${folder}${tag}.sql`, "utf8")
    .split("--> statement-breakpoint")
    .map((s) => s.trim())
    .filter(Boolean);

describe.skipIf(!adminUrl)("migration 0024: focus on the developer pipeline", () => {
  const name = `garnetops_focus_${process.pid}`;
  let admin: ReturnType<typeof createDb>;
  let conn: ReturnType<typeof createDb>;

  const count = async (table: string, where = "true") =>
    Number(
      (
        (await conn.pool.query(`select count(*)::int as n from ${table} where ${where}`)).rows[0] as {
          n: number;
        }
      ).n,
    );

  beforeAll(async () => {
    admin = createDb(adminUrl as string, { max: 1 });
    await admin.pool.query(`drop database if exists ${name} with (force)`);
    await admin.pool.query(`create database ${name}`);
    const url = new URL(adminUrl as string);
    url.pathname = `/${name}`;
    conn = createDb(url.toString(), { max: 2 });

    const journal = JSON.parse(readFileSync(`${folder}meta/_journal.json`, "utf8")) as Journal;
    const tags = journal.entries.map((e) => e.tag);
    const at = tags.indexOf(LAST);
    expect(at).toBeGreaterThan(-1);
    // Everything before this migration, as an installation of 0.0.3 has it.
    for (const tag of tags.slice(0, at))
      for (const statement of statementsOf(tag)) await conn.pool.query(statement);

    const q = (text: string, values: unknown[] = []) => conn.pool.query(text, values);
    await q(`insert into organization (id, name) values ('org_1', 'Example')`);
    await q(`insert into "user" (id, name, email) values ('usr_1', 'Example User', 'user@example.com')`);
    const purposes = [
      "host-ssh-key",
      "proxmox-token",
      "unifi-api-key",
      "unifi-ips-password",
      "wazuh-api-password",
      "wazuh-indexer-password",
      "osint-api-key",
      "netbird-token",
      "forge-token",
      "ssh-private-key",
      "ai-api-key",
      "smtp-password",
      "webhook-url",
      "graph-client-secret",
      "forge-write-token",
      "ldap-bind-password",
      "ldap-user-password",
    ];
    for (const [i, purpose] of purposes.entries()) {
      await q(
        `insert into secret (id, organization_id, purpose, sealed, vault_key_id) values ($1, 'org_1', $2, '{}'::jsonb, 'key_1')`,
        [`sec_${i}`, purpose],
      );
    }
    await q(
      `insert into host (id, organization_id, name, address) values ('host_1', 'org_1', 'web', 'web.example.lan')`,
    );
    await q(
      `insert into attack_osint_result (id, organization_id, provider, ip, score, reports, checked_at) values ('osint_1', 'org_1', 'abuseipdb', '198.51.100.7', 90, 3, now())`,
    );
    await q(
      `insert into geoip_dataset (id, kind, state, source, dataset_month, row_count) values ('geo_1', 'country', 'active', 'import', '2026-10', 10)`,
    );
    const events: [string, string][] = [
      ["finding.new_critical", "findingNewCritical"],
      ["infra.certificate_changed", "certificateChangedDirectory"],
      ["infra.certificate_changed", "certificateChangedProxmox"],
      ["infra.certificate_changed", "certificateChangedXdr"],
      ["infra.host_key_changed", "hostKeyChanged"],
      ["infra.sync_blocked", "syncBlockedProxmox"],
      ["unifi.device_offline", "unifiDeviceOffline"],
      ["exposure.new_open_port", "exposureNewOpenPort"],
    ];
    for (const [event, titleKey] of events) {
      await q(
        `insert into user_notification (user_id, organization_id, event, title_key, link) values ('usr_1', 'org_1', $1, $2, '/')`,
        [event, titleKey],
      );
    }
    for (const event of [
      "finding.new_critical",
      "infra.certificate_changed",
      "infra.host_key_changed",
      "unifi.device_offline",
    ]) {
      await q(
        `insert into notification_preference (organization_id, user_id, event, in_app, email) values ('org_1', 'usr_1', $1, true, false)`,
        [event],
      );
    }
    await q(`insert into audit_log (organization_id, action) values ('org_1', 'host.create')`);

    for (const statement of statementsOf(LAST)) await q(statement);
  }, 120_000);

  afterAll(async () => {
    await conn?.pool.end();
    // pool.end() resolves before every socket has closed; dropping with force right away would end those
    // sockets and surface as unhandled errors (see testing.ts), so wait for them.
    for (let attempt = 0; attempt < 50; attempt++) {
      const dropped = await admin?.pool.query(`drop database if exists ${name}`).then(
        () => true,
        () => false,
      );
      if (dropped) break;
      await new Promise((resolve) => setTimeout(resolve, 100));
    }
    await admin?.pool.query(`drop database if exists ${name} with (force)`);
    await admin?.pool.end();
  });

  it("deletes the rows of the removed modules, stored addresses included", async () => {
    expect(await count("host")).toBe(0);
    expect(await count("attack_osint_result")).toBe(0);
    expect(await count("geoip_dataset")).toBe(0);
  });

  it("deletes the sealed secrets of the removed modules and keeps every other one", async () => {
    const left = (await conn.pool.query(`select purpose from secret order by purpose`)).rows.map(
      (r: { purpose: string }) => r.purpose,
    );
    expect(left).toEqual([
      "ai-api-key",
      "forge-token",
      "forge-write-token",
      "graph-client-secret",
      "ldap-bind-password",
      "ldap-user-password",
      "smtp-password",
      "ssh-private-key",
      "webhook-url",
    ]);
  });

  it("deletes notifications and preferences of removed event types and keeps the directory's", async () => {
    const kept = (
      await conn.pool.query(`select title_key from user_notification order by title_key`)
    ).rows.map((r: { title_key: string }) => r.title_key);
    expect(kept).toEqual(["certificateChangedDirectory", "findingNewCritical"]);
    const prefs = (
      await conn.pool.query(`select event from notification_preference order by event`)
    ).rows.map((r: { event: string }) => r.event);
    expect(prefs).toEqual(["finding.new_critical", "infra.certificate_changed"]);
  });

  it("keeps old audit entries and records the removal once per organisation", async () => {
    expect(await count("audit_log", "action = 'host.create'")).toBe(1);
    expect(await count("audit_log", "action = 'system.modules_removed' and organization_id = 'org_1'")).toBe(
      1,
    );
  });

  it("drops no table: the structures stay until 1.0", async () => {
    for (const table of [
      "host",
      "host_finding",
      "proxmox_cluster",
      "unifi_connection",
      "wazuh_connection",
      "exposure_asset",
      "geoip_dataset",
      "attack_settings",
    ]) {
      expect(await count(table)).toBe(0);
    }
  });
});
