/**
 * Wazuh (ADR 0015): input validation, the request allow-lists, the indexer query templates,
 * the level to severity mapping, the parsers against synthetic fixtures of Wazuh 4.12 and 5.0
 * (example names, documentation address ranges) and against hostile answers, the privilege
 * check and the suggestion of a server for an agent.
 */
import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import {
  ADAPTERS,
  AGENT_SELECT,
  ATTACK_GROUPS,
  adapterFor,
  agentsQuery,
  buildIndexerRequest,
  checkCaPem,
  checkDashboardUrl,
  checkEnrollmentHost,
  checkWazuhUrl,
  checkWazuhUsername,
  extraIndexerPrivileges,
  extraManagerPrivileges,
  isIndexerRequestAllowed,
  isManagerRequestAllowed,
  parseAgents,
  parseAlertStats,
  parseApiInfo,
  parseFimEvents,
  parseIndexerInfo,
  parseLoginToken,
  parsePreviousStats,
  parseVulnerabilityStats,
  parseWazuhSourceRef,
  privilegesAcknowledged,
  readSnapshot,
  severityForLevel,
  suggestHost,
  sumVulnerabilities,
  WAZUH_INDEXER_PORT,
  WAZUH_MANAGER_PORT,
  WAZUH_PASSWORD_PATTERN,
  WINDOWS,
  wazuhSourceRef,
} from "./wazuh.ts";

const fixtures = new URL("../test/fixtures/wazuh/", import.meta.url);
const load = (set: "wazuh4" | "wazuh5", name: string): unknown =>
  JSON.parse(readFileSync(new URL(`${set}/${name}.json`, fixtures), "utf8"));

describe("addresses", () => {
  it("accepts https with the default port of each endpoint", () => {
    expect(checkWazuhUrl("https://wazuh.example.lan", WAZUH_MANAGER_PORT)).toEqual({
      ok: true,
      url: "https://wazuh.example.lan:55000",
      host: "wazuh.example.lan",
      port: 55000,
    });
    expect(checkWazuhUrl("https://192.0.2.50", WAZUH_INDEXER_PORT)).toMatchObject({
      ok: true,
      url: "https://192.0.2.50:9200",
    });
    expect(checkWazuhUrl("https://[2001:db8::5]:9201/", WAZUH_INDEXER_PORT)).toMatchObject({
      ok: true,
      url: "https://[2001:db8::5]:9201",
    });
  });

  it.each([
    ["", "empty"],
    ["http://wazuh.example.lan:55000", "notHttps"],
    ["wazuh.example.lan", "notHttps"],
    ["https://user:pw@wazuh.example.lan", "credentials"],
    ["https://wazuh.example.lan/agents", "path"],
    ["https://wazuh.example.lan/?a=1", "path"],
    ["https://wazuh.example.lan/#x", "path"],
    ["https://127.0.0.1:55000", "address"],
    ["https://127.1", "address"],
    ["https://localhost", "address"],
    ["https://169.254.169.254", "address"],
    ["https://0.0.0.0", "address"],
    ["https://[::1]", "address"],
    ["https://wazuh.example.lan:99999", "invalid"],
    [`https://${"a".repeat(300)}.example.lan`, "tooLong"],
  ])("refuses %s", (value, problem) => {
    expect(checkWazuhUrl(value, 55000)).toEqual({ ok: false, problem });
  });

  it("accepts private addresses, because Wazuh lives there", () => {
    expect(checkWazuhUrl("https://10.1.2.3:55000", 55000)).toMatchObject({ ok: true });
    expect(checkWazuhUrl("https://192.168.5.5", 55000)).toMatchObject({ ok: true });
  });

  it("checks the dashboard link: http(s) only, no credentials, no script schemes", () => {
    expect(checkDashboardUrl("https://dashboard.example.lan/app/wz-home")).toEqual({
      ok: true,
      url: "https://dashboard.example.lan/app/wz-home",
    });
    for (const bad of [
      "javascript:alert(1)",
      "data:text/html,<script>1</script>",
      "ftp://dashboard.example.lan",
      "https://user:pw@dashboard.example.lan",
      "https://dashboard.example.lan/#frag",
      "https://dash board.example.lan",
      "https://dashboard.example.lan/<x>",
      "",
    ]) {
      expect(checkDashboardUrl(bad), bad).toEqual({ ok: false });
    }
  });

  it("accepts a host name or address for agents, nothing with shell characters", () => {
    expect(checkEnrollmentHost("Wazuh.Example.LAN")).toEqual({ ok: true, value: "wazuh.example.lan" });
    expect(checkEnrollmentHost("192.0.2.5")).toEqual({ ok: true, value: "192.0.2.5" });
    expect(checkEnrollmentHost("2001:db8::1")).toEqual({ ok: true, value: "2001:db8::1" });
    for (const bad of [
      "",
      "a b",
      "host;rm -rf /",
      "host$(id)",
      "host`id`",
      "'quoted'",
      'a"b',
      "host.example.lan:1515",
      "-leading.example.lan",
      "x".repeat(254),
      "host\nexample",
      "../etc",
    ]) {
      expect(checkEnrollmentHost(bad), bad).toEqual({ ok: false });
    }
  });
});

describe("credentials", () => {
  it("refuses the default administrative accounts as service users", () => {
    for (const name of ["admin", "Admin", "wazuh", "wazuh-wui", "kibanaserver"]) {
      expect(checkWazuhUsername(name)).toEqual({ ok: false, problem: "privileged" });
    }
    expect(checkWazuhUsername("garnetops-ro")).toEqual({ ok: true, value: "garnetops-ro" });
    expect(checkWazuhUsername("gar net")).toEqual({ ok: false, problem: "invalid" });
    expect(checkWazuhUsername("")).toEqual({ ok: false, problem: "invalid" });
  });

  it("checks the password for length and control characters only", () => {
    expect(WAZUH_PASSWORD_PATTERN.test("short")).toBe(false);
    expect(WAZUH_PASSWORD_PATTERN.test("a long enough passphrase with Ünicode")).toBe(true);
    expect(WAZUH_PASSWORD_PATTERN.test("abcdefgh\nijkl")).toBe(false);
    expect(WAZUH_PASSWORD_PATTERN.test("x".repeat(201))).toBe(false);
  });
});

describe("custom certificate authority", () => {
  const block = (body: string) => `-----BEGIN CERTIFICATE-----\n${body}\n-----END CERTIFICATE-----`;
  it("accepts certificate blocks only", () => {
    const ok = checkCaPem(`${block("MIIBxx==")}\n\n${block("MIIByy==")}`, () => true);
    expect(ok).toMatchObject({ ok: true, count: 2 });
  });
  it("refuses a private key, other text, too many blocks and unparsable certificates", () => {
    expect(checkCaPem("-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----", () => true)).toEqual({
      ok: false,
    });
    expect(checkCaPem(`${block("MIIBxx==")}\nnotes: my key`, () => true)).toEqual({ ok: false });
    expect(checkCaPem(Array.from({ length: 6 }, () => block("MIIBxx==")).join("\n"), () => true)).toEqual({
      ok: false,
    });
    expect(checkCaPem(block("MIIBxx=="), () => false)).toEqual({ ok: false });
    expect(checkCaPem("", () => true)).toEqual({ ok: false });
    expect(checkCaPem(block("A".repeat(30_000)), () => true)).toEqual({ ok: false });
  });
});

describe("rule level to severity (documented mapping)", () => {
  it.each([
    [0, null],
    [-1, null],
    [Number.NaN, null],
    [1, "low"],
    [5, "low"],
    [6, "medium"],
    [8, "medium"],
    [9, "high"],
    [11, "high"],
    [12, "critical"],
    [15, "critical"],
    [16, "critical"],
  ])("level %s is %s", (level, severity) => {
    expect(severityForLevel(level)).toBe(severity);
  });
});

describe("request allow-lists", () => {
  it("lets the manager client log in with POST and read three things with GET", () => {
    expect(isManagerRequestAllowed("POST", "/security/user/authenticate", {})).toBe(true);
    expect(isManagerRequestAllowed("GET", "/", {})).toBe(true);
    expect(isManagerRequestAllowed("GET", "/agents", agentsQuery(0))).toBe(true);
    expect(isManagerRequestAllowed("GET", "/agents", agentsQuery(500))).toBe(true);
    expect(isManagerRequestAllowed("GET", "/security/users/me/policies", {})).toBe(true);
  });

  it("refuses every other method and path of the manager API", () => {
    for (const method of ["PUT", "DELETE", "PATCH", "HEAD", "OPTIONS", "get", "TRACE"]) {
      expect(isManagerRequestAllowed(method, "/agents", agentsQuery(0)), method).toBe(false);
    }
    for (const path of [
      "/agents/001/key",
      "/agents/001",
      "/agents/001/config/syscheck/syscheck",
      "/agents/000/restart",
      "/security/users",
      "/security/roles",
      "/security/user/authenticate/run_as",
      "/security/users/me",
      "/active-response",
      "/manager/configuration",
      "/manager/files",
      "/cluster/nodes",
      "/logtest",
      "/agents?x=1",
      "/agents/",
      "//agents",
      "/syscollector/001/packages",
    ]) {
      expect(isManagerRequestAllowed("GET", path, {}), path).toBe(false);
    }
    // The login is POST only; reading it with GET or adding a query is refused.
    expect(isManagerRequestAllowed("GET", "/security/user/authenticate", {})).toBe(false);
    expect(isManagerRequestAllowed("POST", "/security/user/authenticate", { raw: "true" })).toBe(false);
    expect(isManagerRequestAllowed("POST", "/agents", {})).toBe(false);
    expect(isManagerRequestAllowed("POST", "/", {})).toBe(false);
  });

  it("refuses queries that are not the fixed agent list query", () => {
    expect(isManagerRequestAllowed("GET", "/agents", { ...agentsQuery(0), select: "id,key" })).toBe(false);
    expect(isManagerRequestAllowed("GET", "/agents", { ...agentsQuery(0), limit: "100000" })).toBe(false);
    expect(isManagerRequestAllowed("GET", "/agents", { ...agentsQuery(0), q: "id!=000" })).toBe(false);
    expect(isManagerRequestAllowed("GET", "/agents", { ...agentsQuery(0), offset: "1;drop" })).toBe(false);
    expect(isManagerRequestAllowed("GET", "/", { pretty: "true" })).toBe(false);
  });

  it("never selects secrets from the agent list", () => {
    expect(AGENT_SELECT.split(",")).not.toContain("key");
    expect(AGENT_SELECT).not.toMatch(/key|secret|password/i);
  });

  it("clamps the agent list offset to a number", () => {
    expect(agentsQuery(-5).offset).toBe("0");
    expect(agentsQuery(1.5).offset).toBe("0");
    expect(agentsQuery(Number.NaN).offset).toBe("0");
    expect(agentsQuery(1000).offset).toBe("1000");
  });

  it("lets the indexer client read three GET paths and POST search or count on two indices", () => {
    expect(isIndexerRequestAllowed("GET", "/", {})).toBe(true);
    expect(isIndexerRequestAllowed("GET", "/_plugins/_security/authinfo", {})).toBe(true);
    expect(isIndexerRequestAllowed("GET", "/_plugins/_security/api/permissionsinfo", {})).toBe(true);
    expect(isIndexerRequestAllowed("POST", "/wazuh-alerts-*/_search", {})).toBe(true);
    expect(isIndexerRequestAllowed("POST", "/wazuh-alerts-*/_count", {})).toBe(true);
    expect(isIndexerRequestAllowed("POST", "/wazuh-states-vulnerabilities-*/_search", {})).toBe(true);
  });

  it("refuses everything else on the indexer", () => {
    for (const [method, path] of [
      ["PUT", "/wazuh-alerts-*/_doc/1"],
      ["DELETE", "/wazuh-alerts-*"],
      ["DELETE", "/_all"],
      ["POST", "/wazuh-alerts-*/_delete_by_query"],
      ["POST", "/wazuh-alerts-*/_update_by_query"],
      ["POST", "/wazuh-alerts-*/_bulk"],
      ["POST", "/_bulk"],
      ["POST", "/_search"],
      ["POST", "/*/_search"],
      ["POST", "/.opendistro_security/_search"],
      ["POST", "/wazuh-alerts-*,.kibana/_search"],
      ["POST", "/wazuh-states-inventory-*/_search"],
      ["POST", "/wazuh-states-vulnerabilities-*/_count"],
      ["POST", "/_msearch"],
      ["POST", "/_scripts/x"],
      ["POST", "/_plugins/_security/api/internalusers/x"],
      ["GET", "/_cat/indices"],
      ["GET", "/_cluster/settings"],
      ["GET", "/_plugins/_security/api/internalusers"],
      ["GET", "/_plugins/_security/api/roles"],
      ["GET", "/_search"],
      ["GET", "/wazuh-alerts-*/_search"],
      ["PATCH", "/"],
    ] as const) {
      expect(isIndexerRequestAllowed(method, path, {}), `${method} ${path}`).toBe(false);
    }
    expect(isIndexerRequestAllowed("POST", "/wazuh-alerts-*/_search", { scroll: "1m" })).toBe(false);
    expect(isIndexerRequestAllowed("GET", "/", { pretty: "" })).toBe(false);
  });

  it("every template targets an allowed path", () => {
    for (const adapter of Object.values(ADAPTERS)) {
      const requests = [
        buildIndexerRequest(adapter, { kind: "alertsReadable" }),
        buildIndexerRequest(adapter, { kind: "fimLatest" }),
        buildIndexerRequest(adapter, { kind: "vulnerabilityStats" }),
        ...WINDOWS.flatMap((window) => [
          buildIndexerRequest(adapter, { kind: "alertStats", window }),
          buildIndexerRequest(adapter, { kind: "alertStatsPrevious", window }),
        ]),
      ];
      for (const r of requests) expect(isIndexerRequestAllowed(r.method, r.path, {}), r.path).toBe(true);
    }
  });
});

describe("indexer query templates", () => {
  const adapter = ADAPTERS.wazuh4;

  it("take an enumerated window and nothing else: no value of the input ends up in the query", () => {
    // The type system forbids it; this is the runtime guard that a forged value cannot inject DSL.
    const forged = '24h"}},"script":{"source":"1"}' as never;
    // An unknown window has no range, so nothing is built from it: the call throws instead of interpolating.
    expect(() => buildIndexerRequest(adapter, { kind: "alertStats", window: forged })).toThrow(
      "Unknown window",
    );
    expect(() =>
      buildIndexerRequest(adapter, { kind: "alertStatsPrevious", window: "__proto__" as never }),
    ).toThrow();
  });

  it("builds identical bodies for identical questions (no clocks, no randomness)", () => {
    const a = buildIndexerRequest(adapter, { kind: "alertStats", window: "7d" });
    const b = buildIndexerRequest(adapter, { kind: "alertStats", window: "7d" });
    expect(a).toEqual(b);
    expect(JSON.stringify(a.body)).toContain("now-7d");
  });

  it("uses aggregations with small sizes and never asks for raw alert documents in bulk", () => {
    for (const window of WINDOWS) {
      const stats = buildIndexerRequest(adapter, { kind: "alertStats", window });
      expect(stats.body.size).toBe(0);
      expect(stats.body.timeout).toBe("20s");
      const aggs = stats.body.aggs as Record<string, { terms?: { size: number } }>;
      expect(aggs.agents?.terms?.size).toBe(10);
      expect(aggs.tactics?.terms?.size).toBeLessThanOrEqual(20);
      const sources = JSON.stringify(stats.body);
      expect(sources).toContain('"size":100');
      const previous = buildIndexerRequest(adapter, { kind: "alertStatsPrevious", window });
      expect(previous.body.size).toBe(0);
    }
    const fim = buildIndexerRequest(adapter, { kind: "fimLatest" });
    expect(fim.body.size).toBeLessThanOrEqual(25);
    // Only the fields it needs are fetched, not the whole alert with its log line.
    expect(fim.body._source).toEqual([
      "@timestamp",
      "agent.id",
      "agent.name",
      "syscheck.path",
      "syscheck.event",
      "rule.level",
    ]);
    expect(JSON.stringify(fim.body)).not.toContain("full_log");
    expect(buildIndexerRequest(adapter, { kind: "vulnerabilityStats" }).body.size).toBe(0);
  });

  it("looks at the previous period of the same length", () => {
    const previous = buildIndexerRequest(adapter, { kind: "alertStatsPrevious", window: "24h" });
    expect(JSON.stringify(previous.body.query)).toBe(
      JSON.stringify({ bool: { filter: [{ range: { "@timestamp": { gte: "now-48h", lt: "now-24h" } } }] } }),
    );
  });

  it("asks for the attack numbers of the overview with fixed, small aggregations (ADR 0016)", () => {
    const current = buildIndexerRequest(adapter, { kind: "alertStats", window: "7d" }).body;
    const aggs = current.aggs as Record<string, { aggs?: Record<string, unknown> }>;
    expect(Object.keys(aggs.attacks?.aggs ?? {}).sort()).toEqual(["agents", "distinct"]);
    const perIp = ((aggs.sources?.aggs?.ips ?? { aggs: {} }) as { aggs: Record<string, unknown> }).aggs;
    expect(Object.keys(perIp).sort()).toEqual(["agents", "first", "groups", "last"]);
    const previous = buildIndexerRequest(adapter, { kind: "alertStatsPrevious", window: "7d" }).body;
    expect(JSON.stringify(previous.aggs)).toContain('"cardinality":{"field":"data.srcip"}');
    expect(JSON.stringify(previous.query)).toContain("now-14d");
    // Still nothing but an enumerated window goes into a query.
    expect(JSON.stringify(current)).not.toMatch(/script|_delete|_update/);
  });

  it("keeps source addresses of authentication failures and attacks only", () => {
    const body = JSON.stringify(buildIndexerRequest(adapter, { kind: "alertStats", window: "24h" }).body);
    for (const group of ATTACK_GROUPS) expect(body).toContain(group);
    expect(body).toContain("data.srcip");
  });
});

describe("manager answers (Wazuh 4.12 and 5.0)", () => {
  it.each([
    ["wazuh4", "4.12.0", 4, 12, "wazuh4", false],
    ["wazuh5", "5.0.0", 5, 0, "wazuh5", true],
  ] as const)("%s: version, adapter and agents", (set, version, major, minor, adapterId, preview) => {
    const info = parseApiInfo(load(set, "manager-root"));
    expect(info).toEqual({ version, major, minor });
    const adapter = adapterFor(info as NonNullable<typeof info>);
    expect(adapter?.id).toBe(adapterId);
    expect(adapter?.preview).toBe(preview);

    const agents = parseAgents(load(set, "manager-agents"));
    expect(agents.total).toBe(7);
    expect(agents.dropped).toBe(0);
    expect(agents.items.map((a) => a.agentId)).toEqual(["000", "001", "002", "003", "004", "005", "006"]);
    const web = agents.items.find((a) => a.agentId === "001");
    expect(web).toMatchObject({
      name: "web-01",
      ip: "192.0.2.11",
      osName: "Ubuntu",
      osVersion: "22.04.4 LTS",
      osPlatform: "ubuntu",
      arch: "x86_64",
      version,
      status: "active",
      groups: ["default", "web"],
      isManager: false,
    });
    expect(web?.lastKeepAliveAt?.toISOString()).toBe("2026-10-21T07:59:40.000Z");
    expect(agents.items[0]?.isManager).toBe(true);
    // "any" is not an address: the register address is used instead.
    expect(agents.items.find((a) => a.agentId === "005")).toMatchObject({
      ip: "198.51.100.40",
      status: "never_connected",
      lastKeepAliveAt: null,
      osName: null,
    });
    expect(agents.items.find((a) => a.agentId === "003")?.status).toBe("disconnected");
    expect(agents.items.find((a) => a.agentId === "006")?.status).toBe("pending");
  });

  it("recognises only the Wazuh API's root answer", () => {
    expect(parseApiInfo({ data: { api_version: "v4.9.2" } })).toEqual({
      version: "4.9.2",
      major: 4,
      minor: 9,
    });
    expect(parseApiInfo({ data: { api_version: "4.12" } })).toEqual({ version: "4.12", major: 4, minor: 12 });
    expect(parseApiInfo({ data: { api_version: "5.0.0-rc1" } })?.major).toBe(5);
    for (const bad of [
      null,
      "text",
      [],
      {},
      { data: {} },
      { data: { api_version: 4 } },
      { data: { api_version: "latest" } },
      { data: { api_version: "4.12.0; rm -rf" } },
      { version: "7.0" },
    ]) {
      expect(parseApiInfo(bad), JSON.stringify(bad)).toBeNull();
    }
    expect(adapterFor({ version: "3.13.6", major: 3, minor: 13 })).toBeNull();
    expect(adapterFor({ version: "6.0.0", major: 6, minor: 0 })).toBeNull();
  });

  it("reads the login token, and nothing that is not shaped like one", () => {
    const token = parseLoginToken(load("wazuh4", "manager-login"));
    expect(token).toBe("garnetops-test-jwt-aaaaaaaaaaaa.bbbbbbbbbbbb.cccccccccccc");
    for (const bad of [
      null,
      {},
      { data: {} },
      { data: { token: "short" } },
      { data: { token: 42 } },
      { data: { token: "has space in it 12345678" } },
    ]) {
      expect(parseLoginToken(bad), JSON.stringify(bad)).toBeNull();
    }
  });

  it("drops agents that do not fit, keeps the rest, ignores unknown fields", () => {
    const parsed = parseAgents({
      data: {
        affected_items: [
          { id: "001", name: "ok-1", status: "active", surprise: { nested: true } },
          { id: "../../etc", name: "bad-id" },
          { name: "no-id" },
          "not an object",
          null,
          {
            id: "002",
            name: "x".repeat(500),
            ip: "not-an-ip",
            registerIP: "198.51.100.9",
            group: ["fine", "bad group!", 7],
          },
          { id: "003", status: "from-the-future", lastKeepAlive: "9999-12-31T00:00:00Z" },
        ],
        total_affected_items: "7",
      },
    });
    expect(parsed.items.map((a) => a.agentId)).toEqual(["001", "002", "003"]);
    expect(parsed.dropped).toBe(4);
    expect(parsed.total).toBe(7);
    expect(parsed.items[1]?.name).toHaveLength(128);
    expect(parsed.items[1]?.ip).toBe("198.51.100.9");
    expect(parsed.items[1]?.groups).toEqual(["fine"]);
    expect(parsed.items[2]).toMatchObject({ name: "agent-003", status: "unknown", lastKeepAliveAt: null });
  });

  it("strips control and bidirectional characters from names", () => {
    const parsed = parseAgents({ data: { affected_items: [{ id: "001", name: "web\u202e-01\u0000\n" }] } });
    expect(parsed.items[0]?.name).toBe("web-01");
  });

  it("is not fooled by answers that are not a list", () => {
    for (const bad of [
      null,
      "x",
      5,
      [],
      { data: null },
      { data: { affected_items: "no" } },
      { data: { affected_items: { a: 1 } } },
    ]) {
      expect(parseAgents(bad).items, JSON.stringify(bad)).toEqual([]);
    }
  });

  it("caps the number of agents of one page", () => {
    const many = Array.from({ length: 900 }, (_, i) => ({
      id: String(i + 1).padStart(3, "0"),
      name: `a${i}`,
    }));
    const parsed = parseAgents({ data: { affected_items: many, total_affected_items: 900 } });
    expect(parsed.items).toHaveLength(500);
    expect(parsed.dropped).toBe(400);
  });
});

describe("privileges", () => {
  it.each(["wazuh4", "wazuh5"] as const)("%s: a read-only API user has no extra privilege", (set) => {
    expect(extraManagerPrivileges(load(set, "manager-policies-readonly"))).toEqual([]);
  });

  it("lists every allowed action that is not a read, and ignores denied ones", () => {
    expect(extraManagerPrivileges(load("wazuh4", "manager-policies-admin"))).toEqual([
      "api:agent:restart",
      "api:security:create",
    ]);
    expect(extraManagerPrivileges(load("wazuh5", "manager-policies-admin"))).toEqual([
      "api:agent:read_secrets",
      "api:agent:restart",
      "api:security:create",
    ]);
  });

  it("treats read_secrets as a privilege beyond reading, and a wildcard as everything", () => {
    expect(
      extraManagerPrivileges({
        data: { "cluster:read_secrets": { "*:*:*": "allow" }, "*:*": { "*:*:*": "allow" } },
      }),
    ).toEqual(["api:*:*", "api:cluster:read_secrets"]);
  });

  it("does not guess when the answer has another shape", () => {
    for (const bad of [
      null,
      "x",
      [],
      { data: [] },
      { data: { "agent:read": "allow" } },
      { data: { "agent:read": [1] } },
    ]) {
      expect(extraManagerPrivileges(bad), JSON.stringify(bad)).toBeNull();
    }
  });

  it("flags powerful indexer roles and access to the security API", () => {
    expect(
      extraIndexerPrivileges(
        load("wazuh4", "indexer-authinfo-readonly"),
        load("wazuh4", "indexer-permissionsinfo-readonly"),
      ),
    ).toEqual([]);
    expect(
      extraIndexerPrivileges(
        load("wazuh4", "indexer-authinfo-admin"),
        load("wazuh4", "indexer-permissionsinfo-admin"),
      ),
    ).toEqual(["indexer:role:all_access", "indexer:security-api"]);
    expect(extraIndexerPrivileges({ roles: ["ALL_ACCESS"] }, null)).toEqual(["indexer:role:ALL_ACCESS"]);
    expect(extraIndexerPrivileges({}, null)).toBeNull();
    expect(extraIndexerPrivileges(null, null)).toBeNull();
    // Without the permissions answer only the roles count.
    expect(extraIndexerPrivileges({ roles: ["custom"] }, null)).toEqual([]);
  });

  it("an acknowledgement covers exactly the privileges that were shown", () => {
    expect(privilegesAcknowledged([], [])).toBe(true);
    expect(privilegesAcknowledged(["a"], [])).toBe(false);
    expect(privilegesAcknowledged(["a"], ["a", "b"])).toBe(true);
    expect(privilegesAcknowledged(["a", "c"], ["a", "b"])).toBe(false);
  });
});

describe("indexer answers", () => {
  it.each(["wazuh4", "wazuh5"] as const)("%s: identifies the indexer", (set) => {
    expect(parseIndexerInfo(load(set, "indexer-root"))).toBe(set === "wazuh4" ? "7.10.2" : "2.19.1");
    expect(parseIndexerInfo({ version: { number: "7.10.2" } })).toBeNull();
    expect(parseIndexerInfo({ cluster_name: "x", version: { number: "bad version!" } })).toBeNull();
    expect(parseIndexerInfo(null)).toBeNull();
  });

  it("parses alert aggregations into severities, tactics, top agents, file integrity and sources", () => {
    const stats = parseAlertStats(load("wazuh4", "indexer-alerts-24h"));
    expect(stats).not.toBeNull();
    expect(stats?.total).toBe(2056);
    expect(stats?.bySeverity).toEqual({ critical: 6, high: 30, medium: 120, low: 1900 });
    expect(stats?.fim).toBe(18);
    // Hostile or odd tactic names are dropped by the pattern; a made-up but harmless one is kept as text.
    expect(stats?.tactics.map((t) => t.name)).toEqual([
      "Credential Access",
      "Initial Access",
      "Persistence",
      "Defense Evasion",
      "Made Up Tactic From A Custom Rule",
    ]);
    expect(stats?.agents.map((a) => [a.agentId, a.name, a.count])).toEqual([
      ["001", "web-01", 900],
      ["002", "db-01", 640],
      ["003", "app-02.example.lan", 300],
      ["004", "win-fs01", 150],
    ]);
    expect(stats?.sources).toEqual([
      {
        ip: "198.51.100.77",
        count: 55,
        groups: ["authentication_failed", "authentication_failures"],
        firstSeen: new Date("2026-10-21T08:15:00Z"),
        lastSeen: new Date("2026-10-22T07:58:00Z"),
        agents: [
          { agentId: "001", name: "web-01", count: 50 },
          { agentId: "002", name: "db-01", count: 5 },
        ],
      },
      {
        ip: "203.0.113.9",
        count: 22,
        groups: ["web_scan"],
        firstSeen: new Date("2026-10-21T08:15:00Z"),
        lastSeen: new Date("2026-10-22T06:30:00Z"),
        agents: [{ agentId: "001", name: "web-01", count: 22 }],
      },
      {
        ip: "2001:db8::bad",
        count: 3,
        groups: ["invalid_login"],
        // No first time (null), an agent id that is not an id is dropped.
        firstSeen: null,
        lastSeen: new Date("2026-10-21T22:00:00Z"),
        agents: [{ agentId: "003", name: "app-02.example.lan", count: 3 }],
      },
    ]);
  });

  it("parses the attack numbers of a window (ADR 0016)", () => {
    const stats = parseAlertStats(load("wazuh4", "indexer-alerts-24h"));
    expect(stats?.attack).toEqual({
      alerts: 82,
      distinctSources: 5,
      agents: [
        { agentId: "001", name: "web-01", count: 76 },
        { agentId: "002", name: "db-01", count: 5 },
      ],
    });
    // An answer without the aggregation (an older query, a role that cannot read it) has none.
    const aggs = {
      ...(load("wazuh4", "indexer-alerts-24h") as { aggregations: object }).aggregations,
    } as Record<string, unknown>;
    delete aggs.attacks;
    expect(parseAlertStats({ hits: { total: 1 }, aggregations: aggs })?.attack).toBeNull();
  });

  it("parses the previous period's attack numbers and drops entries that are not addresses", () => {
    const previous = parsePreviousStats(load("wazuh4", "indexer-previous-24h"));
    expect(previous?.attack).toEqual({
      alerts: 60,
      distinctSources: 3,
      sources: [
        { ip: "198.51.100.77", count: 40 },
        { ip: "203.0.113.9", count: 15 },
        { ip: "192.0.2.200", count: 5 },
      ],
    });
  });

  it("bounds hostile timestamps, counts and agent entries of the attack aggregations", () => {
    const stats = parseAlertStats({
      hits: { total: 1 },
      aggregations: {
        levels: { buckets: [] },
        sources: {
          ips: {
            buckets: [
              {
                key: "198.51.100.1",
                doc_count: 5,
                first: { value: -5 },
                last: { value: 9e15 },
                agents: {
                  buckets: [
                    { key: "<script>", doc_count: 1 },
                    { key: 7, doc_count: "x", name: { buckets: [{ key: "a\u202eb\nc" }] } },
                  ],
                },
              },
            ],
          },
        },
        attacks: { doc_count: -4, distinct: { value: "many" }, agents: "nope" },
      },
    });
    expect(stats?.sources[0]).toMatchObject({ firstSeen: null, lastSeen: null });
    expect(stats?.sources[0]?.agents).toEqual([{ agentId: "7", name: "ab c", count: 0 }]);
    expect(stats?.attack).toEqual({ alerts: 0, distinctSources: 0, agents: [] });
  });

  it("parses the same aggregations from a 5.x answer", () => {
    const stats = parseAlertStats(load("wazuh5", "indexer-alerts-7d"));
    expect(stats?.total).toBeGreaterThan(0);
    expect(stats?.bySeverity.critical).toBeGreaterThan(0);
  });

  it("parses the previous period", () => {
    const previous = parsePreviousStats(load("wazuh4", "indexer-previous-24h"));
    expect(previous?.total).toBe(1645);
    expect(previous?.bySeverity).toEqual({ critical: 5, high: 24, medium: 96, low: 1520 });
  });

  it("returns null for an answer without aggregations (an error or another index)", () => {
    for (const bad of [
      null,
      {},
      { error: { type: "index_not_found_exception" }, status: 404 },
      { aggregations: {} },
      "x",
    ]) {
      expect(parseAlertStats(bad), JSON.stringify(bad)).toBeNull();
      expect(parsePreviousStats(bad)).toBeNull();
    }
  });

  it("clamps levels above 15 and ignores level 0 and non-numbers", () => {
    const stats = parseAlertStats({
      hits: { total: { value: 10 } },
      aggregations: {
        levels: {
          buckets: [
            { key: 0, doc_count: 4 },
            { key: 99, doc_count: 2 },
            { key: "12", doc_count: 1 },
            { key: "abc", doc_count: 9 },
            { key: 3, doc_count: -5 },
            { key: 4, doc_count: "7" },
          ],
        },
      },
    });
    expect(stats?.bySeverity).toEqual({ critical: 3, high: 0, medium: 0, low: 7 });
  });

  it("never lets a huge or fake count through", () => {
    const stats = parseAlertStats({
      hits: { total: 5 },
      aggregations: {
        levels: {
          buckets: [
            { key: 3, doc_count: 1e300 },
            { key: 5, doc_count: Number.NaN },
          ],
        },
      },
    });
    expect(stats?.bySeverity.low).toBe(0);
    expect(stats?.total).toBe(5);
  });

  it("parses file integrity events as plain text and drops what is unusable", () => {
    const events = parseFimEvents(load("wazuh4", "indexer-fim-latest"), ADAPTERS.wazuh4);
    expect(events.map((e) => e.path)).toEqual([
      "/etc/passwd",
      "/var/lib/app/new.sh",
      "C:\\Windows\\System32\\drivers\\etc\\hosts",
      "/tmp/evil.txt https://evil.example/<img src=x onerror=alert(1)>",
      "/etc/hosts",
    ]);
    expect(events[0]).toMatchObject({ agentId: "001", agentName: "web-01", event: "modified", level: 7 });
    expect(events[1]?.event).toBe("added");
    expect(events[3]?.event).toBe("deleted");
    // A flat document and an unknown event word and level.
    expect(events[4]).toMatchObject({ agentId: "003", event: "other", level: null });
    expect(events.every((e) => !e.path.includes("\u0000") && !e.path.includes("\u202e"))).toBe(true);
  });

  it("caps the length of a path", () => {
    const events = parseFimEvents(
      {
        hits: {
          hits: [
            { _source: { "@timestamp": "2026-10-21T07:00:00Z", syscheck: { path: `/${"a".repeat(5000)}` } } },
          ],
        },
      },
      ADAPTERS.wazuh4,
    );
    expect(events[0]?.path).toHaveLength(500);
  });

  it("parses vulnerability states per agent and sums them", () => {
    const perAgent = parseVulnerabilityStats(load("wazuh4", "indexer-vulnerabilities"));
    expect(perAgent?.get("001")).toEqual({ critical: 2, high: 9, medium: 20, low: 4 });
    // "Untriaged" is not one of our four severities.
    expect(perAgent?.get("002")).toEqual({ critical: 0, high: 1, medium: 1, low: 0 });
    expect(perAgent?.get("004")).toEqual({ critical: 0, high: 0, medium: 0, low: 0 });
    expect(sumVulnerabilities(perAgent as NonNullable<typeof perAgent>, "2026-10-21T08:00:00.000Z")).toEqual({
      critical: 2,
      high: 10,
      medium: 21,
      low: 16,
      agentsAffected: 3,
      readAt: "2026-10-21T08:00:00.000Z",
    });
    expect(parseVulnerabilityStats({})).toBeNull();
    expect(parseVulnerabilityStats(null)).toBeNull();
  });
});

describe("snapshot", () => {
  it("reads a damaged value as an empty snapshot", () => {
    expect(readSnapshot(null)).toEqual({ windows: {}, vulnerabilities: null });
    expect(readSnapshot("x")).toEqual({ windows: {}, vulnerabilities: null });
    expect(readSnapshot({ windows: { "24h": { total: "many" } } }).windows["24h"]).toBeUndefined();
  });
  it("round-trips what a sync writes", () => {
    const snapshot = {
      windows: {
        "24h": {
          readAt: "2026-10-21T08:00:00.000Z",
          total: 3,
          bySeverity: { critical: 1, high: 1, medium: 1, low: 0 },
          previous: { total: 2, bySeverity: { critical: 0, high: 1, medium: 1, low: 0 } },
          tactics: [{ name: "Discovery", count: 2 }],
          agents: [{ agentId: "001", name: "web-01", count: 3 }],
          fim: 1,
        },
      },
      vulnerabilities: {
        critical: 1,
        high: 0,
        medium: 0,
        low: 0,
        agentsAffected: 1,
        readAt: "2026-10-21T08:00:00.000Z",
      },
    };
    expect(readSnapshot(snapshot)).toEqual(snapshot);
  });
});

describe("suggesting a server for an agent", () => {
  const hosts = [
    { id: "hst_1", name: "web-01", address: "192.0.2.11" },
    { id: "hst_2", name: "db-01.example.lan", address: "192.0.2.12" },
    { id: "hst_3", name: "app-02", address: "192.0.2.99" },
    { id: "hst_4", name: "dup-01.a.example.lan", address: "192.0.2.50" },
    { id: "hst_5", name: "dup-01.b.example.lan", address: "192.0.2.51" },
  ];
  it("matches by address first, then by name, then by host name without domain", () => {
    expect(suggestHost({ name: "renamed", ip: "192.0.2.11", isManager: false }, hosts)).toEqual({
      hostId: "hst_1",
      reason: "address",
    });
    expect(suggestHost({ name: "WEB-01", ip: null, isManager: false }, hosts)).toEqual({
      hostId: "hst_1",
      reason: "name",
    });
    expect(suggestHost({ name: "db-01", ip: "198.51.100.1", isManager: false }, hosts)).toEqual({
      hostId: "hst_2",
      reason: "hostname",
    });
    expect(suggestHost({ name: "app-02.example.lan", ip: null, isManager: false }, hosts)).toEqual({
      hostId: "hst_3",
      reason: "hostname",
    });
  });
  it("suggests nothing when the match is ambiguous, absent, or the agent is the manager", () => {
    expect(suggestHost({ name: "dup-01", ip: null, isManager: false }, hosts)).toBeNull();
    expect(suggestHost({ name: "unknown", ip: "198.51.100.1", isManager: false }, hosts)).toBeNull();
    expect(suggestHost({ name: "web-01", ip: "192.0.2.11", isManager: true }, hosts)).toBeNull();
    expect(suggestHost({ name: "x", ip: null, isManager: false }, hosts)).toBeNull();
  });
});

describe("source references", () => {
  it("round-trips connection and agent id", () => {
    const ref = wazuhSourceRef("wzc_abcdefghij0123456789", "012");
    expect(parseWazuhSourceRef(ref)).toEqual({ connectionId: "wzc_abcdefghij0123456789", agentId: "012" });
    for (const bad of [
      "",
      "wzc_x:1",
      "wzc_abcdefghij0123456789",
      "wzc_abcdefghij0123456789:abc",
      "a:b:c",
      "pxc_abcdefghij0123456789:1x",
    ]) {
      expect(parseWazuhSourceRef(bad), bad).toBeNull();
    }
  });
});
