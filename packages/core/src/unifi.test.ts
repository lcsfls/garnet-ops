import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import {
  API_BASES,
  API_KEY_PATTERN,
  checkConnectionName,
  checkUnifiUrl,
  cleanText,
  deviceFlags,
  deviceStateOf,
  firmwareStatus,
  isOfficialQuery,
  isOfficialReadPath,
  notifyDecision,
  OFFLINE_NOTIFY_AFTER_SYNCS,
  parseClientTotal,
  parseDevices,
  parseInfo,
  parsePage,
  parseSites,
  parseUptime,
} from "./unifi.ts";

const fixture = (name: string): unknown =>
  JSON.parse(readFileSync(new URL(`../test/fixtures/unifi/${name}.json`, import.meta.url), "utf8"));
const SITE = "0a1b2c3d-0000-4000-8000-000000000001";
const DEVICE = "0d0d0d0d-0000-4000-8000-000000000001";

describe("the console address", () => {
  it("accepts https with an optional port and defaults to 443", () => {
    expect(checkUnifiUrl("https://udm.example.lan")).toEqual({
      ok: true,
      url: "https://udm.example.lan:443",
      host: "udm.example.lan",
      port: 443,
    });
    expect(checkUnifiUrl("https://192.0.2.1:8443/")).toMatchObject({ ok: true, port: 8443 });
    expect(checkUnifiUrl("https://[2001:db8::1]")).toMatchObject({
      ok: true,
      url: "https://[2001:db8::1]:443",
    });
  });

  it("allows private addresses, because consoles live in the customer's network", () => {
    expect(checkUnifiUrl("https://192.168.1.1")).toMatchObject({ ok: true });
    expect(checkUnifiUrl("https://10.0.0.1:8443")).toMatchObject({ ok: true });
  });

  it("refuses everything that is not a plain https host", () => {
    const problem = (v: string) => {
      const r = checkUnifiUrl(v);
      return r.ok ? "ok" : r.problem;
    };
    expect(problem("")).toBe("empty");
    expect(problem("http://udm.example.lan")).toBe("notHttps");
    expect(problem("udm.example.lan")).toBe("notHttps");
    expect(problem("https://user:pw@udm.example.lan")).toBe("credentials");
    expect(problem("https://udm.example.lan/proxy/network")).toBe("path");
    expect(problem("https://udm.example.lan/?a=1")).toBe("path");
    expect(problem("https://udm.example.lan/#x")).toBe("path");
    expect(problem("https://udm.example.lan:99999")).toBe("invalid");
    expect(problem(`https://${"a".repeat(300)}.example`)).toBe("tooLong");
  });

  it("refuses loopback, link-local, metadata and numeric tricks (SSRF)", () => {
    for (const host of [
      "127.0.0.1",
      "127.1",
      "localhost",
      "[::1]",
      "169.254.169.254",
      "[fe80::1]",
      "0.0.0.0",
      "224.0.0.1",
      "0x7f.1",
    ]) {
      expect(checkUnifiUrl(`https://${host}`), host).toMatchObject({ ok: false, problem: "address" });
    }
  });

  it("validates names and keys", () => {
    expect(checkConnectionName("  Main console ")).toBe("Main console");
    expect(checkConnectionName("")).toBeNull();
    expect(checkConnectionName("a".repeat(81))).toBeNull();
    expect(checkConnectionName("bad\u0000name")).toBeNull();
    expect(API_KEY_PATTERN.test("A".repeat(32))).toBe(true);
    expect(API_KEY_PATTERN.test("short")).toBe(false);
    expect(API_KEY_PATTERN.test(`${"A".repeat(32)} x`)).toBe(false);
  });
});

describe("the read-only allow-list", () => {
  it("names the two kinds of console", () => {
    expect(API_BASES["unifi-os"]).toBe("/proxy/network/integration");
    expect(API_BASES["network-app"]).toBe("/integration");
  });

  it("allows exactly the inventory endpoints", () => {
    for (const path of [
      "/v1/info",
      "/v1/sites",
      `/v1/sites/${SITE}/devices`,
      `/v1/sites/${SITE}/devices/${DEVICE}/statistics/latest`,
      `/v1/sites/${SITE}/clients`,
    ]) {
      expect(isOfficialReadPath(path), path).toBe(true);
    }
  });

  it("refuses everything else, including actions and traversal", () => {
    for (const path of [
      "",
      "/",
      "/v1",
      "/v1/info/",
      "/v1/infos",
      `/v1/sites/${SITE}`,
      `/v1/sites/${SITE}/devices/${DEVICE}`,
      `/v1/sites/${SITE}/devices/${DEVICE}/actions`,
      `/v1/sites/${SITE}/devices/${DEVICE}/interfaces/ports/1/actions`,
      `/v1/sites/${SITE}/clients/${DEVICE}/actions`,
      `/v1/sites/${SITE}/vouchers`,
      `/v1/sites/${SITE}/../devices`,
      "/v1/sites/default/devices",
      `/v1/sites/${SITE}/devices?x=1`,
      "/proxy/network/integration/v1/info",
      "/api/s/default/stat/ips/event",
      "/v1/pending-devices",
      `/v1/sites/${SITE}/devices/${DEVICE}/statistics/latest/extra`,
    ]) {
      expect(isOfficialReadPath(path), path).toBe(false);
    }
  });

  it("allows paging queries only, as plain integers", () => {
    expect(isOfficialQuery({})).toBe(true);
    expect(isOfficialQuery({ limit: "200", offset: "0" })).toBe(true);
    expect(isOfficialQuery({ limit: "1" })).toBe(true);
    expect(isOfficialQuery({ filter: "name.eq('x')" })).toBe(false);
    expect(isOfficialQuery({ limit: "abc" })).toBe(false);
    expect(isOfficialQuery({ limit: "1; drop" })).toBe(false);
    expect(isOfficialQuery({ offset: "99999999" })).toBe(false);
  });
});

describe("parsers", () => {
  it("reads the application version and nothing that is not one", () => {
    expect(parseInfo(fixture("info"))).toBe("9.0.114");
    expect(parseInfo({ applicationVersion: "9.0.114-beta.1" })).toBe("9.0.114-beta.1");
    for (const bad of [null, [], "x", {}, { applicationVersion: 9 }, { applicationVersion: "<script>" }]) {
      expect(parseInfo(bad), JSON.stringify(bad)).toBeNull();
    }
  });

  it("reads the envelope of a list answer", () => {
    expect(parsePage(fixture("sites"))).toMatchObject({ totalCount: 2 });
    expect(parsePage({ data: [] })).toEqual({ data: [], totalCount: null });
    expect(parsePage({ items: [] })).toBeNull();
    expect(parsePage([])).toBeNull();
    expect(parsePage({ data: "no" })).toBeNull();
  });

  it("reads sites, keeps the internal reference, and drops entries that do not fit", () => {
    const page = parsePage(fixture("sites")) as { data: unknown[] };
    const { sites, dropped } = parseSites(page.data);
    expect(dropped).toBe(0);
    expect(sites).toEqual([
      { id: SITE, internalReference: "default", name: "Main office" },
      { id: "0a1b2c3d-0000-4000-8000-000000000002", internalReference: "branch", name: "Branch" },
    ]);
    const hostile = parseSites([
      { id: "../../etc", name: "x" },
      { id: SITE, internalReference: "a/b", name: "ok\u202e\u0007name" },
      "text",
      null,
    ]);
    expect(hostile.dropped).toBe(3);
    // A reference that could break out of a path is not kept.
    expect(hostile.sites).toEqual([{ id: SITE, internalReference: null, name: "ok name" }]);
  });

  it("reads devices with their firmware flags and unknown fields ignored", () => {
    const page = parsePage(fixture("devices-main")) as { data: unknown[] };
    const { devices, dropped } = parseDevices(page.data);
    expect(dropped).toBe(0);
    expect(devices.map((d) => [d.name, d.state, d.rawState, d.firmwareUpdatable])).toEqual([
      ["gateway.example.lan", "online", "ONLINE", true],
      ["switch-1", "online", "ONLINE", false],
      ["ap-hall", "offline", "OFFLINE", true],
      ["ap-new", "other", "PENDING_ADOPTION", null],
    ]);
    expect(devices[0]).toMatchObject({
      mac: "02:00:00:00:00:01",
      ip: "192.0.2.1",
      model: "UCG Example",
      firmwareVersion: "4.0.6",
      latestFirmware: null,
    });
    expect(devices[3]?.ip).toBeNull();
  });

  it("reads a newest-firmware field if a console sends one", () => {
    const { devices } = parseDevices([
      {
        id: DEVICE,
        name: "x",
        state: "ONLINE",
        firmwareVersion: "1.0.0",
        firmwareUpdatable: true,
        latestFirmwareVersion: "1.1.0",
      },
    ]);
    expect(devices[0]?.latestFirmware).toBe("1.1.0");
  });

  it("is defensive about hostile device entries", () => {
    const { devices, dropped } = parseDevices([
      { id: "not-a-uuid", name: "x" },
      {
        id: DEVICE,
        name: `<b>x</b>\u202e${"y".repeat(500)}`,
        macAddress: "zz",
        ipAddress: "$(id)",
        state: "online; DROP",
        firmwareVersion: "1.0 && rm",
      },
      42,
      {
        id: DEVICE.replace(/1$/, "7"),
        name: "ok",
        macAddress: "02-00-00-00-00-07",
        state: "ONLINE",
        firmwareUpdatable: "yes",
      },
    ]);
    expect(dropped).toBe(2);
    expect(devices[0]?.name.length).toBeLessThanOrEqual(120);
    expect(devices[0]).toMatchObject({
      mac: null,
      ip: null,
      state: "other",
      rawState: "UNKNOWN",
      firmwareVersion: null,
    });
    // Text is kept as text (rendered escaped by the web app) but its control characters are gone.
    expect(devices[0]?.name).toContain("<b>");
    expect(devices[0]?.name).not.toContain("\u202e");
    expect(devices[1]).toMatchObject({ mac: "02:00:00:00:00:07", firmwareUpdatable: null });
  });

  it("maps the console's state words", () => {
    expect(deviceStateOf("ONLINE")).toBe("online");
    for (const word of ["OFFLINE", "CONNECTION_INTERRUPTED", "ISOLATED"])
      expect(deviceStateOf(word)).toBe("offline");
    for (const word of ["UPDATING", "GETTING_READY", "PENDING_ADOPTION", "ADOPTING", "UNKNOWN"]) {
      expect(deviceStateOf(word), word).toBe("other");
    }
  });

  it("reads the uptime, and only plausible values", () => {
    expect(parseUptime(fixture("device-statistics"))).toBe(864000);
    expect(parseUptime({ uptimeSec: "120" })).toBe(120);
    for (const bad of [null, {}, { uptimeSec: -1 }, { uptimeSec: "x" }, { uptimeSec: 1e12 }]) {
      expect(parseUptime(bad), JSON.stringify(bad)).toBeNull();
    }
  });

  it("reads the number of clients and never a client", () => {
    expect(parseClientTotal(fixture("clients"))).toBe(37);
    expect(parseClientTotal({ data: [] })).toBeNull();
    expect(parseClientTotal({ totalCount: 5 })).toBeNull();
    expect(parseClientTotal({ data: [], totalCount: 1e12 })).toBeNull();
    // The function returns a number: nothing of the client entries can leak through it.
    expect(typeof parseClientTotal(fixture("clients"))).toBe("number");
  });

  it("cleans free text", () => {
    expect(cleanText("  a\u202eb\u0007   c\n\nd ", 10)).toBe("a b c d");
    expect(cleanText("x".repeat(50), 5)).toBe("xxxxx");
  });
});

describe("firmware status", () => {
  it("says what the console says and never calls a device vulnerable", () => {
    expect(firmwareStatus({ firmwareUpdatable: true })).toBe("updateAvailable");
    expect(firmwareStatus({ firmwareUpdatable: false })).toBe("current");
    expect(firmwareStatus({ firmwareUpdatable: null })).toBe("unknown");
    expect(deviceFlags({ state: "offline", firmwareUpdatable: true })).toEqual([
      "offline",
      "updateAvailable",
    ]);
    expect(deviceFlags({ state: "online", firmwareUpdatable: false })).toEqual([]);
    // Devices that are updating or waiting for adoption are not "offline".
    expect(deviceFlags({ state: "other", firmwareUpdatable: null })).toEqual([]);
  });
});

describe("what people are told", () => {
  const base = {
    state: "online" as const,
    offlineSyncs: 0,
    offlineNotified: false,
    firmwareUpdatable: false,
    firmwareVersion: "1.0.0",
    firmwareNotifiedVersion: null,
  };

  it("debounces the offline message: after two syncs in a row, once", () => {
    expect(OFFLINE_NOTIFY_AFTER_SYNCS).toBe(2);
    const offline = { ...base, state: "offline" as const };
    expect(notifyDecision({ ...offline, offlineSyncs: 1 }).offline).toBe(false);
    expect(notifyDecision({ ...offline, offlineSyncs: 2 }).offline).toBe(true);
    expect(notifyDecision({ ...offline, offlineSyncs: 3, offlineNotified: true }).offline).toBe(false);
    expect(notifyDecision({ ...base, offlineSyncs: 5 }).offline).toBe(false);
  });

  it("tells about a firmware update once per device and firmware version", () => {
    const updatable = { ...base, firmwareUpdatable: true };
    expect(notifyDecision(updatable).firmware).toBe(true);
    expect(notifyDecision({ ...updatable, firmwareNotifiedVersion: "1.0.0" }).firmware).toBe(false);
    // A new version that is also out of date is news again.
    expect(
      notifyDecision({ ...updatable, firmwareVersion: "1.1.0", firmwareNotifiedVersion: "1.0.0" }).firmware,
    ).toBe(true);
    expect(notifyDecision({ ...updatable, firmwareVersion: null }).firmware).toBe(false);
    expect(notifyDecision({ ...base, firmwareUpdatable: null }).firmware).toBe(false);
  });
});
