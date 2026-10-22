import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import {
  checkIpsUsername,
  IPS_PAGE_LIMIT,
  IPS_PATHS,
  ipsRightsAcknowledged,
  ipsStatus,
  isIpsInterval,
  isIpsRequest,
  isViewOnlyRoleName,
  normalizeAction,
  parseIpsEvents,
  parseLoginResponse,
  sameRights,
} from "./unifi-ips.ts";

const fixture = (name: string): unknown =>
  JSON.parse(readFileSync(new URL(`../test/fixtures/unifi/${name}.json`, import.meta.url), "utf8"));

describe("which requests the IPS client may send", () => {
  it("allows the login and the logout as the only POSTs, with no query", () => {
    for (const flavor of ["unifi-os", "network-app"] as const) {
      const p = IPS_PATHS[flavor];
      expect(isIpsRequest(flavor, "POST", p.login)).toBe(true);
      expect(isIpsRequest(flavor, "POST", p.logout)).toBe(true);
      expect(isIpsRequest(flavor, "POST", p.login, { x: "1" })).toBe(false);
    }
    // The other kind of console's login is not allowed on this one.
    expect(isIpsRequest("unifi-os", "POST", "/api/login")).toBe(false);
    expect(isIpsRequest("network-app", "POST", "/api/auth/login")).toBe(false);
  });

  it("refuses every other POST, PUT, DELETE and PATCH", () => {
    for (const method of ["POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS", "get"]) {
      for (const path of [
        "/proxy/network/api/s/default/cmd/devmgr",
        "/proxy/network/api/s/default/rest/user",
        "/proxy/network/api/s/default/stat/ips/event",
        "/api/auth/users",
        "/proxy/network/api/s/default/set/setting/super_mgmt",
      ]) {
        expect(isIpsRequest("unifi-os", method, path), `${method} ${path}`).toBe(false);
      }
    }
    expect(isIpsRequest("unifi-os", "PUT", IPS_PATHS["unifi-os"].login)).toBe(false);
  });

  it("allows one GET: the events of one site with numeric start, end and limit", () => {
    const events = "/proxy/network/api/s/default/stat/ips/event";
    expect(
      isIpsRequest("unifi-os", "GET", events, {
        start: "1792670000000",
        end: "1792670060000",
        _limit: "100",
      }),
    ).toBe(true);
    expect(isIpsRequest("unifi-os", "GET", events)).toBe(true);
    expect(isIpsRequest("network-app", "GET", "/api/s/branch/stat/ips/event", { _limit: "100" })).toBe(true);
    // Not the wrong prefix, not another endpoint, not traversal, not extra or non-numeric parameters.
    expect(isIpsRequest("network-app", "GET", events)).toBe(false);
    expect(isIpsRequest("unifi-os", "GET", "/api/s/default/stat/ips/event")).toBe(false);
    expect(isIpsRequest("unifi-os", "GET", "/proxy/network/api/s/default/stat/event")).toBe(false);
    expect(isIpsRequest("unifi-os", "GET", "/proxy/network/api/s/default/rest/user")).toBe(false);
    expect(isIpsRequest("unifi-os", "GET", "/proxy/network/api/s/../stat/ips/event")).toBe(false);
    expect(isIpsRequest("unifi-os", "GET", "/proxy/network/api/s/a%2fb/stat/ips/event")).toBe(false);
    expect(isIpsRequest("unifi-os", "GET", events, { _limit: "x" })).toBe(false);
    expect(isIpsRequest("unifi-os", "GET", events, { type: "x" })).toBe(false);
    expect(isIpsRequest("unifi-os", "GET", "/proxy/network/api/self")).toBe(false);
  });
});

describe("the IPS user", () => {
  it("refuses the names of administrator accounts", () => {
    for (const name of [
      "admin",
      "Admin",
      "ADMINISTRATOR",
      "root",
      "ubnt",
      "ui",
      "unifi",
      "owner",
      "superadmin",
      "admin@example.com",
    ]) {
      expect(checkIpsUsername(name), name).toEqual({ ok: false, problem: "forbidden" });
    }
  });

  it("accepts neutral names and refuses odd characters", () => {
    expect(checkIpsUsername(" garnetops-view ")).toEqual({ ok: true, value: "garnetops-view" });
    expect(checkIpsUsername("viewer@example.com")).toMatchObject({ ok: true });
    for (const bad of ["", "a b", "x".repeat(65), "na;me", "na\nme", "$(id)"]) {
      expect(checkIpsUsername(bad), bad).toEqual({ ok: false, problem: "invalid" });
    }
  });

  it("knows the rhythm limits", () => {
    expect(isIpsInterval(60)).toBe(true);
    expect(isIpsInterval(30)).toBe(true);
    expect(isIpsInterval(600)).toBe(true);
    for (const bad of [29, 601, 60.5, "60", Number.NaN, null])
      expect(isIpsInterval(bad), String(bad)).toBe(false);
  });
});

describe("rights beyond viewing in the login answer", () => {
  it("reports nothing for a view-only user", () => {
    expect(parseLoginResponse(fixture("login-viewer"))).toEqual({ rights: [] });
    expect(parseLoginResponse(fixture("login-legacy-readonly"))).toEqual({ rights: [] });
  });

  it("lists owners, super admins and every role that is not view-only", () => {
    expect(parseLoginResponse(fixture("login-admin"))).toEqual({
      rights: ["role: Super Admin", "super_admin"],
    });
    expect(parseLoginResponse(fixture("login-legacy-admin"))).toEqual({ rights: ["role: admin"] });
    expect(parseLoginResponse({ isOwner: true })).toEqual({ rights: ["owner"] });
    expect(parseLoginResponse({ roles: ["Site Admin"] })).toEqual({ rights: ["role: Site Admin"] });
    // Not recognisably view-only means: listed. Together with a view-only role it is still listed.
    expect(parseLoginResponse({ roles: ["Guest Manager", { name: "View Only" }] })).toEqual({
      rights: ["role: Guest Manager"],
    });
    // Sorted, without duplicates, cut and capped.
    expect(parseLoginResponse({ role: "admin", roles: ["admin", "Admin"], isOwner: true }).rights).toEqual([
      "owner",
      "role: Admin",
      "role: admin",
    ]);
    const many = parseLoginResponse({
      roles: Array.from({ length: 30 }, (_, i) => `role-${i}-${"x".repeat(80)}`),
    });
    expect(many.rights.length).toBeLessThanOrEqual(10);
    expect(many.rights.every((r) => r.length <= 56)).toBe(true);
  });

  it("does not guess from shapes it does not know", () => {
    for (const body of [null, "x", 5, [], {}, { roles: "admin" }, { user: null }]) {
      expect(parseLoginResponse(body), JSON.stringify(body)).toEqual({ rights: [] });
    }
    for (const name of ["Read Only", "view-only", "Viewer", "readonly", "View_Only"]) {
      expect(isViewOnlyRoleName(name), name).toBe(true);
    }
    for (const name of ["Super Admin", "owner", "viewer admin", "Read Only Plus", ""]) {
      expect(isViewOnlyRoleName(name), name).toBe(false);
    }
  });

  it("is acknowledged only for exactly the reported list", () => {
    expect(ipsRightsAcknowledged([], [])).toBe(true);
    expect(ipsRightsAcknowledged(["owner"], [])).toBe(false);
    expect(ipsRightsAcknowledged(["owner"], ["owner"])).toBe(true);
    expect(ipsRightsAcknowledged(["owner", "role: x"], ["role: x", "owner"])).toBe(true);
    // More, fewer or other rights are not covered.
    expect(ipsRightsAcknowledged(["owner", "role: x"], ["owner"])).toBe(false);
    expect(ipsRightsAcknowledged(["owner"], ["owner", "role: x"])).toBe(false);
    expect(ipsRightsAcknowledged(["owner"], ["super_admin"])).toBe(false);
    expect(sameRights(["a", "b", "a"], ["b", "a"])).toBe(true);
    expect(sameRights(["a"], ["a", "b"])).toBe(false);
  });
});

describe("threat events", () => {
  it("normalises what the console did", () => {
    for (const v of ["drop", "dropped", "block", "Blocked", "reject", "deny", " blocked "]) {
      expect(normalizeAction(v), v).toBe("blocked");
    }
    for (const v of ["alert", "allow", "allowed", "", "other", null, undefined, 1]) {
      expect(normalizeAction(v), String(v)).toBe("alerted");
    }
  });

  it("parses the recorded events, oldest first, with only the fields that are kept", () => {
    const parsed = parseIpsEvents(fixture("ips-events"));
    expect(parsed).not.toBeNull();
    const { events, dropped, fullPage } = parsed as NonNullable<typeof parsed>;
    // 7 entries: one has a bad address, one has no time; those two are dropped. One has an impossible port and is kept without it.
    expect(dropped).toBe(2);
    expect(fullPage).toBe(false);
    expect(events.map((e) => [e.ip, e.action])).toEqual([
      ["203.0.113.11", "blocked"],
      ["203.0.113.12", "alerted"],
      ["2001:db8::1", "alerted"],
      ["203.0.113.15", "blocked"],
      ["203.0.113.17", "blocked"],
    ]);
    expect(events[0]).toMatchObject({
      signature: "ET SCAN Example SSH brute force",
      category: "Attempted Administrator Privilege Gain",
      destPort: 22,
      proto: "tcp",
    });
    expect(events[1]).toMatchObject({ destPort: 443, proto: "tcp" });
    // No payload, no destination address, no source port, no host: the event holds nothing else.
    expect(Object.keys(events[0] as object).sort()).toEqual(
      ["action", "at", "category", "destPort", "docId", "ip", "proto", "signature"].sort(),
    );
    expect(JSON.stringify(events)).not.toContain("192.0.2.50");
    expect(JSON.stringify(events)).not.toContain("40001");
  });

  it("cleans and cuts attacker-influenced text, and drops impossible values", () => {
    const { events } = parseIpsEvents(fixture("ips-events")) as NonNullable<
      ReturnType<typeof parseIpsEvents>
    >;
    const hostile = events.find((e) => e.ip === "203.0.113.15");
    expect(hostile?.signature.length).toBeLessThanOrEqual(200);
    expect(hostile?.signature).not.toContain("\u202e");
    expect(hostile?.signature).not.toContain("\u0007");
    // Markup stays as text: the web app renders it escaped, and it is never a link.
    expect(hostile?.signature.startsWith("<img src=x")).toBe(true);
    expect(hostile?.category?.length).toBeLessThanOrEqual(80);
    const odd = events.find((e) => e.ip === "203.0.113.17");
    expect(odd?.destPort).toBeNull();
    expect(odd?.proto).toBeNull();
  });

  it("gives the same event the same id, so it is stored once", () => {
    const a = parseIpsEvents([
      {
        timestamp: 1792670001000,
        src_ip: "203.0.113.5",
        inner_alert_signature: "x",
        inner_alert_action: "drop",
        dest_port: 80,
      },
    ]);
    const b = parseIpsEvents([
      {
        timestamp: 1792670001000,
        src_ip: "203.0.113.5",
        inner_alert_signature: "x",
        inner_alert_action: "drop",
        dest_port: 80,
      },
    ]);
    expect(a?.events[0]?.docId).toBe(b?.events[0]?.docId);
    expect(a?.events[0]?.docId).toMatch(/^[0-9a-f]{32}$/);
    const c = parseIpsEvents([
      { _id: "671000000000000000000099", timestamp: 1792670001000, src_ip: "203.0.113.5" },
    ]);
    expect(c?.events[0]?.docId).toBe("671000000000000000000099");
  });

  it("accepts a plain list and times in seconds or ISO text", () => {
    const parsed = parseIpsEvents([
      { time: 1792670001, src_ip: "203.0.113.5" },
      { datetime: "2026-10-22T10:00:00Z", src_ip: "203.0.113.6" },
    ]);
    expect(parsed?.events).toHaveLength(2);
    expect(parsed?.events[0]?.at.toISOString()).toBe("2026-10-22T10:00:00.000Z");
  });

  it("refuses answers that are not event lists, and times that are not plausible", () => {
    for (const body of [null, "x", 5, {}, { data: "no" }, { meta: {} }]) {
      expect(parseIpsEvents(body), JSON.stringify(body)).toBeNull();
    }
    const parsed = parseIpsEvents([
      { timestamp: 5, src_ip: "203.0.113.5" },
      { timestamp: Date.now() + 10 * 86_400_000, src_ip: "203.0.113.5" },
    ]);
    expect(parsed?.events).toHaveLength(0);
    expect(parsed?.dropped).toBe(2);
  });

  it("reports a full page and caps the number of entries it reads", () => {
    const many = Array.from({ length: IPS_PAGE_LIMIT + 20 }, (_, i) => ({
      timestamp: 1792670000000 + i * 1000,
      src_ip: `203.0.113.${(i % 200) + 1}`,
      inner_alert_signature: `s${i}`,
    }));
    const parsed = parseIpsEvents(many);
    expect(parsed?.fullPage).toBe(true);
    expect(parsed?.events.length).toBe(IPS_PAGE_LIMIT);
    expect(parsed?.dropped).toBe(20);
  });
});

describe("the status of the preview", () => {
  const input = {
    enabled: true,
    connectionEnabled: true,
    certificateOk: true,
    hasCredentials: true,
    synced: true,
    rights: [] as string[],
    rightsAcknowledged: [] as string[],
    lastPollAt: new Date("2026-10-22T10:00:00Z"),
    lastError: null,
    intervalSeconds: 60,
    now: new Date("2026-10-22T10:00:30Z"),
  };

  it("is off, paused, waiting or live, and explains why", () => {
    expect(ipsStatus({ ...input, enabled: false }).state).toBe("off");
    expect(ipsStatus({ ...input, connectionEnabled: false })).toMatchObject({
      state: "paused",
      reason: "disabled",
    });
    expect(ipsStatus({ ...input, certificateOk: false })).toMatchObject({
      state: "paused",
      reason: "certificate",
    });
    expect(ipsStatus({ ...input, hasCredentials: false })).toMatchObject({
      state: "paused",
      reason: "credentials",
    });
    expect(ipsStatus({ ...input, synced: false })).toMatchObject({ state: "paused", reason: "no-sync" });
    expect(ipsStatus({ ...input, rights: ["owner"] })).toMatchObject({ state: "paused", reason: "rights" });
    expect(ipsStatus({ ...input, rights: ["owner"], rightsAcknowledged: ["role: x"] })).toMatchObject({
      state: "paused",
      reason: "rights",
    });
    expect(ipsStatus({ ...input, rights: ["owner"], rightsAcknowledged: ["owner"] }).state).toBe("live");
    expect(ipsStatus({ ...input, lastPollAt: null }).state).toBe("waiting");
    expect(ipsStatus({ ...input, lastError: "failed" })).toMatchObject({ state: "waiting", error: "failed" });
    expect(ipsStatus(input).state).toBe("live");
    // The worker has not polled for much longer than its interval.
    expect(ipsStatus({ ...input, now: new Date("2026-10-22T10:10:00Z") }).state).toBe("waiting");
  });
});
