import { describe, expect, it } from "vitest";
import {
  defaultPreference,
  EVENT_CATALOG,
  EVENT_GROUPS,
  isTitleKey,
  type Member,
  type Preference,
  preferenceEvents,
  resolvePreference,
  roleReceives,
  safeAppLink,
  sanitizeParams,
  selectRecipients,
  TITLE_EVENTS,
  USER_EVENTS,
} from "./user-notifications.ts";

const members: Member[] = [
  { userId: "owner", role: "owner" },
  { userId: "admin", role: "admin" },
  { userId: "member", role: "member" },
  { userId: "viewer", role: "viewer" },
];
const none = new Map<string, Partial<Preference>>();
const who = (list: { userId: string }[]) => list.map((r) => r.userId).sort();

describe("event catalogue", () => {
  it("puts every event in a known group and every title key on an existing event", () => {
    for (const event of USER_EVENTS) expect(EVENT_GROUPS).toContain(EVENT_CATALOG[event].group);
    for (const event of Object.values(TITLE_EVENTS)) expect(USER_EVENTS).toContain(event);
    expect(isTitleKey("gateBlocked")).toBe(true);
    expect(isTitleKey("toString")).toBe(false);
    expect(isTitleKey("<script>")).toBe(false);
  });

  it("only offers a scope where it makes sense, and 'mine' is the default only for fix pull requests", () => {
    for (const event of USER_EVENTS) {
      const d = EVENT_CATALOG[event];
      if (!d.scoped) expect(d.defaultScope).toBe("all");
      if (event.startsWith("fix_pr.")) expect(d.defaultScope).toBe("mine");
    }
  });
});

describe("preferences", () => {
  it("default to in app on and email off", () => {
    for (const event of USER_EVENTS) {
      expect(defaultPreference(event)).toMatchObject({ inApp: true, email: false });
      expect(resolvePreference(event, null)).toEqual(defaultPreference(event));
    }
  });

  it("take what is stored and fall back per field", () => {
    expect(resolvePreference("gate.blocked", { email: true })).toEqual({
      inApp: true,
      email: true,
      scope: "all",
    });
    expect(resolvePreference("gate.blocked", { inApp: false, scope: "mine" })).toEqual({
      inApp: false,
      email: false,
      scope: "mine",
    });
    // Garbage in an old row does not become behaviour.
    expect(resolvePreference("gate.blocked", { scope: "everyone" as never }).scope).toBe("all");
  });

  it("ignore a scope on events that cannot be limited", () => {
    expect(resolvePreference("infra.sync_blocked", { scope: "mine" }).scope).toBe("all");
  });
});

describe("roles", () => {
  it("send admin-only events to owners and admins", () => {
    for (const event of [
      "infra.host_key_changed",
      "infra.certificate_changed",
      "infra.sync_blocked",
      "unifi.certificate_changed",
      "unifi.device_offline",
      "unifi.firmware_update_available",
      "exposure.certificate_expiring",
      "exposure.verification_lost",
      "exposure.new_open_port",
      "exposure.risky_service",
      "team.invitation_accepted",
      "system.update_finished",
    ] as const) {
      const got = selectRecipients({ event, members, preferences: none, mailAvailable: false });
      expect(who(got), event).toEqual(["admin", "owner"]);
    }
  });

  it("tell viewers about findings and gates but not about failed scans or fix pull requests", () => {
    const ask = (
      event: (typeof USER_EVENTS)[number],
      ctx = { ownerUserId: "member", requestedBy: "member" },
    ) => who(selectRecipients({ event, members, preferences: none, context: ctx, mailAvailable: false }));
    expect(ask("finding.new_critical")).toEqual(["admin", "member", "owner", "viewer"]);
    expect(ask("gate.blocked")).toEqual(["admin", "member", "owner", "viewer"]);
    expect(ask("scan.failed")).toEqual(["admin", "member", "owner"]);
    // Fix pull requests default to "mine": only the requester.
    expect(ask("fix_pr.merged")).toEqual(["member"]);
  });

  it("tell only the person a targeted event is about, whatever their role", () => {
    const got = selectRecipients({
      event: "team.role_changed",
      members,
      preferences: none,
      context: { targetUserId: "viewer" },
      mailAvailable: false,
    });
    expect(who(got)).toEqual(["viewer"]);
    expect(
      selectRecipients({ event: "team.role_changed", members, preferences: none, mailAvailable: false }),
    ).toEqual([]);
  });

  it("lists only the rows a role can receive", () => {
    expect(preferenceEvents("viewer")).toContain("gate.blocked");
    expect(preferenceEvents("viewer")).not.toContain("infra.certificate_changed");
    expect(preferenceEvents("viewer")).not.toContain("scan.failed");
    expect(preferenceEvents("viewer")).toContain("team.role_changed");
    expect(preferenceEvents("admin")).toEqual([...USER_EVENTS]);
    expect(roleReceives("member", "team.invitation_accepted")).toBe(false);
  });
});

describe("recipients and choices", () => {
  it("respect a switched-off in-app notification", () => {
    const got = selectRecipients({
      event: "gate.blocked",
      members,
      preferences: new Map([["member", { inApp: false }]]),
      mailAvailable: false,
    });
    expect(who(got)).toEqual(["admin", "owner", "viewer"]);
  });

  it("never lets a stored choice widen the role", () => {
    const got = selectRecipients({
      event: "infra.certificate_changed",
      members,
      preferences: new Map([["viewer", { inApp: true, email: true }]]),
      mailAvailable: true,
    });
    expect(who(got)).toEqual(["admin", "owner"]);
  });

  it("counts email only when the organisation has a mail channel", () => {
    const preferences = new Map<string, Partial<Preference>>([
      ["admin", { email: true }],
      ["owner", { email: true, inApp: false }],
    ]);
    const without = selectRecipients({ event: "scan.failed", members, preferences, mailAvailable: false });
    expect(without.find((r) => r.userId === "admin")).toEqual({ userId: "admin", inApp: true, email: false });
    // In app off and no mail means nobody to tell.
    expect(without.find((r) => r.userId === "owner")).toBeUndefined();
    const withMail = selectRecipients({ event: "scan.failed", members, preferences, mailAvailable: true });
    expect(withMail.find((r) => r.userId === "admin")).toEqual({ userId: "admin", inApp: true, email: true });
    expect(withMail.find((r) => r.userId === "owner")).toEqual({
      userId: "owner",
      inApp: false,
      email: true,
    });
  });

  it("limit to what a person added or asked for when they choose 'mine'", () => {
    const preferences = new Map<string, Partial<Preference>>([["admin", { scope: "mine" }]]);
    const mine = selectRecipients({
      event: "finding.new_critical",
      members,
      preferences,
      context: { ownerUserId: "admin" },
      mailAvailable: false,
    });
    expect(who(mine)).toEqual(["admin", "member", "owner", "viewer"]);
    const notMine = selectRecipients({
      event: "finding.new_critical",
      members,
      preferences,
      context: { ownerUserId: "member" },
      mailAvailable: false,
    });
    expect(who(notMine)).toEqual(["member", "owner", "viewer"]);
    // Without an owner (the connecting user is gone) nothing is "mine".
    const orphan = selectRecipients({
      event: "finding.new_critical",
      members,
      preferences,
      context: { ownerUserId: null },
      mailAvailable: false,
    });
    expect(who(orphan)).not.toContain("admin");
  });

  it("lets a person widen fix pull request notices to all", () => {
    const got = selectRecipients({
      event: "fix_pr.failed",
      members,
      preferences: new Map([["admin", { scope: "all" }]]),
      context: { requestedBy: "member" },
      mailAvailable: false,
    });
    expect(who(got)).toEqual(["admin", "member"]);
  });
});

describe("contents", () => {
  it("accepts app paths and refuses everything that leaves the app", () => {
    expect(safeAppLink("/repositories/repo_1")).toBe("/repositories/repo_1");
    expect(safeAppLink("/findings?id=fnd_1&state=open")).toBe("/findings?id=fnd_1&state=open");
    expect(safeAppLink("/settings?section=notifications#top")).toBe("/settings?section=notifications#top");
    for (const bad of [
      "",
      "repositories",
      "//evil.example",
      "https://evil.example/",
      "javascript:alert(1)",
      "/\\evil.example",
      "/a/../b",
      "/%2e%2e/b",
      "/a%5cb",
      "/a\nb",
      "/a b",
      "/<script>",
      `/${"a".repeat(400)}`,
      null,
      42,
    ]) {
      expect(safeAppLink(bad), String(bad)).toBeNull();
    }
  });

  it("keeps parameters short, flat and free of control characters", () => {
    const clean = sanitizeParams({
      repository: "billing\nportal‮",
      critical: 3,
      "bad key": "x",
      nested: { a: 1 } as never,
      nan: Number.NaN,
      long: "é".repeat(300),
    });
    expect(clean.repository).toBe("billing portal");
    expect(clean.critical).toBe(3);
    expect(clean).not.toHaveProperty("bad key");
    expect(clean).not.toHaveProperty("nested");
    expect(clean).not.toHaveProperty("nan");
    expect(String(clean.long)).toHaveLength(120);
    expect(
      Object.keys(sanitizeParams(Object.fromEntries(Array.from({ length: 20 }, (_, i) => [`k${i}`, i]))))
        .length,
    ).toBe(8);
  });
});
