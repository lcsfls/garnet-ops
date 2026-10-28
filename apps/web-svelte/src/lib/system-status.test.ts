import { STATUS_LEVELS } from "@garnetops/core/system-status";
import { describe, expect, it } from "vitest";
import { navFor, navTrail } from "./nav.ts";
import { SETTINGS_SECTIONS } from "./search.ts";
import type { Me } from "./session.ts";
import { camelState, canOpenSection, INTEGRATION_SECTION, LEVEL_TONE, queueKey } from "./system-status.ts";

const me = (role: Me["role"]) => ({ role }) as Me;

describe("levels", () => {
  it("never use the green of proof", () => {
    for (const level of STATUS_LEVELS) expect(LEVEL_TONE[level]).not.toBe("success");
    expect(LEVEL_TONE.failed).toBe("critical");
    expect(LEVEL_TONE.attention).toBe("medium");
  });
});

describe("links to settings", () => {
  it("lead to sections that exist", () => {
    for (const section of Object.values(INTEGRATION_SECTION)) expect(SETTINGS_SECTIONS).toContain(section);
  });

  it("leave the directory to owners, who are the only ones who see that section", () => {
    expect(canOpenSection("signin", "owner")).toBe(true);
    expect(canOpenSection("signin", "admin")).toBe(false);
    expect(canOpenSection("ai", "admin")).toBe(true);
  });
});

describe("keys", () => {
  it("turn queue names and states into message keys without dots", () => {
    expect(queueKey("scan.repository")).toBe("scanRepository");
    expect(queueKey("scan.schedule-tick")).toBe("scanScheduleTick");
    expect(queueKey("fix-pr.create")).toBe("fixPrCreate");
    expect(camelState("not_configured")).toBe("notConfigured");
    expect(camelState("current")).toBe("current");
  });
});

describe("navigation", () => {
  const entries = (role: Me["role"]) => navFor(me(role)).flatMap((g) => g.items.map((i) => i.to));

  it("lists the page for owners and admins only, in the admin group", () => {
    expect(entries("owner")).toContain("/system");
    expect(entries("admin")).toContain("/system");
    expect(entries("member")).not.toContain("/system");
    expect(entries("viewer")).not.toContain("/system");
    const group = navFor(me("admin")).find((g) => g.items.some((i) => i.to === "/system"));
    expect(group?.label).toBe("shell.groupAdmin");
    expect(navTrail("/system")?.item.label).toBe("nav.system");
  });
});
