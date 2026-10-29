import { describe, expect, it } from "vitest";
import { NAV, navFor, navTrail } from "./nav.ts";
import type { Me } from "./session.ts";

const me = (role: Me["role"]) => ({ role }) as Me;
const items = (role: Me["role"]) => navFor(me(role)).flatMap((g) => g.items.map((i) => i.to));

describe("navigation of the developer pipeline", () => {
  it("has the daily, code and admin groups and no infrastructure group", () => {
    expect(NAV.map((g) => g.label)).toEqual(["shell.groupDaily", "shell.groupCode", "shell.groupAdmin"]);
    const code = NAV.find((g) => g.label === "shell.groupCode");
    expect(code?.items.map((i) => i.to)).toEqual([
      "/repositories",
      "/gates",
      "/pull-requests",
      "/fixes",
      "/packages",
    ]);
  });

  it("lists the admin pages for owners and admins only", () => {
    for (const to of ["/team", "/audit-log", "/system"] as const) {
      expect(items("owner")).toContain(to);
      expect(items("admin")).toContain(to);
      expect(items("member")).not.toContain(to);
      expect(items("viewer")).not.toContain(to);
    }
    expect(items("viewer")).toEqual([
      "/",
      "/findings",
      "/early-warnings",
      "/statistics",
      "/repositories",
      "/gates",
      "/pull-requests",
      "/fixes",
      "/packages",
      "/settings",
    ]);
  });

  it("knows the breadcrumb of a page and of a page below it", () => {
    expect(navTrail("/repositories")?.item.label).toBe("nav.repositories");
    expect(navTrail("/repositories/repo_1")?.item.label).toBe("nav.repositories");
    expect(navTrail("/system")?.group).toBe("shell.groupAdmin");
    expect(navTrail("/statistics")?.group).toBe("shell.groupDaily");
    expect(navTrail("/servers")).toBeNull();
  });
});
