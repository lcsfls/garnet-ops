import { describe, expect, it } from "vitest";
import {
  findingSearch,
  repositorySearch,
  serverDetailSearch,
  serverSearch,
  settingsSearch,
  toQuery,
} from "./search.ts";

describe("search params", () => {
  it("accepts numbers where the URL decoder produced them", () => {
    expect(findingSearch.parse({ kev: 1, q: 2099, pageSize: "50" })).toMatchObject({
      kev: "1",
      q: "2099",
      pageSize: 50,
    });
  });

  it("keeps the AI panel flag and the AI settings section in the address, and drops anything else", () => {
    expect(findingSearch.parse({ id: "fnd_1", ai: 1 })).toMatchObject({ id: "fnd_1", ai: "1" });
    expect(findingSearch.parse({ ai: "yes" })).toMatchObject({ ai: undefined });
    expect(settingsSearch.parse({ section: "ai" })).toEqual({ section: "ai" });
    expect(settingsSearch.parse({ section: "nope" })).toEqual({ section: undefined });
    // The flag is for the page only: the list request leaves it out.
    expect(toQuery({ q: "x", ai: "1", id: "fnd_1" }, ["id", "ai"])).toBe("?q=x");
  });

  it("drops invalid values instead of failing the page", () => {
    const parsed = findingSearch.parse({
      state: "nope",
      kev: "yes",
      pageSize: 7,
      severity: "critical,bogus",
    });
    expect(parsed).toMatchObject({
      state: undefined,
      kev: undefined,
      pageSize: undefined,
      severity: "critical",
    });
    expect(repositorySearch.parse({ status: "weird", add: "1" })).toMatchObject({
      status: undefined,
      add: "1",
    });
  });

  it("builds API queries without empty or UI-only values", () => {
    expect(toQuery({ severity: "critical", q: undefined, id: "fnd_1", kev: "1" }, ["id"])).toBe(
      "?severity=critical&kev=1",
    );
    expect(toQuery({})).toBe("");
  });

  it("reads the server list's parameters: the wizard, a server to continue with, sorting", () => {
    expect(
      serverSearch.parse({ add: 1, import: "1", sort: "critical", dir: "desc", status: "attention" }),
    ).toMatchObject({
      add: "1",
      import: "1",
      sort: "critical",
      dir: "desc",
      status: "attention",
    });
    expect(serverSearch.parse({ add: "host_e2eseeded000000004" }).add).toBe("host_e2eseeded000000004");
    // Anything else in `add` is dropped, so a crafted link cannot name arbitrary text.
    for (const add of ["host_x", "../../etc", "2", "<script>"])
      expect(serverSearch.parse({ add }).add).toBeUndefined();
    expect(serverSearch.parse({ sort: "password", status: "weird" })).toMatchObject({
      sort: undefined,
      status: undefined,
    });
  });

  it("reads the Proxmox view's parameters and drops what is not allowed", () => {
    expect(
      serverSearch.parse({
        view: "proxmox",
        pxQ: 100,
        pxType: "lxc",
        pxStatus: "stopped",
        pxNode: "pve1",
        pxFlag: "stale",
        pxSort: "lastBackup",
        pxDir: "desc",
        pxPageSize: "50",
        guest: "pxg_abc",
      }),
    ).toMatchObject({
      view: "proxmox",
      pxQ: "100",
      pxType: "lxc",
      pxStatus: "stopped",
      pxNode: "pve1",
      pxFlag: "stale",
      pxSort: "lastBackup",
      pxDir: "desc",
      pxPageSize: 50,
      guest: "pxg_abc",
    });
    expect(
      serverSearch.parse({
        view: "evil",
        pxType: "vz",
        pxStatus: "weird",
        pxFlag: "all-of-it",
        pxSort: "password",
      }),
    ).toMatchObject({
      view: undefined,
      pxType: undefined,
      pxStatus: undefined,
      pxFlag: undefined,
      pxSort: undefined,
    });
  });

  it("keeps the three lists of a server page apart", () => {
    expect(
      serverDetailSearch.parse({
        findings: "a",
        packages: "b",
        runs: "c",
        findingState: "resolved",
        updates: 1,
      }),
    ).toMatchObject({ findings: "a", packages: "b", runs: "c", findingState: "resolved", updates: "1" });
    expect(serverDetailSearch.parse({ findingState: "bogus", findingSort: "nope" })).toMatchObject({
      findingState: undefined,
      findingSort: undefined,
    });
  });

  it("accepts one grade or 'none' in the lists, and the grade link's filters on the server page", () => {
    expect(repositorySearch.parse({ grade: "F", sort: "grade" })).toMatchObject({
      grade: "F",
      sort: "grade",
    });
    expect(serverSearch.parse({ grade: "none", sort: "grade", dir: "asc" })).toMatchObject({
      grade: "none",
      sort: "grade",
      dir: "asc",
    });
    expect(repositorySearch.parse({ grade: "G" })).toMatchObject({ grade: undefined });
    expect(repositorySearch.parse({ grade: "f" })).toMatchObject({ grade: undefined });
    expect(
      serverDetailSearch.parse({ findingSeverity: "high", findingFixable: 1, findingKev: "1" }),
    ).toMatchObject({ findingSeverity: "high", findingFixable: "1", findingKev: "1" });
    expect(serverDetailSearch.parse({ findingSeverity: "bogus" })).toMatchObject({
      findingSeverity: undefined,
    });
  });
});
