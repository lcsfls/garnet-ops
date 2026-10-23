import { WAZUH_ERRORS } from "@garnetops/core";
import { describe, expect, it } from "vitest";
import { navFor, navTrail } from "../components/nav.ts";
import { serverSearch, settingsSearch, xdrSearch } from "./search.ts";
import type { Me } from "./session.ts";
import { AGENT_STATUS_TONE, changeOf, PERIOD_KEY, XDR_SEVERITIES } from "./xdr.ts";

const me = (role: Me["role"]): Me => ({
  user: { id: "u", name: "Erika", email: "erika@example.test", locale: null, timeZone: null },
  organization: {
    id: "o",
    name: "Example",
    scanSchedule: { enabled: false, localTime: "04:00:00", timeZone: "UTC" },
  },
  role,
});

describe("change against the previous period", () => {
  it("says up, down, same or unknown", () => {
    expect(changeOf(10, 4)).toEqual({ kind: "up", by: 6 });
    expect(changeOf(4, 10)).toEqual({ kind: "down", by: 6 });
    expect(changeOf(5, 5)).toEqual({ kind: "same" });
    expect(changeOf(5, null)).toEqual({ kind: "unknown" });
    expect(changeOf(5, undefined)).toEqual({ kind: "unknown" });
    expect(changeOf(0, 0)).toEqual({ kind: "same" });
  });
});

describe("tables of the XDR page", () => {
  it("order severities from critical to low and name every period", () => {
    expect(XDR_SEVERITIES).toEqual(["critical", "high", "medium", "low"]);
    expect(PERIOD_KEY).toEqual({ "24h": "h24", "7d": "d7", "30d": "d30" });
  });
  it("never colour a status green: online proves nothing, and orange is for severity", () => {
    for (const tone of Object.values(AGENT_STATUS_TONE)) {
      expect(["success", "critical", "high", "medium"]).not.toContain(tone);
    }
  });
});

describe("navigation", () => {
  const items = (features: { xdr?: boolean }, role: Me["role"] = "member") =>
    navFor(me(role), features)
      .flatMap((g) => g.items)
      .map((i) => i.to);

  it("lists XDR under Infrastructure only while a Wazuh connection exists", () => {
    expect(items({})).not.toContain("/xdr");
    expect(items({ xdr: false })).not.toContain("/xdr");
    expect(items({ xdr: true })).toContain("/xdr");
    const group = navFor(me("viewer"), { xdr: true }).find((g) => g.items.some((i) => i.to === "/xdr"));
    expect(group?.label).toBe("shell.groupInfrastructure");
    // The attack overview is built from Wazuh alerts and is listed right after XDR.
    expect(group?.items.map((i) => i.to)).toEqual(["/servers", "/exposure", "/xdr", "/attacks"]);
    expect(items({})).not.toContain("/attacks");
    expect(navTrail("/attacks")?.item.label).toBe("nav.attacks");
  });

  it("knows the breadcrumb of the page", () => {
    expect(navTrail("/xdr")?.item.label).toBe("nav.xdr");
  });
});

describe("search params of XDR", () => {
  it("keeps valid filters and drops anything else", () => {
    expect(
      xdrSearch.parse({
        period: "7d",
        status: "active",
        link: "suggested",
        sort: "vulnerabilities",
        dir: "desc",
      }),
    ).toMatchObject({
      period: "7d",
      status: "active",
      link: "suggested",
      sort: "vulnerabilities",
      dir: "desc",
    });
    expect(
      xdrSearch.parse({ period: "1y", status: "up", link: "x", sort: "password", group: "bad group!" }),
    ).toMatchObject({
      period: undefined,
      status: undefined,
      link: undefined,
      sort: undefined,
      group: undefined,
    });
    expect(xdrSearch.parse({ enroll: 1, q: 7 })).toMatchObject({ enroll: "1", q: "7" });
  });

  it("has the Wazuh view on the Servers page and the XDR section in the settings", () => {
    expect(serverSearch.parse({ view: "wazuh", wzStatus: "disconnected", wzLink: "unlinked" })).toMatchObject(
      {
        view: "wazuh",
        wzStatus: "disconnected",
        wzLink: "unlinked",
      },
    );
    expect(serverSearch.parse({ view: "other" }).view).toBeUndefined();
    expect(settingsSearch.parse({ section: "xdr" })).toEqual({ section: "xdr" });
  });
});

describe("stored Wazuh errors", () => {
  it("every code has a translation with the same placeholders as the stored English text", async () => {
    const { resources } = await import("@garnetops/i18n");
    const names = (text: string) => [...text.matchAll(/\{(\w+)\}/g)].map((m) => m[1]).sort();
    for (const [code, text] of Object.entries(WAZUH_ERRORS)) {
      for (const lang of ["en", "de"] as const) {
        const translated = (resources[lang].translation.wazuhError as Record<string, string>)[code];
        expect(translated, `${lang} ${code}`).toBeTruthy();
        expect(names(translated as string), `${lang} ${code}`).toEqual(names(text));
      }
    }
    expect(Object.keys(resources.en.translation.wazuhError).sort()).toEqual(Object.keys(WAZUH_ERRORS).sort());
  });
});
