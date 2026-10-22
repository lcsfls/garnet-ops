import { parseUnifiError } from "@garnetops/core";
import { describe, expect, it } from "vitest";
import { navFor } from "../components/nav.ts";
import { ARC_STROKE, BLOCKED_DASH, POINT_FILL } from "./globe.ts";
import { serverSearch, settingsSearch, toQuery } from "./search.ts";
import type { Me } from "./session.ts";
import { FLAG_ORDER, FLAG_TONE } from "./unifi.ts";

const me = (role: Me["role"]) => ({ role }) as Me;
const items = (features: { xdr?: boolean; attacks?: boolean }) =>
  navFor(me("member"), features)
    .flatMap((g) => g.items)
    .map((i) => i.to);

describe("UniFi tones", () => {
  it("never colour a device green, and never call anything critical", () => {
    for (const tone of Object.values(FLAG_TONE)) {
      expect(["success", "critical", "high"]).not.toContain(tone);
    }
    expect(FLAG_ORDER).toEqual(["offline", "updateAvailable"]);
    // An update is a maintenance hint, not a severity.
    expect(FLAG_TONE.updateAvailable).toBe("neutral");
  });

  it("draws blocked events in the information colour with a dash, never green and never a severity colour", () => {
    expect(ARC_STROKE.blocked).toBe("stroke-info");
    expect(POINT_FILL.blocked).toBe("fill-info");
    expect(ARC_STROKE.blocked).not.toMatch(/success|critical|high/);
    expect(BLOCKED_DASH).toMatch(/^\d+ \d+$/);
  });
});

describe("the Attacks entry", () => {
  it("is listed for a Wazuh connection or for UniFi threat events", () => {
    expect(items({})).not.toContain("/attacks");
    expect(items({ xdr: true })).toContain("/attacks");
    expect(items({ attacks: true })).toContain("/attacks");
    // The XDR page itself still needs a Wazuh connection.
    expect(items({ attacks: true })).not.toContain("/xdr");
    expect(items({ xdr: false, attacks: false })).not.toContain("/attacks");
  });
});

describe("search params of the Network devices tab", () => {
  it("keeps valid filters and drops anything else", () => {
    expect(
      serverSearch.parse({
        view: "unifi",
        ufQ: "ap",
        ufFlag: "update",
        ufState: "offline",
        ufSort: "uptime",
        ufDir: "desc",
        ufPageSize: 50,
        device: "ufd_abc",
      }),
    ).toMatchObject({
      view: "unifi",
      ufQ: "ap",
      ufFlag: "update",
      ufState: "offline",
      ufSort: "uptime",
      ufDir: "desc",
      ufPageSize: 50,
      device: "ufd_abc",
    });
    const bad = serverSearch.parse({
      view: "unifi",
      ufFlag: "vulnerable",
      ufState: "gone",
      ufSort: "password",
    });
    expect(bad.ufFlag).toBeUndefined();
    expect(bad.ufState).toBeUndefined();
    expect(bad.ufSort).toBeUndefined();
  });

  it("knows the settings section", () => {
    expect(settingsSearch.parse({ section: "unifi" })).toEqual({ section: "unifi" });
  });

  it("leaves the tab's own keys out of the API query when asked", () => {
    expect(toQuery({ q: "x", ufQ: "y" }, ["ufQ"])).toBe("?q=x");
  });
});

describe("stored error texts", () => {
  it("map back to a code the web app translates", () => {
    expect(
      parseUnifiError("The console rejected the API key. Create a new key and enter it again.")?.code,
    ).toBe("keyRejected");
    expect(parseUnifiError("something unknown")).toBeNull();
  });
});
