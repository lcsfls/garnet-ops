import { describe, expect, it } from "vitest";
import {
  ARC_STEPS,
  type AttackSource,
  agentTotals,
  arcStep,
  arcTone,
  asnTotals,
  changeOf,
  countryCount,
  countryTotals,
  internalTotals,
  mergeSources,
  shadeStep,
  windowOf,
} from "./attacks.ts";
import { canonicalIp } from "./geoip.ts";

const source = (over: Partial<AttackSource> = {}): AttackSource => ({
  ip: "198.51.100.1",
  count: 10,
  groups: ["authentication_failed"],
  firstSeen: null,
  lastSeen: null,
  agents: [],
  scope: "public",
  country: "DE",
  asn: 64500,
  org: "Example Hosting",
  ...over,
});

const sources: AttackSource[] = [
  source({ ip: "198.51.100.1", count: 100, agents: [{ agentId: "001", name: "web-01", count: 100 }] }),
  source({
    ip: "198.51.100.2",
    count: 50,
    agents: [
      { agentId: "001", name: "web-01", count: 30 },
      { agentId: "002", name: "db-01", count: 20 },
    ],
  }),
  source({ ip: "203.0.113.1", count: 70, country: "FR", asn: 64501, org: "Exemple" }),
  source({ ip: "192.0.2.200", count: 5, country: null, asn: null, org: null }),
  source({ ip: "2001:db8::1", count: 3, country: "ZZ", asn: 64502, org: "Unknown" }),
  source({ ip: "10.0.0.1", count: 40, scope: "internal", country: null, asn: null, org: null }),
];

describe("totals", () => {
  it("sums alerts and addresses per country, busiest first, internal addresses excluded", () => {
    expect(countryTotals(sources)).toEqual([
      { country: "DE", alerts: 150, sources: 2 },
      { country: "FR", alerts: 70, sources: 1 },
      { country: null, alerts: 5, sources: 1 },
      { country: "ZZ", alerts: 3, sources: 1 },
    ]);
    expect(countryCount(sources)).toBe(2);
    expect(internalTotals(sources)).toEqual({ alerts: 40, sources: 1 });
  });

  it("sums per AS and takes the first organisation name it sees", () => {
    const totals = asnTotals(sources);
    expect(totals[0]).toEqual({ asn: 64500, org: "Example Hosting", alerts: 150, sources: 2 });
    expect(totals.find((t) => t.asn === null)).toMatchObject({ alerts: 5 });
  });

  it("sums the targeted agents", () => {
    expect(agentTotals(sources)).toEqual([
      { agentId: "001", name: "web-01", count: 130 },
      { agentId: "002", name: "db-01", count: 20 },
    ]);
    expect(agentTotals(sources, 1)).toHaveLength(1);
  });

  it("handles no sources", () => {
    expect(countryTotals([])).toEqual([]);
    expect(asnTotals([])).toEqual([]);
    expect(internalTotals([])).toEqual({ alerts: 0, sources: 0 });
  });
});

describe("map shades and changes", () => {
  it("steps a count to one of five shades on a square-root scale", () => {
    expect(shadeStep(0, 100)).toBe(0);
    expect(shadeStep(5, 0)).toBe(0);
    expect(shadeStep(1, 10_000)).toBe(1);
    expect(shadeStep(100, 100)).toBe(5);
    expect(shadeStep(50, 100)).toBe(4);
    expect(shadeStep(10, 100)).toBe(2);
    for (let n = 1; n <= 100; n++) {
      const step = shadeStep(n, 100);
      expect(step).toBeGreaterThanOrEqual(1);
      expect(step).toBeLessThanOrEqual(5);
      expect(step).toBeGreaterThanOrEqual(shadeStep(n - 1, 100));
    }
  });

  it("describes the change against the period before", () => {
    expect(changeOf(10, null)).toBeNull();
    expect(changeOf(10, 10)).toEqual({ kind: "same", by: 0 });
    expect(changeOf(15, 10)).toEqual({ kind: "up", by: 5 });
    expect(changeOf(4, 10)).toEqual({ kind: "down", by: 6 });
  });

  it("falls back to 24 hours for a window it does not know", () => {
    expect(windowOf("7d")).toBe("7d");
    expect(windowOf("1h")).toBe("24h");
    expect(windowOf(undefined)).toBe("24h");
  });
});

describe("arcs on the globe", () => {
  it("has three stroke steps on the square-root scale, none for no alerts", () => {
    expect(ARC_STEPS).toBe(3);
    expect(arcStep(0, 100)).toBe(0);
    expect(arcStep(1, 100)).toBe(1);
    expect(arcStep(11, 100)).toBe(1);
    expect(arcStep(12, 100)).toBe(2);
    expect(arcStep(44, 100)).toBe(2);
    expect(arcStep(45, 100)).toBe(3);
    expect(arcStep(100, 100)).toBe(3);
    // Never more than the highest step, and never a step for an empty maximum.
    expect(arcStep(500, 100)).toBe(3);
    expect(arcStep(5, 0)).toBe(0);
  });
  it("never invents precision: neighbouring counts share a step", () => {
    const steps = new Set(Array.from({ length: 100 }, (_, i) => arcStep(i + 1, 100)));
    expect([...steps].sort()).toEqual([1, 2, 3]);
  });
  it("calls an arc high only above an abuse score of 80, and only with OSINT on and a score", () => {
    expect(arcTone(81, true)).toBe("high");
    expect(arcTone(100, true)).toBe("high");
    expect(arcTone(80, true)).toBe("observed");
    expect(arcTone(10, true)).toBe("observed");
    expect(arcTone(99, false)).toBe("observed");
    expect(arcTone(null, true)).toBe("observed");
    expect(arcTone(undefined, true)).toBe("observed");
  });
});

describe("sources of two origins (ADR 0022)", () => {
  const wazuh = [
    source({
      ip: "198.51.100.1",
      count: 100,
      agents: [{ agentId: "001", name: "web-01", count: 100 }],
      firstSeen: "2026-10-20T00:00:00.000Z",
      lastSeen: "2026-10-22T08:00:00.000Z",
    }),
    source({ ip: "198.51.100.2", count: 5, country: "FR" }),
  ];
  const unifi = [
    source({
      ip: "198.51.100.1",
      count: 40,
      blocked: 30,
      groups: [],
      firstSeen: "2026-10-21T00:00:00.000Z",
      lastSeen: "2026-10-22T09:00:00.000Z",
    }),
    source({ ip: "203.0.113.9", count: 7, blocked: 7, groups: [], country: "NL" }),
  ];

  it("joins an address that both saw into one row with the counts added", () => {
    const merged = mergeSources(wazuh, unifi);
    expect(merged.map((s) => [s.ip, s.count, s.blocked ?? 0])).toEqual([
      ["198.51.100.1", 140, 30],
      ["203.0.113.9", 7, 7],
      ["198.51.100.2", 5, 0],
    ]);
    const joined = merged[0] as AttackSource;
    expect(joined.firstSeen).toBe("2026-10-20T00:00:00.000Z");
    expect(joined.lastSeen).toBe("2026-10-22T09:00:00.000Z");
    expect(joined.agents).toEqual([{ agentId: "001", name: "web-01", count: 100 }]);
    // The inputs are not changed.
    expect(wazuh[0]?.count).toBe(100);
  });

  it("joins by the canonical form of the address", () => {
    const merged = mergeSources(
      [source({ ip: "2001:db8::1", count: 1 })],
      [source({ ip: "2001:0db8:0:0:0:0:0:1", count: 2, blocked: 2 })],
      (ip) => canonicalIp(ip) ?? ip,
    );
    expect(merged).toHaveLength(1);
    expect(merged[0]?.count).toBe(3);
  });

  it("counts blocked events per country and leaves the key out when there are none", () => {
    const totals = countryTotals(mergeSources(wazuh, unifi));
    expect(totals.find((t) => t.country === "DE")).toMatchObject({ alerts: 140, blocked: 30 });
    expect(totals.find((t) => t.country === "NL")).toMatchObject({ alerts: 7, blocked: 7 });
    expect("blocked" in (totals.find((t) => t.country === "FR") as object)).toBe(false);
  });
});
