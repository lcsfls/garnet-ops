import { describe, expect, it } from "vitest";
import { ABUSEIPDB, OSINT_LIMITS, osintProvider, scoreBand } from "./osint.ts";

const answer = (data: Record<string, unknown>) => ({ data: { ipAddress: "198.51.100.77", ...data } });

describe("AbuseIPDB provider", () => {
  it("builds one GET request for a public address, with the key only in a header", () => {
    const request = ABUSEIPDB.request("198.51.100.77", "k".repeat(40));
    expect(request.method).toBe("GET");
    expect(request.path).toBe("/api/v2/check?ipAddress=198.51.100.77&maxAgeInDays=90");
    expect(request.headers.Key).toBe("k".repeat(40));
    expect(request.path).not.toContain("k".repeat(10));
    expect(ABUSEIPDB.host).toBe("api.abuseipdb.com");
  });

  it("encodes IPv6 and normalises IPv4-mapped addresses", () => {
    expect(ABUSEIPDB.request("2001:db8::bad", "k".repeat(40)).path).toContain(
      "ipAddress=2001%3Adb8%3A0%3A0%3A0%3A0%3A0%3Abad",
    );
    expect(ABUSEIPDB.request("::ffff:198.51.100.77", "k".repeat(40)).path).toContain(
      "ipAddress=198.51.100.77",
    );
  });

  it("never builds a request for an internal or invalid address", () => {
    for (const ip of [
      "10.0.0.1",
      "192.168.1.1",
      "127.0.0.1",
      "169.254.169.254",
      "fd00::1",
      "224.0.0.1",
      "nope",
      "198.51.100.1&x=1",
    ]) {
      expect(() => ABUSEIPDB.request(ip, "k".repeat(40)), ip).toThrow();
    }
  });

  it("checks a key before it is stored", () => {
    expect(ABUSEIPDB.keyProblem("")).toBe("empty");
    expect(ABUSEIPDB.keyProblem("short")).toBe("tooShort");
    expect(ABUSEIPDB.keyProblem("x".repeat(129))).toBe("tooLong");
    expect(ABUSEIPDB.keyProblem(`${"a".repeat(30)}\n`)).toBe("characters");
    expect(ABUSEIPDB.keyProblem(`${"a".repeat(30)} `)).toBe("characters");
    expect(ABUSEIPDB.keyProblem("0123456789abcdef0123456789abcdef")).toBeNull();
  });

  it("reads the score, the reports and the last report, and nothing else", () => {
    const parsed = ABUSEIPDB.parse(
      answer({
        abuseConfidenceScore: 91,
        totalReports: 120,
        lastReportedAt: "2026-10-22T06:00:00+00:00",
        isp: "<script>alert(1)</script>",
        domain: "evil.example",
        hostnames: ["x"],
      }),
      "198.51.100.77",
    );
    expect(parsed).toEqual({ score: 91, reports: 120, lastReportedAt: new Date("2026-10-22T06:00:00Z") });
    expect(JSON.stringify(parsed)).not.toContain("script");
  });

  it("accepts an answer without a last report and an equivalent spelling of the address", () => {
    expect(
      ABUSEIPDB.parse(
        answer({ abuseConfidenceScore: 0, totalReports: 0, lastReportedAt: null }),
        "198.51.100.77",
      ),
    ).toEqual({
      score: 0,
      reports: 0,
      lastReportedAt: null,
    });
    expect(
      ABUSEIPDB.parse(
        { data: { ipAddress: "2001:db8:0:0:0:0:0:bad", abuseConfidenceScore: 5, totalReports: 1 } },
        "2001:db8::bad",
      )?.score,
    ).toBe(5);
  });

  it("refuses answers that do not fit: another address, no score, out-of-range or non-numbers, wrong shapes", () => {
    const bad: unknown[] = [
      null,
      "x",
      [],
      {},
      { data: null },
      { data: [] },
      answer({ ipAddress: "203.0.113.9", abuseConfidenceScore: 5 }),
      answer({}),
      answer({ abuseConfidenceScore: -1 }),
      answer({ abuseConfidenceScore: 101 }),
      answer({ abuseConfidenceScore: "50" }),
      answer({ abuseConfidenceScore: 50.5 }),
      answer({ abuseConfidenceScore: Number.NaN }),
      { data: { abuseConfidenceScore: 5 } },
      { errors: [{ detail: "Daily rate limit of 1000 requests exceeded." }] },
    ];
    for (const body of bad) expect(ABUSEIPDB.parse(body, "198.51.100.77"), JSON.stringify(body)).toBeNull();
  });

  it("bounds the report count and ignores implausible dates", () => {
    expect(
      ABUSEIPDB.parse(answer({ abuseConfidenceScore: 1, totalReports: 1e12 }), "198.51.100.77")?.reports,
    ).toBe(0);
    expect(
      ABUSEIPDB.parse(answer({ abuseConfidenceScore: 1, totalReports: -3 }), "198.51.100.77")?.reports,
    ).toBe(0);
    for (const lastReportedAt of [
      "1970-01-01T00:00:00Z",
      "9999-12-31T00:00:00Z",
      "garbage",
      "x".repeat(100),
      12345,
    ]) {
      expect(
        ABUSEIPDB.parse(answer({ abuseConfidenceScore: 1, lastReportedAt }), "198.51.100.77")?.lastReportedAt,
        String(lastReportedAt),
      ).toBeNull();
    }
  });

  it("is a registered provider whose terms are not confirmed, and the budget stays below the free tier", () => {
    expect(osintProvider("abuseipdb")).toBe(ABUSEIPDB);
    expect(osintProvider("someone-else")).toBeNull();
    expect(osintProvider("__proto__")).toBeNull();
    expect(ABUSEIPDB.termsConfirmed).toBe(false);
    expect(OSINT_LIMITS.dailyBudget.max).toBeLessThan(ABUSEIPDB.freeDailyLimit);
    expect(OSINT_LIMITS.cacheHours).toBe(24);
  });

  it("bands scores for the table", () => {
    expect(scoreBand(0)).toBe("low");
    expect(scoreBand(24)).toBe("low");
    expect(scoreBand(25)).toBe("medium");
    expect(scoreBand(74)).toBe("medium");
    expect(scoreBand(75)).toBe("high");
    expect(scoreBand(100)).toBe("high");
  });
});
