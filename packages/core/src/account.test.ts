import { describe, expect, it } from "vitest";
import { describeUserAgent, isTimeZone, mayRemovePasskey } from "./account.ts";

describe("mayRemovePasskey: never zero second factors", () => {
  it("allows removing a passkey while the authenticator app stays", () => {
    expect(mayRemovePasskey({ totpEnrolled: true, passkeys: 1 })).toBe(true);
    expect(mayRemovePasskey({ totpEnrolled: true, passkeys: 3 })).toBe(true);
  });

  it("allows removing one of several passkeys without an authenticator app", () => {
    expect(mayRemovePasskey({ totpEnrolled: false, passkeys: 2 })).toBe(true);
  });

  it("refuses removing the last factor", () => {
    expect(mayRemovePasskey({ totpEnrolled: false, passkeys: 1 })).toBe(false);
  });

  it("has nothing to remove without a passkey", () => {
    expect(mayRemovePasskey({ totpEnrolled: true, passkeys: 0 })).toBe(false);
  });
});

describe("isTimeZone", () => {
  it("accepts IANA zones", () => {
    for (const zone of ["UTC", "Europe/Berlin", "America/Argentina/Buenos_Aires", "Etc/GMT+5"]) {
      expect(isTimeZone(zone), zone).toBe(true);
    }
  });

  it("refuses anything else", () => {
    for (const zone of ["", "Mars/Olympus", "Europe/Berlin; drop", "x".repeat(65), "../etc"]) {
      expect(isTimeZone(zone), zone).toBe(false);
    }
  });
});

describe("describeUserAgent", () => {
  const cases: [string, { browser: string; os: string }][] = [
    [
      "Mozilla/5.0 (X11; Linux x86_64; rv:130.0) Gecko/20100101 Firefox/130.0",
      { browser: "Firefox", os: "Linux" },
    ],
    [
      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36 Edg/129.0.0.0",
      { browser: "Edge", os: "Windows" },
    ],
    [
      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36",
      { browser: "Chrome", os: "Windows" },
    ],
    [
      "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15",
      { browser: "Safari", os: "macOS" },
    ],
    [
      "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1",
      { browser: "Safari", os: "iOS" },
    ],
    [
      "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Mobile Safari/537.36",
      { browser: "Chrome", os: "Android" },
    ],
  ];
  it.each(cases)("%s", (ua, expected) => {
    expect(describeUserAgent(ua)).toEqual(expected);
  });

  it("copes with a missing or odd user agent", () => {
    expect(describeUserAgent(null)).toEqual({ browser: "", os: "" });
    expect(describeUserAgent("")).toEqual({ browser: "", os: "" });
    expect(describeUserAgent("x".repeat(100_000))).toEqual({ browser: "", os: "" });
  });
});
