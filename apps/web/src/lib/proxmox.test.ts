import { describe, expect, it } from "vitest";
import { FLAG_ORDER, FLAG_TONE, PVEUM_COMMANDS, usage } from "./proxmox.ts";
import { formatBytesIn, formatDuration } from "./units.ts";

describe("sizes and durations", () => {
  it("writes bytes with binary units", () => {
    expect(formatBytesIn(0, "en")).toBe("0 B");
    expect(formatBytesIn(1023, "en")).toBe("1,023 B");
    expect(formatBytesIn(1024, "en")).toBe("1 KiB");
    expect(formatBytesIn(1.5 * 1024 ** 3, "en")).toBe("1.5 GiB");
    expect(formatBytesIn(32 * 1024 ** 3, "en")).toBe("32 GiB");
    expect(formatBytesIn(2 * 1024 ** 4, "en")).toBe("2 TiB");
  });

  it("writes durations with the two largest units", () => {
    expect(formatDuration(30)).toBe("< 1 min");
    expect(formatDuration(600)).toBe("10 min");
    expect(formatDuration(3 * 3600 + 5 * 60)).toBe("3 h 5 min");
    expect(formatDuration(90_061)).toBe("1 d 1 h");
    expect(formatDuration(2_592_000)).toBe("30 d 0 h");
  });
});

describe("usage", () => {
  it("is a share between 0 and 1, or unknown", () => {
    expect(usage(1, 4)).toBe(0.25);
    expect(usage(5, 4)).toBe(1);
    expect(usage(0, 4)).toBe(0);
    expect(usage(null, 4)).toBeNull();
    expect(usage(1, null)).toBeNull();
    expect(usage(1, 0)).toBeNull();
  });
});

describe("flags", () => {
  it("every flag has a tone and a place", () => {
    expect([...FLAG_ORDER].sort()).toEqual(Object.keys(FLAG_TONE).sort());
  });
});

describe("token commands", () => {
  it("create a dedicated user with the auditor role and a token with privilege separation", () => {
    expect(PVEUM_COMMANDS).toContain("--roles PVEAuditor");
    expect(PVEUM_COMMANDS).toContain("--privsep 1");
    expect(PVEUM_COMMANDS).not.toMatch(/root@pam|password|--roles (Administrator|PVEAdmin)/i);
    // Only example names.
    expect(PVEUM_COMMANDS).toContain("garnetops@pve");
  });
});
