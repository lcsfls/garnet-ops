import { EXPOSURE_ERRORS, EXPOSURE_PORTS, EXPOSURE_RULES, PORT_CATEGORIES } from "@garnetops/core/exposure";
import { resources } from "@garnetops/i18n";
import { describe, expect, it } from "vitest";
import {
  busy,
  daysUntil,
  type ExposureAsset,
  isBusy,
  knownError,
  stage1Key,
  stage2Key,
  VERIFICATION_TONE,
  verificationKey,
} from "./exposure.ts";
import { exposureDetailSearch, exposureSearch, SETTINGS_SECTIONS } from "./search.ts";

const en = resources.en.translation;
const exposure = en.exposure as unknown as Record<string, Record<string, unknown>>;

function asset(over: Partial<ExposureAsset> = {}): ExposureAsset {
  return {
    id: "exa_1",
    kind: "domain",
    value: "www.example.com",
    includeSubdomains: false,
    verification: {
      state: "unverified",
      method: null,
      confirmedAt: null,
      checkedAt: null,
      error: null,
      effective: false,
      via: null,
      parent: null,
    },
    stage1: { enabled: true, lastAt: null, error: null, run: null, summary: null },
    stage2: {
      enabled: false,
      schedule: "daily",
      acknowledgedAt: null,
      lastAt: null,
      error: null,
      run: null,
      summary: null,
      nextManualAt: null,
    },
    open: { critical: 0, high: 0, medium: 0, low: 0 },
    createdAt: "2026-10-22T10:00:00.000Z",
    ...over,
  };
}
const run = (state: "queued" | "running" | "succeeded" | "failed") => ({
  id: "exr_1",
  state,
  trigger: "manual" as const,
  error: null,
  createdAt: "2026-10-22T10:00:00.000Z",
  finishedAt: null,
});

describe("states", () => {
  it("shows verification as one word, covered when a parent verifies it", () => {
    expect(verificationKey(asset())).toBe("unverified");
    const v = asset().verification;
    expect(verificationKey(asset({ verification: { ...v, state: "verified" } }))).toBe("verified");
    expect(verificationKey(asset({ verification: { ...v, state: "lost" } }))).toBe("lost");
    expect(verificationKey(asset({ verification: { ...v, effective: true, via: "parent" } }))).toBe(
      "covered",
    );
  });

  it("never colours a verification green: a proof of control is no security result", () => {
    for (const tone of Object.values(VERIFICATION_TONE)) expect(tone).not.toBe("success");
    expect(VERIFICATION_TONE.lost).toBe("critical");
  });

  it("names what stage 1 is doing: a run in progress wins, then a failure, then whether it ever worked", () => {
    expect(stage1Key(asset())).toBe("never");
    const s1 = asset().stage1;
    expect(stage1Key(asset({ stage1: { ...s1, enabled: false } }))).toBe("paused");
    expect(stage1Key(asset({ stage1: { ...s1, lastAt: "2026-10-22T10:00:00Z" } }))).toBe("ok");
    expect(stage1Key(asset({ stage1: { ...s1, lastAt: "2026-10-22T10:00:00Z", error: "timeout" } }))).toBe(
      "failed",
    );
    expect(stage1Key(asset({ stage1: { ...s1, error: "timeout", run: run("running") } }))).toBe("running");
    expect(stage1Key(asset({ stage1: { ...s1, run: run("queued") } }))).toBe("queued");
  });

  it("names what stage 2 is doing", () => {
    expect(stage2Key(asset())).toBe("off");
    const s2 = asset().stage2;
    expect(stage2Key(asset({ stage2: { ...s2, enabled: true } }))).toBe("waiting");
    expect(stage2Key(asset({ stage2: { ...s2, enabled: true, lastAt: "2026-10-22T10:00:00Z" } }))).toBe("on");
    expect(stage2Key(asset({ stage2: { ...s2, enabled: true, error: "notVerified" } }))).toBe("failed");
    expect(stage2Key(asset({ stage2: { ...s2, enabled: false, run: run("running") } }))).toBe("off");
    expect(stage2Key(asset({ stage2: { ...s2, enabled: true, run: run("running") } }))).toBe("running");
  });

  it("looks again soon while a run is waiting or running", () => {
    expect(busy(null)).toBe(false);
    expect(busy(run("succeeded"))).toBe(false);
    expect(busy(run("queued"))).toBe(true);
    expect(isBusy(asset())).toBe(false);
    expect(isBusy(asset({ stage1: { ...asset().stage1, run: run("running") } }))).toBe(true);
  });

  it("counts whole days to an instant", () => {
    const now = new Date("2026-10-22T12:00:00Z");
    expect(daysUntil("2026-10-25T12:00:00Z", now)).toBe(3);
    expect(daysUntil("2026-10-22T11:00:00Z", now)).toBe(-1);
    expect(daysUntil(null, now)).toBeNull();
  });

  it("knows the error codes of this version and shows others as they are", () => {
    expect(knownError("dnsNoMatch")).toBe("dnsNoMatch");
    expect(knownError("somethingNew")).toBeNull();
    expect(knownError(null)).toBeNull();
  });
});

describe("translations", () => {
  it("has a title and a sentence for every rule", () => {
    const rules = exposure.rules as Record<string, { title: string; text: string }>;
    for (const rule of EXPOSURE_RULES) {
      expect(rules[rule]?.title, rule).toBeTruthy();
      expect(rules[rule]?.text, rule).toBeTruthy();
    }
    expect(Object.keys(rules).sort()).toEqual([...EXPOSURE_RULES].sort());
  });
  it("has a name for every service of the port list and every category", () => {
    for (const port of EXPOSURE_PORTS) expect(exposure.service?.[port.service], port.service).toBeTruthy();
    for (const category of PORT_CATEGORIES) expect(exposure.category?.[category], category).toBeTruthy();
  });
  it("has a sentence for every error code", () => {
    for (const code of EXPOSURE_ERRORS) expect(exposure.error?.[code], code).toBeTruthy();
  });
  it("has the settings section and the navigation entry", () => {
    expect(SETTINGS_SECTIONS).toContain("exposure");
    expect(en.nav.exposure).toBeTruthy();
    expect(en.settings.sectionExposure).toBeTruthy();
  });
});

describe("search parameters", () => {
  it("fall back to the default for values that are not valid", () => {
    expect(exposureSearch.parse({ status: "nonsense", sort: "nonsense", dir: "up", pageSize: 7 })).toEqual(
      {},
    );
    expect(
      exposureSearch.parse({ status: "attention", sort: "certificate", dir: "desc", q: "example", add: "1" }),
    ).toEqual({
      status: "attention",
      sort: "certificate",
      dir: "desc",
      q: "example",
      add: "1",
    });
    expect(
      exposureDetailSearch.parse({ tab: "ports", verify: "1", stage2: "1", findings: "resolved" }),
    ).toEqual({
      tab: "ports",
      verify: "1",
      stage2: "1",
      findings: "resolved",
    });
    expect(exposureDetailSearch.parse({ tab: "nonsense", verify: "2" })).toEqual({});
  });
});
