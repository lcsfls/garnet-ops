import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import {
  ageDays,
  appVersionOf,
  buildProviderLevel,
  cleanVersion,
  freshnessOf,
  HEARTBEAT_LATE_AFTER_SECONDS,
  integrationState,
  isolationLevel,
  levelOfFreshness,
  levelOfIntegration,
  overallLevel,
  PINNED_SCANNERS,
  parseVersionOutput,
  queueLevel,
  SYNC_STALE_AFTER_INTERVALS,
  scannerLevel,
  scannerMatch,
  VULNDB_OUTDATED_AFTER_DAYS,
  VULNDB_STALE_AFTER_DAYS,
  vulnDbBuildReportSchema,
  vulnDbFreshness,
  vulnDbReportSchema,
  vulnDbUpdateReason,
  vulnDbUpdateReportSchema,
  workerLiveness,
  worstLevel,
  worstState,
} from "./system-status.ts";

const NOW = new Date("2026-10-23T12:00:00.000Z");
const DAY = 86_400_000;
const ago = (ms: number) => new Date(NOW.getTime() - ms);

describe("pinned scanner versions", () => {
  it("are the versions scripts/fetch-scanners.mjs downloads and checks", () => {
    const script = readFileSync(
      fileURLToPath(new URL("../../../scripts/fetch-scanners.mjs", import.meta.url)),
      "utf8",
    );
    for (const [name, version] of Object.entries(PINNED_SCANNERS)) {
      expect(script).toMatch(new RegExp(`name: "${name}",\\s*version: "${version.replaceAll(".", "\\.")}"`));
    }
  });
});

describe("vulnerability database freshness", () => {
  it("documents the limits: amber after 3 days, vermilion after 7", () => {
    expect(VULNDB_STALE_AFTER_DAYS).toBe(3);
    expect(VULNDB_OUTDATED_AFTER_DAYS).toBe(7);
  });

  it("is current up to and including 3 days, stale after, outdated after 7", () => {
    expect(vulnDbFreshness(ago(0), NOW)).toBe("current");
    expect(vulnDbFreshness(ago(3 * DAY), NOW)).toBe("current");
    expect(vulnDbFreshness(ago(3 * DAY + 1), NOW)).toBe("stale");
    expect(vulnDbFreshness(ago(7 * DAY), NOW)).toBe("stale");
    expect(vulnDbFreshness(ago(7 * DAY + 1), NOW)).toBe("outdated");
  });

  it("treats a date in the future as current and a missing or broken one as unknown", () => {
    expect(vulnDbFreshness(new Date(NOW.getTime() + DAY), NOW)).toBe("current");
    expect(vulnDbFreshness(null, NOW)).toBe("unknown");
    expect(vulnDbFreshness("not a date", NOW)).toBe("unknown");
  });

  it("maps to levels: neutral, amber, vermilion", () => {
    expect(levelOfFreshness("current")).toBe("ok");
    expect(levelOfFreshness("stale")).toBe("attention");
    expect(levelOfFreshness("unknown")).toBe("attention");
    expect(levelOfFreshness("outdated")).toBe("failed");
  });

  it("counts whole days", () => {
    expect(ageDays(ago(2.9 * DAY), NOW)).toBe(2);
    expect(ageDays(new Date(NOW.getTime() + DAY), NOW)).toBe(0);
    expect(ageDays(undefined, NOW)).toBeNull();
  });

  it("works with any limits", () => {
    expect(freshnessOf(ago(2 * DAY), NOW, 1, 5)).toBe("stale");
  });
});

describe("scanners", () => {
  it("cleans versions the way the tools print them", () => {
    expect(cleanVersion("v1.55.0")).toBe("1.55.0");
    expect(cleanVersion(" 0.120.1 ")).toBe("0.120.1");
    expect(cleanVersion("1.2.3-rc.1")).toBe("1.2.3-rc.1");
    expect(cleanVersion("dev")).toBeNull();
    expect(cleanVersion("1.2")).toBeNull();
    expect(cleanVersion(null)).toBeNull();
  });

  it("matches the pinned version, shows a different one and knows when it cannot tell", () => {
    expect(scannerMatch("grype", PINNED_SCANNERS.grype)).toBe("match");
    expect(scannerMatch("syft", `v${PINNED_SCANNERS.syft}`)).toBe("match");
    expect(scannerMatch("grype", "0.1.0")).toBe("differs");
    expect(scannerMatch("grype", null)).toBe("unknown");
    expect(scannerMatch("grype", "weird")).toBe("unknown");
  });

  it("levels: a match is neutral, a difference needs a look, a missing binary fails, an unset syft is inactive", () => {
    expect(scannerLevel("match", null)).toBe("ok");
    expect(scannerLevel("differs", null)).toBe("attention");
    expect(scannerLevel("unknown", null)).toBe("attention");
    expect(scannerLevel("unknown", "missing")).toBe("failed");
    expect(scannerLevel("unknown", "not_configured")).toBe("inactive");
  });

  it("isolation (ADR 0028): the service is fine, the worker needs a look, a silent service fails", () => {
    expect(isolationLevel("service", true)).toBe("ok");
    expect(isolationLevel("service", true, false)).toBe("attention");
    expect(isolationLevel("service", false)).toBe("failed");
    expect(isolationLevel("worker", null)).toBe("attention");
    expect(isolationLevel(null, null)).toBe("inactive");
  });

  it("reads the version out of `grype version` and `syft version`", () => {
    const grype =
      "Application:         grype\nVersion:             0.120.1\nBuildDate:           2026-10-06T20:41:29Z\n";
    const syft = "Application:   syft\nVersion:       1.55.0\nBuildDate:     2026-10-19T18:54:46Z\n";
    expect(parseVersionOutput(grype)).toBe("0.120.1");
    expect(parseVersionOutput(syft)).toBe("1.55.0");
    expect(parseVersionOutput("Syft Version:        v1.54.1\n")).toBeNull();
    expect(parseVersionOutput("")).toBeNull();
  });
});

describe("app version", () => {
  it("takes a release version and falls back to the 0.0.12 alpha", () => {
    expect(appVersionOf("0.1.0")).toBe("0.1.0");
    expect(appVersionOf("1.2.3-rc.1")).toBe("1.2.3-rc.1");
    expect(appVersionOf("latest")).toBe("0.0.12");
    expect(appVersionOf(undefined)).toBe("0.0.12");
  });
});

describe("worker", () => {
  it("is running up to three missed beats, late after, missing without a beat", () => {
    expect(HEARTBEAT_LATE_AFTER_SECONDS).toBe(90);
    expect(workerLiveness(ago(10_000), NOW)).toBe("running");
    expect(workerLiveness(ago(90_000), NOW)).toBe("running");
    expect(workerLiveness(ago(91_000), NOW)).toBe("late");
    expect(workerLiveness(null, NOW)).toBe("missing");
  });

  it("flags a queue with failed jobs in 24 hours or a long wait", () => {
    expect(queueLevel({ failed24h: 0, oldestQueuedSeconds: null })).toBe("ok");
    expect(queueLevel({ failed24h: 0, oldestQueuedSeconds: 60 })).toBe("ok");
    expect(queueLevel({ failed24h: 1, oldestQueuedSeconds: null })).toBe("attention");
    expect(queueLevel({ failed24h: 0, oldestQueuedSeconds: 16 * 60 })).toBe("attention");
  });
});

describe("integration state", () => {
  const base = {
    configured: true,
    enabled: true,
    blocked: null,
    lastSuccessAt: ago(5 * 60_000),
    lastAttemptOk: true,
    expectedEveryMs: 15 * 60_000,
  } as const;

  it("is current after a recent success", () => {
    expect(integrationState(base, NOW)).toBe("current");
  });

  it("is stale after three missed intervals", () => {
    expect(SYNC_STALE_AFTER_INTERVALS).toBe(3);
    expect(integrationState({ ...base, lastSuccessAt: ago(45 * 60_000) }, NOW)).toBe("current");
    expect(integrationState({ ...base, lastSuccessAt: ago(45 * 60_000 + 1) }, NOW)).toBe("stale");
  });

  it("never goes stale when it only runs on request", () => {
    expect(integrationState({ ...base, expectedEveryMs: null, lastSuccessAt: ago(400 * DAY) }, NOW)).toBe(
      "current",
    );
  });

  it("is waiting before the first success", () => {
    expect(integrationState({ ...base, lastSuccessAt: null, lastAttemptOk: null }, NOW)).toBe("waiting");
  });

  it("fails when the last attempt failed, even if an older one worked", () => {
    expect(integrationState({ ...base, lastAttemptOk: false }, NOW)).toBe("failed");
  });

  it("is blocked before anything else that is configured and enabled", () => {
    expect(integrationState({ ...base, blocked: "certificate", lastAttemptOk: false }, NOW)).toBe("blocked");
  });

  it("is paused when switched off, even when blocked, and not configured without a connection", () => {
    expect(integrationState({ ...base, enabled: false, blocked: "credentials" }, NOW)).toBe("paused");
    expect(integrationState({ ...base, configured: false }, NOW)).toBe("not_configured");
  });

  it("maps states to levels", () => {
    expect(levelOfIntegration("current")).toBe("ok");
    expect(levelOfIntegration("stale")).toBe("attention");
    expect(levelOfIntegration("blocked")).toBe("attention");
    expect(levelOfIntegration("waiting")).toBe("attention");
    expect(levelOfIntegration("failed")).toBe("failed");
    expect(levelOfIntegration("paused")).toBe("inactive");
    expect(levelOfIntegration("not_configured")).toBe("inactive");
  });

  it("stands several connections for by the one that needs the reader most", () => {
    expect(worstState(["current", "failed", "paused"])).toBe("failed");
    expect(worstState(["current", "blocked", "stale"])).toBe("blocked");
    expect(worstState(["paused", "current"])).toBe("current");
    expect(worstState(["paused", "paused"])).toBe("paused");
    expect(worstState([])).toBe("not_configured");
  });
});

describe("levels", () => {
  it("takes the worst, and an overall verdict ignores inactive rows", () => {
    expect(worstLevel(["ok", "attention", "inactive"])).toBe("attention");
    expect(worstLevel(["ok", "failed", "attention"])).toBe("failed");
    expect(worstLevel([])).toBe("inactive");
    expect(overallLevel(["inactive", "inactive"])).toBe("ok");
    expect(overallLevel(["ok", "inactive"])).toBe("ok");
    expect(overallLevel(["ok", "attention"])).toBe("attention");
  });
});

describe("update failures", () => {
  it("become short codes and never carry the tool's words", () => {
    expect(vulnDbUpdateReason({ message: "grype timed out" })).toBe("timeout");
    expect(vulnDbUpdateReason({ message: "Could not start /opt/scanners/grype: ENOENT" })).toBe(
      "not_started",
    );
    expect(
      vulnDbUpdateReason({
        message: "grype exited with code 1",
        stderr: "dial tcp: lookup grype.example.com: no such host",
      }),
    ).toBe("network");
    expect(vulnDbUpdateReason({ message: "grype exited with code 1", stderr: "checksum mismatch" })).toBe(
      "checksum",
    );
    expect(
      vulnDbUpdateReason({ message: "grype exited with code 1", stderr: "write: no space left on device" }),
    ).toBe("storage");
    expect(vulnDbUpdateReason({ message: "grype exited with code 1", stderr: "something odd" })).toBe(
      "failed",
    );
    expect(vulnDbUpdateReason(null)).toBe("failed");
  });
});

describe("reports", () => {
  it("accepts the vulnerability database report and drops what is not in the shape", () => {
    const ok = vulnDbReportSchema.safeParse({
      checkedAt: NOW.toISOString(),
      valid: true,
      problem: null,
      schemaVersion: "6.1.5",
      builtAt: "2026-10-22T06:39:15Z",
      source: "anchore",
      providers: {
        available: true,
        items: [{ name: "nvd", version: "6", capturedAt: null, records: 250000 }],
      },
    });
    expect(ok.success).toBe(true);
    expect(vulnDbReportSchema.safeParse({ valid: true }).success).toBe(false);
    expect(vulnDbReportSchema.safeParse(null).success).toBe(false);
  });

  it("accepts the update report", () => {
    expect(
      vulnDbUpdateReportSchema.safeParse({
        mode: "auto",
        lastAttemptAt: NOW.toISOString(),
        lastSuccessAt: null,
        lastResult: "failed",
        reason: "network",
        nextAt: null,
      }).success,
    ).toBe(true);
    expect(vulnDbUpdateReportSchema.safeParse({ mode: "weekly" }).success).toBe(false);
  });
});

describe("local build report (the builder's future report shape)", () => {
  const report = {
    v: 1,
    enabled: true,
    providers: [
      {
        name: "nvd",
        lastRunAt: NOW.toISOString(),
        result: "ok",
        records: 250_000,
        durationMs: 420_000,
        reason: null,
      },
      {
        name: "debian",
        lastRunAt: NOW.toISOString(),
        result: "failed",
        records: null,
        durationMs: 1_000,
        reason: "network",
      },
    ],
  };

  it("takes one entry per provider", () => {
    const parsed = vulnDbBuildReportSchema.parse(report);
    expect(parsed.providers.map((p) => p.name)).toEqual(["nvd", "debian"]);
  });

  it("keeps working when a later version adds fields", () => {
    const later = {
      ...report,
      v: 2,
      builderVersion: "2.0.0",
      providers: report.providers.map((p) => ({ ...p, inputDigest: "sha256:0" })),
    };
    expect(vulnDbBuildReportSchema.safeParse(later).success).toBe(true);
  });

  it("refuses a provider without a name or a result outside the known ones", () => {
    expect(
      vulnDbBuildReportSchema.safeParse({ ...report, providers: [{ ...report.providers[0], name: "" }] })
        .success,
    ).toBe(false);
    expect(
      vulnDbBuildReportSchema.safeParse({
        ...report,
        providers: [{ ...report.providers[0], result: "weird" }],
      }).success,
    ).toBe(false);
  });

  it("levels a provider by its result", () => {
    expect(buildProviderLevel("ok")).toBe("ok");
    expect(buildProviderLevel("failed")).toBe("failed");
    expect(buildProviderLevel("skipped")).toBe("attention");
    expect(buildProviderLevel(null)).toBe("attention");
  });
});
