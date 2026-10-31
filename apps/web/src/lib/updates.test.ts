import type { StateView } from "@restow-backup/cicd-updater/protocol";
import { describe, expect, it } from "vitest";
import { availableUpdate } from "./updates.ts";

const state = (over: {
  latest?: string | null;
  running?: string | null;
  phase?: StateView["phase"];
}): StateView =>
  ({
    phase: over.phase ?? "idle",
    updater: { version: "1.0.0", configHash: "0".repeat(64), latestAvailable: over.latest ?? null },
    running: { version: over.running === undefined ? "0.0.14" : over.running, source: "health" },
  }) as StateView;

describe("availableUpdate", () => {
  it("names a newer release found by the daily check", () => {
    expect(availableUpdate(state({ latest: "0.0.15" }))).toBe("0.0.15");
    expect(availableUpdate(state({ latest: "0.1.0", running: "0.0.14" }))).toBe("0.1.0");
  });

  it("says nothing for the running release, an older one or none", () => {
    expect(availableUpdate(state({ latest: "0.0.14" }))).toBeNull();
    expect(availableUpdate(state({ latest: "0.0.13" }))).toBeNull();
    expect(availableUpdate(state({ latest: null }))).toBeNull();
  });

  it("says nothing without a sidecar, an unknown running version or something that is not a version", () => {
    expect(availableUpdate(null)).toBeNull();
    expect(availableUpdate(undefined)).toBeNull();
    expect(availableUpdate(state({ latest: "0.0.15", running: null }))).toBeNull();
    expect(availableUpdate(state({ latest: "latest" }))).toBeNull();
  });

  it("leaves a scheduled or running update to the banner", () => {
    expect(availableUpdate(state({ latest: "0.0.15", phase: "scheduled" }))).toBeNull();
    expect(availableUpdate(state({ latest: "0.0.15", phase: "running" }))).toBeNull();
    expect(availableUpdate(state({ latest: "0.0.15", phase: "succeeded" }))).toBe("0.0.15");
  });
});
