import { describe, expect, it } from "vitest";
import { serverIsBusy, serverState } from "./servers.ts";
import type { HostRow } from "./types.ts";

const base = {
  hostKey: {
    status: "confirmed",
    type: "ssh-ed25519",
    fingerprint: "SHA256:x",
    confirmedAt: null,
    candidate: null,
  },
  run: null,
  lastError: null,
  lastInventoryAt: null,
} as Pick<HostRow, "hostKey" | "run" | "lastError" | "lastInventoryAt">;
const withKey = (
  status: HostRow["hostKey"]["status"],
  candidate: HostRow["hostKey"]["candidate"] = null,
) => ({
  ...base,
  hostKey: { ...base.hostKey, status, candidate },
});
const run = (state: "queued" | "running" | "succeeded" | "failed") =>
  ({ id: "r", state, trigger: "manual", error: null, createdAt: "", finishedAt: null }) as HostRow["run"];

describe("serverState", () => {
  it("puts a changed host key above everything", () => {
    expect(
      serverState({
        ...withKey("changed", { type: "ssh-ed25519", fingerprint: "SHA256:y", seenAt: null }),
        run: run("running"),
      }),
    ).toEqual({
      key: "hostKeyChanged",
      tone: "critical",
    });
  });

  it("waits for the host key, then asks for its confirmation", () => {
    expect(serverState(withKey("pending"))).toEqual({ key: "hostKeyWaiting", tone: "neutral" });
    expect(
      serverState({
        ...withKey("pending"),
        lastError: "No SSH host key could be read from the server. Check the address and port.",
      }),
    ).toEqual({
      key: "failed",
      tone: "critical",
    });
    expect(
      serverState(withKey("pending", { type: "ssh-ed25519", fingerprint: "SHA256:y", seenAt: null })),
    ).toEqual({
      key: "hostKeyPending",
      tone: "info",
    });
  });

  it("shows the run in progress, a failure, or the last result, and never uses success green", () => {
    expect(serverState({ ...base, run: run("queued") }).key).toBe("queued");
    expect(serverState({ ...base, run: run("running") }).key).toBe("running");
    expect(
      serverState({ ...base, run: run("failed"), lastError: "The server could not be reached." }),
    ).toEqual({ key: "failed", tone: "critical" });
    expect(serverState({ ...base, run: run("succeeded"), lastInventoryAt: "2026-10-21T00:00:00Z" })).toEqual({
      key: "read",
      tone: "neutral",
    });
    expect(serverState(base)).toEqual({ key: "neverRead", tone: "neutral" });
    for (const state of ["queued", "running", "failed", "succeeded"] as const) {
      expect(
        serverState({ ...base, run: run(state), lastError: state === "failed" ? "x" : null }).tone,
      ).not.toBe("success");
    }
  });
});

describe("serverIsBusy", () => {
  it("is true while the worker has something to do for the server", () => {
    expect(serverIsBusy({ ...base, run: run("queued") })).toBe(true);
    expect(serverIsBusy({ ...base, run: run("running") })).toBe(true);
    expect(serverIsBusy(withKey("pending"))).toBe(true);
    expect(
      serverIsBusy(withKey("pending", { type: "ssh-ed25519", fingerprint: "SHA256:y", seenAt: null })),
    ).toBe(false);
    expect(serverIsBusy({ ...withKey("pending"), lastError: "x" })).toBe(false);
    expect(serverIsBusy({ ...base, run: run("succeeded") })).toBe(false);
  });
});
