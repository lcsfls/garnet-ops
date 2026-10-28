import { describe, expect, it, vi } from "vitest";
import { type Queues, RETIRED_QUEUES, removeRetiredQueues } from "./retired-queues.ts";

const fake = (existing: string[]) => {
  const calls: string[] = [];
  return {
    calls,
    boss: {
      getQueues: vi.fn(async () => existing.map((name) => ({ name }))),
      unschedule: vi.fn(async (name: string) => {
        calls.push(`unschedule ${name}`);
      }),
      deleteQueue: vi.fn(async (name: string) => {
        calls.push(`delete ${name}`);
      }),
    },
  };
};

describe("retired queues (ADR 0025)", () => {
  it("names each queue once and never a queue that is still in use", () => {
    expect(new Set(RETIRED_QUEUES).size).toBe(RETIRED_QUEUES.length);
    for (const live of [
      "scan.repository",
      "scan.schedule-tick",
      "notify.deliver",
      "directory.request",
      "ai.generate",
      "ai.probe",
      "fix-pr.create",
      "fix-pr.check",
      "fix-pr.refresh",
    ]) {
      expect(RETIRED_QUEUES).not.toContain(live);
    }
  });

  it("removes the schedule and the queue of the retired queues that exist, and nothing else", async () => {
    const { boss, calls } = fake(["proxmox.sync", "proxmox.sync-tick"]);
    const removed = await removeRetiredQueues(boss as unknown as Queues);
    expect(removed).toEqual(["proxmox.sync", "proxmox.sync-tick"]);
    expect(calls).toEqual([
      "unschedule proxmox.sync",
      "delete proxmox.sync",
      "unschedule proxmox.sync-tick",
      "delete proxmox.sync-tick",
    ]);
  });

  it("does nothing on a fresh installation and survives a failing queue API", async () => {
    const empty = fake([]);
    expect(await removeRetiredQueues(empty.boss as unknown as Queues)).toEqual([]);
    expect(empty.calls).toEqual([]);

    const broken = fake(["xdr.sync"]);
    broken.boss.deleteQueue.mockRejectedValue(new Error("database is down"));
    const log = vi.spyOn(console, "error").mockImplementation(() => {});
    expect(await removeRetiredQueues(broken.boss as unknown as Queues)).toEqual([]);
    expect(log).toHaveBeenCalledWith("retired queues:", "Error");
    log.mockRestore();
  });
});
