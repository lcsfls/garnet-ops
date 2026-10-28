import type { PgBoss } from "pg-boss";

/**
 * Queues of the modules removed in 0.0.4 (ADR 0025): servers, Proxmox VE, UniFi, Wazuh/XDR, the attack
 * overview and external exposure. An earlier version created them and scheduled jobs on some, and
 * pg-boss keeps both in the database. Without this clean-up the schedules would go on sending jobs
 * that nobody works on, and the System status page would list queues that never drain.
 */
export const RETIRED_QUEUES = [
  "host.access-key",
  "host.keyscan",
  "host.inventory",
  "proxmox.certificate",
  "proxmox.sync",
  "proxmox.sync-tick",
  "unifi.certificate",
  "unifi.sync",
  "unifi.sync-tick",
  "exposure.verify",
  "exposure.run",
  "exposure.tick",
  "xdr.certificate",
  "xdr.sync",
  "xdr.sync-tick",
  "xdr.summary",
  "attacks.summary",
  "attacks.maintenance",
] as const;

export type Queues = Pick<PgBoss, "unschedule" | "deleteQueue" | "getQueues">;

/**
 * Removes the schedules and the queues (with their waiting jobs) of the retired modules. Safe to run
 * on every start: a queue that does not exist is skipped. Returns the names it removed. A failure is
 * logged and never stops the worker.
 */
export async function removeRetiredQueues(boss: Queues): Promise<string[]> {
  const removed: string[] = [];
  try {
    const existing = new Set((await boss.getQueues([...RETIRED_QUEUES])).map((q) => q.name));
    for (const name of RETIRED_QUEUES) {
      if (!existing.has(name)) continue;
      await boss.unschedule(name).catch(() => {});
      await boss.deleteQueue(name);
      removed.push(name);
    }
  } catch (error) {
    console.error("retired queues:", (error as Error)?.name ?? "error");
  }
  return removed;
}
