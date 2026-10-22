/**
 * Which Proxmox guests deserve a look (ADR 0012). Pure functions and constants without Node
 * imports, so the API, the worker and the web app share one definition.
 */

/** A guest that has been stopped for longer than this is flagged (we measure from when we first saw it stopped). */
export const STALE_STOPPED_DAYS = 30;
/** A guest whose newest backup is older than this, or that has none, is flagged. */
export const STALE_BACKUP_DAYS = 7;
/** A guest whose oldest snapshot is older than this is flagged (snapshots are not backups and slow the guest down). */
export const STALE_SNAPSHOT_DAYS = 30;
/** How often the worker syncs every connected cluster. */
export const PROXMOX_SYNC_INTERVAL_MINUTES = 15;

export const GUEST_FLAGS = ["stoppedLong", "noRecentBackup", "oldSnapshot", "untracked"] as const;
export type GuestFlag = (typeof GUEST_FLAGS)[number];

export const GUEST_STATUSES = ["running", "stopped", "paused", "other"] as const;
export type GuestStatus = (typeof GUEST_STATUSES)[number];

export interface GuestFlagInput {
  status: GuestStatus;
  template: boolean;
  /** When GarnetOps first saw the guest in its current status. */
  statusSince: Date | null;
  lastBackupAt: Date | null;
  oldestSnapshotAt: Date | null;
  /** False when the token may not list backups: then "no recent backup" cannot be told and is not flagged. */
  backupsReadable: boolean;
  /** A server in the Servers list is linked to this guest. */
  linked: boolean;
}

const DAY_MS = 24 * 60 * 60 * 1000;
const olderThan = (when: Date, days: number, now: Date) => now.getTime() - when.getTime() > days * DAY_MS;

/** The flags of one guest at `now`. Templates are never flagged: they are not meant to run or be backed up. */
export function guestFlags(g: GuestFlagInput, now: Date): GuestFlag[] {
  const flags: GuestFlag[] = [];
  if (g.template) return flags;
  if (g.status === "stopped" && g.statusSince && olderThan(g.statusSince, STALE_STOPPED_DAYS, now)) {
    flags.push("stoppedLong");
  }
  if (g.backupsReadable && (!g.lastBackupAt || olderThan(g.lastBackupAt, STALE_BACKUP_DAYS, now))) {
    flags.push("noRecentBackup");
  }
  if (g.oldestSnapshotAt && olderThan(g.oldestSnapshotAt, STALE_SNAPSHOT_DAYS, now)) {
    flags.push("oldSnapshot");
  }
  if (g.status === "running" && !g.linked) flags.push("untracked");
  return flags;
}

/** Reference that links a server to a guest: `host.source_ref` for source `proxmox`. */
export const proxmoxSourceRef = (clusterId: string, vmid: number) => `${clusterId}:${vmid}`;

const SOURCE_REF = /^(pxc_[a-z0-9]{10,40}):([1-9][0-9]{0,8})$/;
/** Splits a source reference, or null if it is not one. */
export function parseProxmoxSourceRef(ref: string): { clusterId: string; vmid: number } | null {
  const m = SOURCE_REF.exec(ref);
  return m ? { clusterId: m[1] as string, vmid: Number(m[2]) } : null;
}
