import type { BadgeTone } from "../components/ui/badge.tsx";
import type { HostRow } from "./types.ts";

export type ServerStateKey =
  | "hostKeyChanged"
  | "hostKeyPending"
  | "hostKeyWaiting"
  | "queued"
  | "running"
  | "failed"
  | "neverRead"
  | "read";

/**
 * What to tell about a server in one word. Green is never used: a server that was read is not
 * proof of anything (AGENTS.md rule 6). A changed host key outranks everything, because it can
 * mean someone is intercepting the connection.
 */
export function serverState(host: Pick<HostRow, "hostKey" | "run" | "lastError" | "lastInventoryAt">): {
  key: ServerStateKey;
  tone: BadgeTone;
} {
  if (host.hostKey.status === "changed") return { key: "hostKeyChanged", tone: "critical" };
  if (host.hostKey.status === "pending") {
    if (host.hostKey.candidate) return { key: "hostKeyPending", tone: "info" };
    return host.lastError ? { key: "failed", tone: "critical" } : { key: "hostKeyWaiting", tone: "neutral" };
  }
  if (host.run?.state === "queued") return { key: "queued", tone: "info" };
  if (host.run?.state === "running") return { key: "running", tone: "info" };
  if (host.run?.state === "failed" || host.lastError) return { key: "failed", tone: "critical" };
  return host.lastInventoryAt ? { key: "read", tone: "neutral" } : { key: "neverRead", tone: "neutral" };
}

/** The list keeps refreshing while the worker is busy with a server. */
export function serverIsBusy(host: Pick<HostRow, "hostKey" | "run" | "lastError">): boolean {
  if (host.run?.state === "queued" || host.run?.state === "running") return true;
  // A new server waits for its host key to be read.
  return host.hostKey.status === "pending" && !host.hostKey.candidate && !host.lastError;
}
