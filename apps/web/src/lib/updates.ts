import type { MaintenanceView } from "@restow-backup/cicd-updater/maintenance";
import type { PublicStatus, ReleasesView, StateView } from "@restow-backup/cicd-updater/protocol";
import { isNewer } from "@restow-backup/cicd-updater/semver";
import { api } from "./api.ts";

/**
 * The browser's side of in-app updates (ADR 0007). The browser only ever talks to
 * GarnetOps' own API; the sidecar's token never leaves the API container. While the
 * API itself is down for the update, the banner reads the sidecar's public status
 * through the reverse proxy (`/public/v1/status`, read-only, no token).
 */

/** `GET /api/v1/updates`: null state means there is no sidecar on this installation. */
export interface AdminUpdatesView {
  state: StateView | null;
  leadTimes: readonly number[];
  stepUpMaxAgeSeconds: number;
}

export const updatesApi = {
  status: () => api<AdminUpdatesView>("/updates"),
  releases: (refresh = false) => api<ReleasesView>(`/updates/releases${refresh ? "?refresh=1" : ""}`),
  schedule: (body: { version: string; leadSeconds: number; releaseSha256: string }) =>
    api<StateView>("/updates", { method: "POST", body }),
  cancel: (runId: string) =>
    api<StateView>(`/updates/${encodeURIComponent(runId)}/cancel`, { method: "POST", body: {} }),
  acknowledge: (runId: string) =>
    api<StateView>(`/updates/${encodeURIComponent(runId)}/acknowledge`, { method: "POST", body: {} }),
};

/**
 * The update state for owners and admins, shared by Settings → Updates and the dot at Settings in the sidebar. The
 * sidecar checks for releases once a day, so the sidebar asks every ten minutes; the panel asks more often itself.
 */
export const updatesStatusQuery = {
  queryKey: ["updates"],
  queryFn: updatesApi.status,
  retry: false,
  refetchInterval: 10 * 60_000,
} as const;

/**
 * Tells the banner that this browser just changed the update state (scheduled, cancelled,
 * acknowledged), so it asks again at once instead of at its next poll.
 */
export const maintenanceChanged = new EventTarget();
export const notifyMaintenanceChanged = () => maintenanceChanged.dispatchEvent(new Event("change"));

/** For the banner: must throw when the API does not answer, which switches to the public status. */
export async function fetchMaintenance(): Promise<MaintenanceView> {
  const response = await fetch("/api/v1/maintenance", { credentials: "same-origin", cache: "no-store" });
  if (!response.ok) throw new Error(`HTTP ${response.status}`);
  return (await response.json()) as MaintenanceView;
}

/** The sidecar's public status through the reverse proxy, while the API is down. */
export async function fetchPublicStatus(): Promise<PublicStatus | null> {
  const response = await fetch("/public/v1/status", { cache: "no-store" });
  if (!response.ok || !response.headers.get("content-type")?.includes("json")) return null;
  return (await response.json()) as PublicStatus;
}

/**
 * The newer release the sidecar's daily check found, for the dot at Settings: null without a sidecar, without a newer
 * release, or while an update is already scheduled or running (the banner shows that one).
 */
export function availableUpdate(state: StateView | null | undefined): string | null {
  const latest = state?.updater.latestAvailable;
  const running = state?.running.version;
  if (!state || !latest || !running || state.phase === "scheduled" || state.phase === "running") return null;
  return isNewer(running, latest) === true ? latest : null;
}

/** The finished update whose banner this browser closed; the banner of a later update shows again. */
const DISMISSED_KEY = "garnetops.updateBanner.dismissed";

export function dismissedUpdateRun(): string | null {
  try {
    return localStorage.getItem(DISMISSED_KEY);
  } catch {
    return null;
  }
}

export function dismissUpdateRun(runId: string): void {
  try {
    localStorage.setItem(DISMISSED_KEY, runId);
  } catch {
    // Not kept: the banner stays closed for this page view only.
  }
}
