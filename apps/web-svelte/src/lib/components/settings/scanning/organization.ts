/** `GET /organization`: the nightly scan schedule and its last runs. */
export interface Organization {
  id: string;
  name: string;
  scanSchedule: { enabled: boolean; localTime: string; timeZone: string };
  lastRuns: { localDate: string; queuedScans: number; createdAt: string }[];
}

/** IANA zones known to the browser, with UTC first and the stored zone always present. */
export function timeZonesWith(current: string): string[] {
  const zones = new Set<string>(["UTC", current]);
  for (const zone of Intl.supportedValuesOf("timeZone")) zones.add(zone);
  return ["UTC", ...[...zones].filter((z) => z !== "UTC").sort()];
}
