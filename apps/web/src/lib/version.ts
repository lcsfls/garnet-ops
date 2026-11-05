/**
 * Release versions stay plain semver (the updater accepts nothing else); the stage is shown as a label next to the number
 * instead: 0.0.x releases are the alpha, the other 0.x releases the beta ("0.1.0 Beta"), from 1.0.0 on there is no label.
 */
export type ReleaseStage = "alpha" | "beta";

export function releaseStage(version: string): ReleaseStage | null {
  const m = /^0\.(\d+)\.\d+$/.exec(version);
  if (!m) return null;
  return m[1] === "0" ? "alpha" : "beta";
}

export function displayVersion(version: string, labels: Record<ReleaseStage, string>): string {
  const stage = releaseStage(version);
  return stage ? `${version} ${labels[stage]}` : version;
}
