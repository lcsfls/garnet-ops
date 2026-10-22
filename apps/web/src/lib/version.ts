/**
 * Release versions stay plain semver (the updater accepts nothing else); every 0.x release
 * is an alpha, so the stage is shown as a label next to the number: "0.0.1 Alpha".
 */
export function displayVersion(version: string, alphaLabel: string): string {
  return /^0\.\d+\.\d+$/.test(version) ? `${version} ${alphaLabel}` : version;
}
