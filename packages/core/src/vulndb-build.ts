/**
 * The installation's own vulnerability database build (vunnel and grype-db in a separate builder container). Two optional,
 * installation-wide keys make the public feeds faster to read: a GitHub token for the GitHub Advisory Database and an NVD API key.
 * Both are sealed by the API, opened only by the worker, and handed to the builder for one build. Each key is sent only to its
 * own host. Keep this file free of Node-only imports: the web app imports it too.
 */

/** The one row of `vulndb_build_settings`. */
export const VULNDB_BUILD_SETTINGS_ID = "installation";

/** The shapes the two keys are accepted in; anything else is refused before it is sealed. */
export const VULNDB_BUILD_KEYS = {
  /** A classic personal access token or a fine-grained one. No scopes are needed: public advisories only. */
  githubToken: /^(ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{22,255})$/,
  /** NVD issues API keys as UUIDs. */
  nvdApiKey: /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/,
} as const;

/** The only host each key is sent to. */
export const VULNDB_BUILD_HOSTS = {
  /** vunnel's `github` provider reads the GitHub Advisory Database through the GraphQL API there. */
  githubToken: "api.github.com",
  nvdApiKey: "services.nvd.nist.gov",
} as const;

export type VulnDbBuildKey = keyof typeof VULNDB_BUILD_KEYS;

/** Whether a value has the shape of the given key. Surrounding whitespace is not part of a key. */
export function isVulnDbBuildKey(kind: VulnDbBuildKey, value: string): boolean {
  return VULNDB_BUILD_KEYS[kind].test(value.trim());
}
