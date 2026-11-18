/**
 * Whether the package of a repository finding is in a running image built from that repository (ADR 0054). Pure: the states, the
 * reasons for having no answer, and the package types where "not found" says less than it seems. The answer is a fact about the
 * image as the agent read it; it never changes a finding, a grade or a gate.
 */
export const IMAGE_PRESENCE = ["in-image", "not-in-image"] as const;
export type ImagePresence = (typeof IMAGE_PRESENCE)[number];

/** Why there is no answer: the Agents module is off, no agent reports a container built from the repository, or its image is not read yet. */
export const PRESENCE_UNKNOWN = ["module-off", "no-image", "not-read"] as const;
export type PresenceUnknown = (typeof PRESENCE_UNKNOWN)[number];

/** The filter values of the findings list. */
export const IMAGE_FILTERS = ["in", "not-in"] as const;
export type ImageFilter = (typeof IMAGE_FILTERS)[number];

/**
 * What "not found in the image" cannot rule out, by package type:
 * - `bundled`: front-end packages are compiled into script files, where no package list names them;
 * - `compiled`: a binary names its crates only when it was built to (cargo auditable).
 * Go modules are named by the binary itself, and installed packages (deb, apk, rpm, Python, PHP, Ruby, jars) by their files.
 */
export const PRESENCE_CAVEATS = { npm: "bundled", "rust-crate": "compiled" } as const;
export type PresenceCaveat = (typeof PRESENCE_CAVEATS)[keyof typeof PRESENCE_CAVEATS];
export const presenceCaveatOf = (packageType: string): PresenceCaveat | null =>
  (PRESENCE_CAVEATS as Record<string, PresenceCaveat>)[packageType] ?? null;

/** Names are compared without case: registries and package lists do not agree on it (Django, django). */
export const presenceName = (name: string): string => name.toLowerCase();

/**
 * The answer for one package from what the agent reported: `images` running images built from the repository, `read` of them
 * with a package list, and whether any of those lists names the package.
 */
export function imagePresence(input: {
  hostsOn: boolean;
  images: number;
  read: number;
  found: boolean;
}): { state: ImagePresence; reason: null } | { state: null; reason: PresenceUnknown } {
  if (!input.hostsOn) return { state: null, reason: "module-off" };
  if (input.images === 0) return { state: null, reason: "no-image" };
  if (input.found) return { state: "in-image", reason: null };
  // An image that could not be read is no evidence of absence.
  if (input.read === 0) return { state: null, reason: "not-read" };
  return { state: "not-in-image", reason: null };
}
