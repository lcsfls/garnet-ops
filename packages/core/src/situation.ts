/**
 * The situation per vulnerability (ADR 0052): which systems have it, in which state, and what fixes it. Pure: the API reads the
 * findings of repositories, running containers and hosts, and these rules say what a row means. What fixes a finding follows from
 * where its package comes from, never from a model.
 */

export const SITUATION_KINDS = ["repository", "container", "host"] as const;
export type SituationKind = (typeof SITUATION_KINDS)[number];

/**
 * - `affected`: the vulnerable version is there;
 * - `not-reachable`: it is there, and the system's configuration does not allow the flaw;
 * - `not-checked`: GarnetOps has no current answer for the system (never a "fine").
 */
export const SITUATION_STATUSES = ["affected", "not-reachable", "not-checked"] as const;
export type SituationStatus = (typeof SITUATION_STATUSES)[number];

/**
 * Who has to do what:
 * - `server-package`: update a package (or the kernel) with the host's package manager;
 * - `server-image`: pull a newer image, for a container no repository of ours builds;
 * - `repository-dependency`: raise a dependency in a repository;
 * - `repository-base-image`: raise the base image of an image a repository builds, or rebuild it;
 * - `vendor`: no fixed version is known yet.
 */
export const FIX_PATHS = [
  "server-package",
  "server-image",
  "repository-dependency",
  "repository-base-image",
  "vendor",
] as const;
export type FixPath = (typeof FIX_PATHS)[number];

/** Whether the fix is a server action or a commit; `vendor` is neither yet. */
export const FIX_SIDE: Record<FixPath, "server" | "repository" | "none"> = {
  "server-package": "server",
  "server-image": "server",
  "repository-dependency": "repository",
  "repository-base-image": "repository",
  vendor: "none",
};

/**
 * Package types that come with an image's base (the distribution's packages, and binaries syft finds outside a package manager,
 * such as the `nginx` or `node` binary of an official image), as syft names them. Everything else is a language package.
 */
const BASE_IMAGE_TYPES = new Set(["deb", "rpm", "apk", "alpm", "portage", "binary", "linux-kernel", "nix"]);
export const isBaseImagePackage = (packageType: string): boolean => BASE_IMAGE_TYPES.has(packageType);

/** A fixed version is known (what grype calls fixed). */
export const fixKnown = (fixedIn: readonly string[] | null | undefined): boolean =>
  (fixedIn ?? []).some((v) => v.trim() !== "");

/** What fixes a finding, from where its package comes from. */
export function fixPathOf(input: {
  kind: SituationKind;
  packageType: string;
  fixedIn: readonly string[] | null | undefined;
  /** For a container: a repository of the organisation builds its image (linked by the image's source label). */
  builtByRepository?: boolean;
}): FixPath {
  if (!fixKnown(input.fixedIn)) return "vendor";
  if (input.kind === "host") return "server-package";
  if (input.kind === "repository") return "repository-dependency";
  if (!input.builtByRepository) return "server-image";
  return isBaseImagePackage(input.packageType) ? "repository-base-image" : "repository-dependency";
}

/** One system's worst state for a vulnerability: affected beats not reachable. */
export function worstStatus(statuses: readonly SituationStatus[]): SituationStatus {
  if (statuses.includes("affected")) return "affected";
  if (statuses.includes("not-reachable")) return "not-reachable";
  return "not-checked";
}

/** How many systems the page of one vulnerability lists; the rest is counted. */
export const SITUATION_MAX_SYSTEMS = 500;
