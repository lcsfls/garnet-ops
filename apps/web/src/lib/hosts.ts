/**
 * Hosts and containers on the web side (ADR 0034): the shapes the API sends, the Compose file for a new host, and the small
 * decisions the screens share. Everything a host reported (names, labels, image references) is hostile text the API cleaned; the
 * screens still render it as text only.
 */
import type { BadgeTone } from "./components/ui/tones.ts";

export type SeverityCounts = { critical: number; high: number; medium: number; low: number };

export interface KernelSummary {
  release: string | null;
  package: { name: string; version: string; distro: string } | null;
  problem: "unknownDistribution" | "unknownVersion" | "unsupportedDistribution" | null;
  matchedAt: string | null;
  matchError: string | null;
}

export interface KernelFinding {
  id: string;
  vulnerabilityId: string;
  packageName: string;
  packageVersion: string;
  fixedIn: string[] | null;
  fixState: string | null;
  severity: "critical" | "high" | "medium" | "low" | "negligible" | "unknown";
  severityRank: number;
  firstSeenAt: string;
  cvssScore: number | null;
  knownExploited: boolean;
}

/** Where a host's kernel stands: affected, no known flaw, not checked (with the reason), or no report from an older agent. */
export type KernelState = "affected" | "clean" | "waiting" | "failed" | "problem" | "oldAgent";
export function kernelState(kernel: KernelSummary, findings: number): KernelState {
  if (!kernel.release) return "oldAgent";
  if (kernel.problem) return "problem";
  if (kernel.matchError) return "failed";
  if (!kernel.matchedAt) return "waiting";
  return findings > 0 ? "affected" : "clean";
}

export interface HostRow {
  id: string;
  name: string;
  hostname: string;
  agentVersion: string | null;
  dockerVersion: string | null;
  os: string | null;
  enrolledAt: string;
  lastSeenAt: string | null;
  lastInventoryAt: string | null;
  reporting: boolean;
  containers: number;
  images: number;
  open: SeverityCounts;
  updatesAvailable: number;
  /** `total` counts every finding, also those the distribution has not rated yet. */
  kernel: KernelSummary & { open: SeverityCounts & { total: number } };
}

export type UpdateState = "unchecked" | "current" | "newer-build" | "newer-version" | "failed";
export interface UpdateInfo {
  state: UpdateState;
  tag: string | null;
  kind: "major" | "minor" | "patch" | null;
}

export interface HostContainer {
  containerId: string;
  name: string;
  imageRef: string;
  imageId: string;
  state: string;
  startedAt: string | null;
  firstSeenAt: string;
  lastSeenAt: string;
  revision: string | null;
  packagesAt: string | null;
  matchedAt: string | null;
  matchError: string | null;
  repository: { id: string; name: string } | null;
  open: SeverityCounts;
  update: UpdateInfo;
}

export interface HostDetail
  extends Omit<HostRow, "containers" | "images" | "open" | "updatesAvailable" | "kernel"> {
  containers: HostContainer[];
  kernel: KernelSummary & { findings: KernelFinding[] };
}

export interface ImageFinding {
  id: string;
  vulnerabilityId: string;
  packageName: string;
  packageVersion: string;
  packageType: string;
  fixedIn: string[] | null;
  fixState: string | null;
  severity: "critical" | "high" | "medium" | "low" | "negligible" | "unknown";
  severityRank: number;
  firstSeenAt: string;
  cvssScore: number | null;
  knownExploited: boolean;
  epss: number | null;
}

export interface ImageDetail {
  imageId: string;
  tags: string[];
  digests: string[];
  os: string | null;
  architecture: string | null;
  builtAt: string | null;
  labels: Record<string, string>;
  distro: string | null;
  packageCount: number | null;
  packagesAt: string | null;
  matchedAt: string | null;
  matchError: string | null;
  repository: { id: string; name: string } | null;
  running: {
    hostId: string;
    hostName: string;
    containerId: string;
    name: string;
    imageRef: string;
    state: string;
  }[];
  findings: ImageFinding[];
  updates: (UpdateInfo & { ref: string; checkedAt: string | null })[];
}

export interface RunningContainer {
  hostId: string;
  hostName: string;
  containerId: string;
  name: string;
  imageRef: string;
  imageId: string;
  revision: string | null;
  lastSeenAt: string;
  open: SeverityCounts;
}

export interface HostSettings {
  registryChecks: { enabled: boolean; enabledAt: string | null; enabledBy: string | null };
  agent: { image: string; serverUrl: string };
}

export interface Enrolment {
  id: string;
  code: string;
  expiresAt: string;
  image: string;
  serverUrl: string;
}

/** Updates never look like proof: a newer image is information, a current one is plain text (AGENTS.md rule 6). */
export const UPDATE_TONE: Record<UpdateState, BadgeTone> = {
  unchecked: "neutral",
  current: "neutral",
  "newer-build": "info",
  "newer-version": "info",
  failed: "neutral",
};

/** The first 12 characters of an image id, as Docker shows it. */
export const shortId = (id: string) => id.replace(/^sha256:/, "").slice(0, 12);

/** A YAML string that cannot break out of its line. */
const yaml = (value: string) => JSON.stringify(value);

/** The Compose file for a new host: the read-only Docker proxy and the agent, hardened, with the one-time code. */
export function composeFile(input: {
  image: string;
  serverUrl: string;
  code: string;
  hostName?: string;
}): string {
  return [
    "# GarnetOps host agent (ADR 0034). Save as docker-compose.yml on the host and run: docker compose up -d",
    "services:",
    "  # The only part with the Docker socket: forwards read requests only, and has no network.",
    "  docker-proxy:",
    `    image: ${yaml(input.image)}`,
    '    command: ["node", "apps/agent/src/main.ts", "proxy"]',
    '    user: "0:0"',
    "    restart: unless-stopped",
    "    read_only: true",
    "    cap_drop: [ALL]",
    '    security_opt: ["no-new-privileges:true"]',
    "    network_mode: none",
    "    volumes:",
    "      - /var/run/docker.sock:/var/run/docker.sock:ro",
    "      - proxy-socket:/run/garnetops-agent",
    "  # Reads the running containers through the proxy and reports to GarnetOps over HTTPS.",
    "  agent:",
    `    image: ${yaml(input.image)}`,
    "    restart: unless-stopped",
    "    read_only: true",
    "    cap_drop: [ALL]",
    '    security_opt: ["no-new-privileges:true"]',
    "    depends_on: [docker-proxy]",
    "    environment:",
    `      GARNETOPS_URL: ${yaml(input.serverUrl)}`,
    "      # Used once to enrol; you may remove it afterwards.",
    `      GARNETOPS_ENROLMENT_CODE: ${yaml(input.code)}`,
    ...(input.hostName ? [`      GARNETOPS_HOST_NAME: ${yaml(input.hostName)}`] : []),
    "    tmpfs:",
    "      # syft reads each image here; make it as large as your largest image.",
    "      - /tmp:size=4g",
    "    volumes:",
    "      - proxy-socket:/run/garnetops-agent",
    "      - agent-state:/var/lib/garnetops-agent",
    "volumes:",
    "  proxy-socket:",
    "  agent-state:",
    "",
  ].join("\n");
}
