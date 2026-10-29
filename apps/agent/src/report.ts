/**
 * One report of the agent (ADR 0034): enrol if this host has no identity yet, send the inventory of running containers and their
 * images, then the package lists GarnetOps asks for.
 */
import { hostname } from "node:os";
import { newAgentKeyPair } from "@garnetops/core/agent";
import type { Identity, Server } from "./client.ts";
import { type DockerImage, dockerVersion, inspectImage, runningContainers } from "./docker.ts";
import { loadIdentity, saveIdentity } from "./state.ts";
import { readPackages } from "./syft.ts";

export const AGENT_VERSION = process.env.APP_VERSION ?? "dev";

export interface ReportDeps {
  server: Server;
  stateDir: string;
  dockerSocket: string;
  syftBin: string;
  enrolmentCode?: string;
  hostName?: string;
  log?: (line: string) => void;
}

/** The identity of this host, enrolling with the one-time code the first time. */
export async function ensureIdentity(deps: ReportDeps): Promise<Identity> {
  const existing = await loadIdentity(deps.stateDir);
  if (existing) return existing;
  if (!deps.enrolmentCode)
    throw new Error("Not enrolled yet: set GARNETOPS_ENROLMENT_CODE to the code from Monitoring, Hosts");
  const keys = newAgentKeyPair();
  const { hostId } = await deps.server.post<{ hostId: string }>("/enrol", {
    code: deps.enrolmentCode,
    publicKey: keys.publicKey,
    hostname: deps.hostName || hostname(),
    agentVersion: AGENT_VERSION,
  });
  const identity = { hostId, privateKeyPem: keys.privateKeyPem };
  await saveIdentity(deps.stateDir, identity);
  deps.log?.(`agent: enrolled as ${hostId}`);
  return identity;
}

/** One inventory and the package lists asked for. Returns how many package lists were sent. */
export async function reportOnce(deps: ReportDeps): Promise<{ containers: number; packageLists: number }> {
  const identity = await ensureIdentity(deps);
  const [docker, containers] = await Promise.all([
    dockerVersion(deps.dockerSocket),
    runningContainers(deps.dockerSocket),
  ]);
  const images: DockerImage[] = [];
  for (const id of new Set(containers.map((c) => c.imageId))) {
    try {
      images.push(await inspectImage(deps.dockerSocket, id));
    } catch (error) {
      // A container can outlive its image (removed or pruned); it is reported without the image's details.
      deps.log?.(`agent: image ${id.replace(/^sha256:/, "").slice(0, 12)}: ${(error as Error).message}`);
    }
  }
  const { needPackages } = await deps.server.post<{ needPackages: string[] }>(
    "/inventory",
    {
      hostname: deps.hostName || hostname(),
      agentVersion: AGENT_VERSION,
      dockerVersion: docker.version,
      os: docker.os,
      containers,
      images,
    },
    identity,
  );
  let sent = 0;
  for (const imageId of needPackages ?? []) {
    try {
      const list = await readPackages(deps.syftBin, deps.dockerSocket, imageId);
      await deps.server.post("/packages", { imageId, ...list }, identity);
      sent += 1;
    } catch (error) {
      // One image that syft cannot read does not stop the others; it is asked for again next time.
      deps.log?.(`agent: packages of ${imageId.slice(0, 12)}: ${(error as Error).message}`);
    }
  }
  return { containers: containers.length, packageLists: sent };
}
