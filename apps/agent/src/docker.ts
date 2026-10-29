/**
 * Reading Docker through the proxy (ADR 0034): the running containers and the images they use. Only GET requests; answers are capped
 * and checked before the agent sends anything on. The API version is left to Docker (no version prefix).
 */
import { request } from "node:http";
import { z } from "zod";

const MAX_ANSWER = 16 * 1024 * 1024;

export class DockerError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "DockerError";
  }
}

/** GET a path on the Docker API over a Unix socket and parse the JSON answer. */
export function dockerGet(socket: string, path: string, timeoutMs = 30_000): Promise<unknown> {
  return new Promise((resolve, reject) => {
    const req = request(
      { socketPath: socket, method: "GET", path, headers: { host: "docker" }, timeout: timeoutMs },
      (res) => {
        const chunks: Buffer[] = [];
        let size = 0;
        res.on("data", (chunk: Buffer) => {
          size += chunk.length;
          if (size > MAX_ANSWER) {
            res.destroy();
            reject(new DockerError("answer too large"));
            return;
          }
          chunks.push(chunk);
        });
        res.on("end", () => {
          if ((res.statusCode ?? 0) >= 300)
            return reject(new DockerError(`Docker answered ${res.statusCode}`));
          try {
            resolve(JSON.parse(Buffer.concat(chunks).toString("utf8")));
          } catch {
            reject(new DockerError("Docker sent no JSON"));
          }
        });
        res.on("error", reject);
      },
    );
    req.on("timeout", () => req.destroy(new DockerError("Docker did not answer in time")));
    req.on("error", (error) => reject(error instanceof DockerError ? error : new DockerError(error.message)));
    req.end();
  });
}

const containerList = z.array(
  z.object({
    Id: z.string(),
    Names: z.array(z.string()).default([]),
    Image: z.string(),
    ImageID: z.string(),
    State: z.string().default("unknown"),
    Created: z.number().optional(),
  }),
);

const imageInspect = z.object({
  Id: z.string(),
  RepoTags: z.array(z.string()).nullish(),
  RepoDigests: z.array(z.string()).nullish(),
  Os: z.string().nullish(),
  Architecture: z.string().nullish(),
  Created: z.string().nullish(),
  Config: z.object({ Labels: z.record(z.string(), z.string()).nullish() }).nullish(),
});

const version = z.object({ Version: z.string().optional(), Os: z.string().optional() });
const info = z.object({
  OperatingSystem: z.string().optional(),
  OSVersion: z.string().optional(),
  KernelVersion: z.string().optional(),
  Architecture: z.string().optional(),
});

export interface DockerContainer {
  id: string;
  name: string;
  image: string;
  imageId: string;
  state: string;
  startedAt: string | null;
}

export interface DockerImage {
  id: string;
  tags: string[];
  digests: string[];
  os: string | null;
  architecture: string | null;
  created: string | null;
  labels: Record<string, string>;
}

export async function dockerVersion(socket: string): Promise<{ version: string | null; os: string | null }> {
  const v = version.parse(await dockerGet(socket, "/version"));
  return { version: v.Version ?? null, os: v.Os ?? null };
}

/** The running containers. */
export async function runningContainers(socket: string): Promise<DockerContainer[]> {
  const list = containerList.parse(await dockerGet(socket, "/containers/json"));
  return list.map((c) => ({
    id: c.Id,
    name: c.Names[0] ?? c.Id.slice(0, 12),
    image: c.Image,
    imageId: c.ImageID,
    state: c.State,
    startedAt: c.Created ? new Date(c.Created * 1000).toISOString() : null,
  }));
}

/** What an image says about itself. Labels are filtered again by the server; the agent sends only the OCI ones. */
export async function inspectImage(socket: string, id: string): Promise<DockerImage> {
  const i = imageInspect.parse(await dockerGet(socket, `/images/${encodeURIComponent(id)}/json`));
  const labels = Object.fromEntries(
    Object.entries(i.Config?.Labels ?? {}).filter(([k]) => k.startsWith("org.opencontainers.image.")),
  );
  const created =
    i.Created && !Number.isNaN(Date.parse(i.Created)) ? new Date(i.Created).toISOString() : null;
  return {
    id: i.Id,
    tags: i.RepoTags ?? [],
    digests: i.RepoDigests ?? [],
    os: i.Os ?? null,
    architecture: i.Architecture ?? null,
    created,
    labels,
  };
}

/** What Docker says about the host: its distribution, release and kernel. Nothing else of `/info` is kept. */
export async function hostInfo(socket: string): Promise<{
  osName: string | null;
  osVersion: string | null;
  kernel: string | null;
  architecture: string | null;
}> {
  const i = info.parse(await dockerGet(socket, "/info"));
  return {
    osName: i.OperatingSystem ?? null,
    osVersion: i.OSVersion ?? null,
    kernel: i.KernelVersion ?? null,
    architecture: i.Architecture ?? null,
  };
}
