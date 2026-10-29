/**
 * The packages of an image, read by syft (pinned and checksummed in the agent image) through the Docker proxy. Only the package URL,
 * name, version and type of each package leave this module, never file paths or contents.
 */
import { execFile } from "node:child_process";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { MAX_PACKAGES } from "@garnetops/core/agent";
import { z } from "zod";

export const SYFT_TIMEOUT_MS = 15 * 60_000;

const report = z.object({
  artifacts: z
    .array(
      z.object({
        name: z.string(),
        version: z.string(),
        type: z.string(),
        purl: z.string().optional(),
      }),
    )
    .default([]),
  distro: z
    .object({
      prettyName: z.string().optional(),
      name: z.string().optional(),
      version: z.string().optional(),
    })
    .nullish(),
});

export interface ImagePackageList {
  distro: string | null;
  packages: { name: string; version: string; type: string; purl: string }[];
}

/** Runs syft on an image by its id (`docker:<id>`), with Docker reached through the proxy socket only. */
export async function readPackages(
  syftBin: string,
  dockerSocket: string,
  imageId: string,
): Promise<ImagePackageList> {
  if (!/^(sha256:)?[a-f0-9]{64}$/.test(imageId)) throw new Error("not an image id");
  const dir = await mkdtemp(join(tmpdir(), "garnetops-syft-"));
  const out = join(dir, "sbom.json");
  try {
    await new Promise<void>((resolve, reject) => {
      execFile(
        syftBin,
        // Docker refuses a bare 64-character id as a name; with "sha256:" it is the exact image.
        ["scan", `docker:sha256:${imageId.replace(/^sha256:/, "")}`, "-o", `syft-json=${out}`, "-q"],
        {
          timeout: SYFT_TIMEOUT_MS,
          maxBuffer: 1024 * 1024,
          // syft's own update check and telemetry off; Docker only through the proxy.
          env: {
            PATH: process.env.PATH ?? "/usr/bin:/bin",
            HOME: dir,
            TMPDIR: dir,
            DOCKER_HOST: `unix://${dockerSocket}`,
            SYFT_CHECK_FOR_APP_UPDATE: "false",
          },
        },
        (error) => (error ? reject(new Error(`syft failed: ${error.message.slice(0, 200)}`)) : resolve()),
      );
    });
    const parsed = report.parse(JSON.parse(await readFile(out, "utf8")));
    const packages = parsed.artifacts
      .filter((a): a is typeof a & { purl: string } => Boolean(a.purl?.startsWith("pkg:")))
      .slice(0, MAX_PACKAGES)
      .map((a) => ({ name: a.name, version: a.version, type: a.type, purl: a.purl }));
    const d = parsed.distro;
    const distro = d ? (d.prettyName ?? ([d.name, d.version].filter(Boolean).join(" ") || null)) : null;
    return { distro, packages };
  } finally {
    await rm(dir, { recursive: true, force: true }).catch(() => {});
  }
}
