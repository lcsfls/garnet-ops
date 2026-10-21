import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { z } from "zod";
import { run } from "./run.ts";

/** Upper bound per repository; a larger inventory is cut, never stored unbounded. */
export const MAX_PACKAGES = 50_000;

const artifact = z.object({
  name: z.string().min(1),
  version: z.string().default(""),
  type: z.string().default("unknown"),
  purl: z.string().optional(),
  locations: z.array(z.object({ path: z.string().optional() })).optional(),
  licenses: z.array(z.object({ value: z.string().optional() })).optional(),
});
const sbom = z.object({
  artifacts: z.array(z.unknown()),
  descriptor: z.object({ version: z.string().optional() }).optional(),
});

export interface InventoryPackage {
  name: string;
  version: string;
  type: string;
  purl: string | null;
  locations: string[];
  licenses: string[];
}

export interface Inventory {
  packages: InventoryPackage[];
  /** Packages in the SBOM before the MAX_PACKAGES cut. */
  total: number;
  syftVersion: string | null;
}

/** Package inventory from a syft JSON SBOM. Malformed entries are skipped, duplicates merged. */
export function parseSbom(json: unknown): Inventory {
  const data = sbom.parse(json);
  const byKey = new Map<string, InventoryPackage>();
  for (const raw of data.artifacts) {
    const parsed = artifact.safeParse(raw);
    if (!parsed.success) continue;
    const a = parsed.data;
    const pkg: InventoryPackage = {
      name: a.name.slice(0, 300),
      version: a.version.slice(0, 200),
      type: a.type.slice(0, 50),
      purl: a.purl?.slice(0, 500) ?? null,
      locations: (a.locations ?? []).flatMap((l) => (l.path ? [l.path.slice(0, 500)] : [])).slice(0, 20),
      licenses: (a.licenses ?? []).flatMap((l) => (l.value ? [l.value.slice(0, 100)] : [])).slice(0, 10),
    };
    const key = `${pkg.type}|${pkg.name}|${pkg.version}`;
    const existing = byKey.get(key);
    if (existing) {
      existing.locations = [...new Set([...existing.locations, ...pkg.locations])].slice(0, 20);
      existing.licenses = [...new Set([...existing.licenses, ...pkg.licenses])].slice(0, 10);
    } else byKey.set(key, pkg);
  }
  const packages = [...byKey.values()].sort(
    (a, b) => a.name.localeCompare(b.name) || a.version.localeCompare(b.version),
  );
  return {
    packages: packages.slice(0, MAX_PACKAGES),
    total: packages.length,
    syftVersion: data.descriptor?.version ?? null,
  };
}

/**
 * Builds an SBOM of a checked-out repository with syft. Never contacts the network
 * (no remote license lookups, no Maven or Go proxies, no update check). Development
 * dependencies are included: they run on developer machines and in CI, and grype's own
 * directory scan has always reported them.
 */
export async function buildSbom(syftBin: string, dir: string, outDir: string): Promise<string> {
  const out = join(outDir, "sbom.syft.json");
  await run(syftBin, [`dir:${dir}`, "-o", `syft-json=${out}`, "-q"], {
    env: {
      PATH: process.env.PATH,
      SystemRoot: process.env.SystemRoot,
      HOME: outDir,
      USERPROFILE: outDir,
      TMP: outDir,
      TEMP: outDir,
      SYFT_CHECK_FOR_APP_UPDATE: "false",
      SYFT_JAVASCRIPT_INCLUDE_DEV_DEPENDENCIES: "true",
      SYFT_JAVASCRIPT_SEARCH_REMOTE_LICENSES: "false",
      SYFT_PYTHON_SEARCH_REMOTE_LICENSES: "false",
      SYFT_GOLANG_SEARCH_REMOTE_LICENSES: "false",
      SYFT_JAVA_USE_NETWORK: "false",
      GOPROXY: "off",
    },
    timeoutMs: 15 * 60_000,
  });
  return out;
}

export async function readSbom(path: string): Promise<Inventory> {
  return parseSbom(JSON.parse(await readFile(path, "utf8")));
}
