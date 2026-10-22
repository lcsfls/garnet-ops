import { cp, mkdir, readdir } from "node:fs/promises";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

/** Directory with the recorded repository contents (see test/fixtures/README.md). */
export const fixturesDir = fileURLToPath(new URL("./fixtures/", import.meta.url));

const SUFFIX = ".fixture";

/**
 * Copies a fixture repository into `target`. Files ending in `.fixture` (the manifests, which
 * must not look like real manifests to scanners that read this repository) get their real name.
 */
export async function copyFixtureRepo(name: string, target: string): Promise<void> {
  const source = join(fixturesDir, name);
  await mkdir(target, { recursive: true });
  await cp(source, target, {
    recursive: true,
    filter: (path) => !path.endsWith(SUFFIX),
  });
  const entries = await readdir(source, { recursive: true, withFileTypes: true });
  for (const entry of entries) {
    if (!entry.isFile() || !entry.name.endsWith(SUFFIX)) continue;
    const relative = join(entry.parentPath.slice(source.length), entry.name);
    await mkdir(join(target, entry.parentPath.slice(source.length)), { recursive: true });
    await cp(join(source, relative), join(target, relative.slice(0, -SUFFIX.length)));
  }
}
