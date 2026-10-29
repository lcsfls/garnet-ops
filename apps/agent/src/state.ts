/** The host's identity: its id at GarnetOps and its Ed25519 private key, in the agent's own volume (mode 0600). */
import { mkdir, readFile, rename, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { z } from "zod";
import type { Identity } from "./client.ts";

const stateSchema = z.object({
  hostId: z.string().regex(/^hst_[A-Za-z0-9_-]{1,64}$/),
  privateKeyPem: z.string(),
});

export async function loadIdentity(dir: string): Promise<Identity | null> {
  try {
    return stateSchema.parse(JSON.parse(await readFile(join(dir, "identity.json"), "utf8")));
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return null;
    throw new Error("The stored identity cannot be read; remove the agent's volume and enrol again");
  }
}

export async function saveIdentity(dir: string, identity: Identity): Promise<void> {
  await mkdir(dir, { recursive: true, mode: 0o700 });
  const file = join(dir, "identity.json");
  await writeFile(`${file}.new`, JSON.stringify(identity), { mode: 0o600 });
  await rename(`${file}.new`, file);
}
