/**
 * The GarnetOps WordPress plugin (ADR 0042, part 4) as a zip, built from its files when it is first asked for: an installation
 * serves the plugin itself, so it also works without internet access. Stored entries only (no compression), fixed timestamps,
 * so the same files always give the same zip.
 */
import { createHash } from "node:crypto";
import { readdir, readFile, stat } from "node:fs/promises";
import { join, relative, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { crc32 } from "node:zlib";

/** The folder name inside the zip, which is the plugin's slug in WordPress. */
const FOLDER = "garnetops";
/** 1980-01-01 00:00 in DOS time and date. */
const DOS_TIME = 0;
const DOS_DATE = (0 << 9) | (1 << 5) | 1;

async function files(dir: string): Promise<string[]> {
  const out: string[] = [];
  for (const entry of await readdir(dir, { withFileTypes: true })) {
    const path = join(dir, entry.name);
    if (entry.isDirectory()) out.push(...(await files(path)));
    else if (entry.isFile()) out.push(path);
  }
  return out.sort();
}

/** A zip of stored entries. */
export function zip(entries: { name: string; data: Buffer }[]): Buffer {
  const locals: Buffer[] = [];
  const centrals: Buffer[] = [];
  let offset = 0;
  for (const { name, data } of entries) {
    const nameBytes = Buffer.from(name, "utf8");
    const crc = crc32(data);
    const local = Buffer.alloc(30);
    local.writeUInt32LE(0x04034b50, 0);
    local.writeUInt16LE(10, 4); // version needed
    local.writeUInt16LE(0x0800, 6); // UTF-8 names
    local.writeUInt16LE(0, 8); // stored
    local.writeUInt16LE(DOS_TIME, 10);
    local.writeUInt16LE(DOS_DATE, 12);
    local.writeUInt32LE(crc, 14);
    local.writeUInt32LE(data.length, 18);
    local.writeUInt32LE(data.length, 22);
    local.writeUInt16LE(nameBytes.length, 26);
    local.writeUInt16LE(0, 28);
    const central = Buffer.alloc(46);
    central.writeUInt32LE(0x02014b50, 0);
    central.writeUInt16LE(20, 4); // made by
    central.writeUInt16LE(10, 6);
    central.writeUInt16LE(0x0800, 8);
    central.writeUInt16LE(0, 10);
    central.writeUInt16LE(DOS_TIME, 12);
    central.writeUInt16LE(DOS_DATE, 14);
    central.writeUInt32LE(crc, 16);
    central.writeUInt32LE(data.length, 20);
    central.writeUInt32LE(data.length, 24);
    central.writeUInt16LE(nameBytes.length, 28);
    central.writeUInt32LE(offset, 42);
    locals.push(local, nameBytes, data);
    centrals.push(central, nameBytes);
    offset += local.length + nameBytes.length + data.length;
  }
  const directory = Buffer.concat(centrals);
  const end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50, 0);
  end.writeUInt16LE(entries.length, 8);
  end.writeUInt16LE(entries.length, 10);
  end.writeUInt32LE(directory.length, 12);
  end.writeUInt32LE(offset, 16);
  return Buffer.concat([...locals, directory, end]);
}

let cached: Promise<{ zip: Buffer; sha256: string; version: string } | null> | null = null;

/** The plugin zip with its SHA-256 and version, or null when the plugin's files are not there. */
export function wordpressPluginZip(dir: string) {
  cached ??= (async () => {
    const repository = fileURLToPath(
      new URL("../../../../integrations/wordpress/garnetops", import.meta.url),
    );
    for (const candidate of [dir, repository]) {
      if (!(await stat(join(candidate, "garnetops.php")).catch(() => null))) continue;
      const entries = await Promise.all(
        (await files(candidate)).map(async (path) => ({
          name: `${FOLDER}/${relative(candidate, path).split(sep).join("/")}`,
          data: await readFile(path),
        })),
      );
      const archive = zip(entries);
      const main = entries.find((e) => e.name === `${FOLDER}/garnetops.php`)?.data.toString("utf8") ?? "";
      return {
        zip: archive,
        sha256: createHash("sha256").update(archive).digest("hex"),
        version: /^\s*\*\s*Version:\s*([\w.-]+)/m.exec(main)?.[1] ?? "unknown",
      };
    }
    return null;
  })();
  return cached;
}
