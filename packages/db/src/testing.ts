/**
 * Throw-away databases for integration tests, on the development PostgreSQL
 * started by `pnpm dev`. Never import this from application code.
 */
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { createDb, runMigrations } from "./index.ts";

const devEnvFile = fileURLToPath(new URL("../../../.data/dev.env", import.meta.url));

/** The development database URL, or null when `pnpm dev` has not set one up (tests then skip). */
export function devDatabaseUrl(): string | null {
  try {
    const line = readFileSync(devEnvFile, "utf8")
      .split("\n")
      .find((l) => l.startsWith("DATABASE_URL="));
    return line ? line.slice("DATABASE_URL=".length).trim() : null;
  } catch {
    return null;
  }
}

export interface TestDatabase {
  url: string;
  db: ReturnType<typeof createDb>["db"];
  pool: ReturnType<typeof createDb>["pool"];
  drop(): Promise<void>;
}

/** Creates a migrated database named after `label` and the process, and drops it again in `drop()`. */
export async function createTestDatabase(adminUrl: string, label: string): Promise<TestDatabase> {
  const name = `garnetops_${label}_${process.pid}`.replace(/[^a-z0-9_]/g, "_");
  const admin = createDb(adminUrl, { max: 1 });
  await admin.pool.query(`drop database if exists ${name} with (force)`);
  await admin.pool.query(`create database ${name}`);
  const url = new URL(adminUrl);
  url.pathname = `/${name}`;
  const conn = createDb(url.toString(), { max: 4 });
  await runMigrations(conn.db);
  return {
    url: url.toString(),
    db: conn.db,
    pool: conn.pool,
    async drop() {
      await conn.pool.end();
      // pool.end() resolves before every socket has closed. Dropping with force right away
      // would terminate those sockets and surface as unhandled errors, so wait for them.
      for (let attempt = 0; attempt < 50; attempt++) {
        const dropped = await admin.pool.query(`drop database if exists ${name}`).then(
          () => true,
          () => false,
        );
        if (dropped) break;
        await new Promise((resolve) => setTimeout(resolve, 100));
      }
      await admin.pool.query(`drop database if exists ${name} with (force)`);
      await admin.pool.end();
    },
  };
}
