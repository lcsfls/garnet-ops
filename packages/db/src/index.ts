import { fileURLToPath } from "node:url";
import { drizzle } from "drizzle-orm/node-postgres";
import { migrate } from "drizzle-orm/node-postgres/migrator";
import pg from "pg";
import * as schema from "./schema.ts";

export * from "./directory.ts";
export * from "./schedule.ts";
export * from "./system.ts";
export * from "./trend.ts";
export * from "./user-notifications.ts";
export { schema };
export type Database = ReturnType<typeof createDb>["db"];

/**
 * SQL `date` values stay "YYYY-MM-DD" strings. By default node-postgres turns
 * them into a JavaScript Date at local midnight of the server process, which
 * shifts the day for anyone east or west of that zone.
 */
pg.types.setTypeParser(pg.types.builtins.DATE, (value) => value);

/**
 * Every session runs in UTC, whatever the server's own time zone is, so `::date`,
 * `current_date` and similar never depend on where the database happens to run.
 * Calendar days of a user are computed explicitly with `AT TIME ZONE <IANA zone>`.
 */
export const SESSION_TIME_ZONE = "UTC";

export function createDb(connectionString: string, options: { max?: number; applicationName?: string } = {}) {
  const pool = new pg.Pool({
    connectionString,
    max: options.max ?? 10,
    application_name: options.applicationName ?? "garnetops",
    options: `-c TimeZone=${SESSION_TIME_ZONE}`,
  });
  const db = drizzle(pool, { schema, casing: "snake_case" });
  return { db, pool };
}

const migrationsFolder = fileURLToPath(new URL("../drizzle", import.meta.url));

/** Applies pending migrations. Forward-only; safe to run on every start. */
export async function runMigrations(db: Database): Promise<void> {
  await migrate(db, { migrationsFolder });
}
