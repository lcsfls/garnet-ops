import { createDb } from "@garnetops/db";
import { PgBoss } from "pg-boss";
import { env } from "./env.ts";

export const { db, pool } = createDb(env.DATABASE_URL, { applicationName: "garnetops-api" });

/** Job queue. The API only sends jobs; the worker consumes them. */
export const boss = new PgBoss({
  connectionString: env.DATABASE_URL,
  application_name: "garnetops-api-queue",
});
boss.on("error", (error) => console.error("queue:", error.message));

export const QUEUES = {
  scanRepository: "scan.repository",
} as const;
